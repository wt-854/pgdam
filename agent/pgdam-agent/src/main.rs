use aya::{
    include_bytes_aligned,
    maps::{RingBuf, HashMap},
    programs::UProbe,
    Bpf,
};
use pgdam_common::SqlEvent;
use std::convert::TryFrom;
use tokio::signal;
use tokio::net::UnixStream;
use tokio::io::AsyncWriteExt;
use serde::Serialize;
use log::{info, error};
use object::{Object, ObjectSymbol};

#[repr(transparent)]
#[derive(Copy, Clone)]
struct SqlEventWrapper(SqlEvent);
unsafe impl aya::Pod for SqlEventWrapper {}

#[derive(Serialize)]
struct AuditEventJson {
    pub pid: u32,
    pub timestamp: u64,
    pub raw_sql: String,
    pub user: String,
    pub db: String,
    pub src_ip: String,
}

fn discover_postgres_path() -> Option<String> {
    let default_path = "/usr/lib/postgresql/18/bin/postgres";
    if std::path::Path::new(default_path).exists() {
        return Some(default_path.to_string());
    }

    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() { continue; }
            
            let comm_path = path.join("comm");
            if let Ok(comm) = std::fs::read_to_string(comm_path) {
                if comm.trim() == "postgres" {
                    let container_path = path.join("root").join("usr/lib/postgresql/18/bin/postgres");
                    if container_path.exists() {
                        return Some(container_path.to_string_lossy().to_string());
                    }
                }
            }
        }
    }
    None
}

fn find_symbol_offset(path: &str, name: &str) -> Option<u64> {
    let data = std::fs::read(path).ok()?;
    let obj = object::File::parse(&*data).ok()?;
    
    // Check static symbols
    for sym in obj.symbols() {
        if sym.name() == Ok(name) {
            return Some(sym.address());
        }
    }
    
    // Check dynamic symbols
    for sym in obj.dynamic_symbols() {
        if sym.name() == Ok(name) {
            return Some(sym.address());
        }
    }
    None
}

fn find_postgres_base_address() -> Option<u64> {
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() { continue; }
            
            let comm_path = path.join("comm");
            if let Ok(comm) = std::fs::read_to_string(comm_path) {
                if comm.trim() == "postgres" {
                    let maps_path = path.join("maps");
                    if let Ok(maps) = std::fs::read_to_string(maps_path) {
                        for line in maps.lines() {
                            if line.contains("postgres") {
                                let parts: Vec<&str> = line.split_whitespace().collect();
                                if parts.len() > 0 {
                                    let addr_range = parts[0];
                                    let base_addr_str = addr_range.split('-').next()?;
                                    return u64::from_str_radix(base_addr_str, 16).ok();
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    info!("Starting pgdam-agent...");

    let bpf_bytes = include_bytes_aligned!("../../target/bpfel-unknown-none/release/pgdam-ebpf");
    let mut bpf = Bpf::load(bpf_bytes)?;

    let path = discover_postgres_path().expect("Could not find postgres binary");
    
    // 1. Look up MyProcPort offset in the binary
    let offset = find_symbol_offset(&path, "MyProcPort").expect("Could not find MyProcPort symbol");
    info!("Found MyProcPort symbol offset: 0x{:x}", offset);

    // 2. Find virtual base address of a running postgres process
    let mut base_addr = 0;
    while base_addr == 0 {
        if let Some(addr) = find_postgres_base_address() {
            base_addr = addr;
            break;
        }
        info!("Waiting for postgres process to appear...");
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    }
    
    let abs_addr = base_addr + offset;
    info!("Postgres base address: 0x{:x}. Virtual address for MyProcPort: 0x{:x}", base_addr, abs_addr);

    // Pass absolute address to eBPF program via HashMap
    let mut config: HashMap<_, u32, u64> = HashMap::try_from(bpf.map_mut("CONFIG").unwrap())?;
    config.insert(1, abs_addr, 0)?; // Key 1 = MyProcPort Addr

    let program: &mut UProbe = bpf.program_mut("pg_pg_parse_query").unwrap().try_into()?;
    program.load()?;
    program.attach(Some("pg_parse_query"), 0, &path, None)?;

    info!("Attached eBPF probes to {}", path);

    let mut ring_buf = RingBuf::try_from(bpf.map_mut("EVENTS").unwrap())?;
    
    // Connect to Processor UDS with retry
    let socket_path = "/tmp/pgdam.sock";
    let mut processor_stream = None;
    for i in 0..10 {
        match UnixStream::connect(socket_path).await {
            Ok(s) => {
                info!("Connected to processor at {}", socket_path);
                processor_stream = Some(s);
                break;
            }
            Err(e) => {
                error!("Attempt {} to connect to processor failed: {}. Retrying in 2s...", i + 1, e);
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            }
        }
    }

    loop {
        if let Some(item) = ring_buf.next() {
            let event_wrapper = unsafe { &*(item.as_ptr() as *const SqlEventWrapper) };
            let event = &event_wrapper.0;
            
            let sql = std::str::from_utf8(&event.payload[..event.payload_len as usize])
                .unwrap_or("<invalid utf8>");
            
            let user = std::str::from_utf8(&event.user_name)
                .unwrap_or("")
                .trim_matches(char::from(0))
                .to_string();
            
            let db = std::str::from_utf8(&event.database_name)
                .unwrap_or("")
                .trim_matches(char::from(0))
                .to_string();

            let src_ip = std::str::from_utf8(&event.remote_host)
                .unwrap_or("")
                .trim_matches(char::from(0))
                .to_string();

            let event_json = AuditEventJson {
                pid: event.pid,
                timestamp: event.timestamp,
                raw_sql: sql.to_string(),
                user,
                db,
                src_ip,
            };

            info!("Captured SQL: pid={} user={} db={} src_ip={} sql=\"{}\"", 
                event.pid, event_json.user, event_json.db, event_json.src_ip, sql.trim());

            // Forward to processor
            if let Some(ref mut stream) = processor_stream {
                let json_data = serde_json::to_vec(&event_json)?;
                if let Err(e) = stream.write_all(&json_data).await {
                    error!("Failed to forward to processor: {}", e);
                    // Attempt to reconnect once if failed
                    if let Ok(new_stream) = UnixStream::connect(socket_path).await {
                        processor_stream = Some(new_stream);
                    } else {
                        processor_stream = None;
                    }
                }
            }
        } else {
            tokio::select! {
                _ = signal::ctrl_c() => break,
                _ = tokio::time::sleep(tokio::time::Duration::from_millis(10)) => {}
            }
        }
    }

    Ok(())
}
