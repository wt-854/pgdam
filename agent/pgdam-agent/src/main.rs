use aya::{
    include_bytes_aligned,
    maps::{RingBuf, HashMap},
    programs::{UProbe, TracePoint},
    Bpf,
};
use pgdam_common::SqlEvent;
use std::{
    collections::HashSet,
    convert::TryFrom,
    time::Duration,
};
use tokio::{signal, net::UnixStream, io::AsyncWriteExt};
use serde::Serialize;
use log::{info, warn, error};
use object::{Object, ObjectSymbol, ObjectSegment};

const PID_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

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
    pub incomplete: bool,
}

// ── Binary discovery ──────────────────────────────────────────────────────────

fn discover_postgres_path() -> Option<String> {
    let default_path = "/usr/lib/postgresql/18/bin/postgres";
    if std::path::Path::new(default_path).exists() {
        return Some(default_path.to_string());
    }
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() { continue; }
            if let Ok(comm) = std::fs::read_to_string(path.join("comm")) {
                if comm.trim() == "postgres" {
                    let bin = path.join("root/usr/lib/postgresql/18/bin/postgres");
                    if bin.exists() {
                        return Some(bin.to_string_lossy().into_owned());
                    }
                }
            }
        }
    }
    None
}

// ── ELF symbol offset (PIE-safe) ─────────────────────────────────────────────

fn find_symbol_offset(path: &str, name: &str) -> Option<u64> {
    let data = std::fs::read(path).ok()?;
    let obj = object::File::parse(&*data).ok()?;

    let load_base_vma: u64 = obj
        .segments()
        .map(|s| s.address())
        .filter(|&a| a > 0)
        .min()
        .unwrap_or(0);

    for sym in obj.symbols().chain(obj.dynamic_symbols()) {
        if sym.name() == Ok(name) && sym.address() != 0 {
            return Some(sym.address() - load_base_vma);
        }
    }
    None
}

// ── Live Postgres process discovery ──────────────────────────────────────────

fn find_all_postgres_processes() -> Vec<(u32, u64)> {
    let mut results = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else { return results };

    for entry in entries.flatten() {
        let pid_path = entry.path();
        if !pid_path.is_dir() { continue; }

        let Ok(comm) = std::fs::read_to_string(pid_path.join("comm")) else { continue };
        if comm.trim() != "postgres" { continue; }

        let pid: u32 = match pid_path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|s| s.parse().ok())
        {
            Some(p) => p,
            None => continue,
        };

        let Ok(maps) = std::fs::read_to_string(pid_path.join("maps")) else { continue };
        for line in maps.lines() {
            if line.contains("postgres") && line.contains("r-xp") {
                if let Some(base_str) = line.split('-').next() {
                    if let Ok(base) = u64::from_str_radix(base_str, 16) {
                        results.push((pid, base));
                        break;
                    }
                }
            }
        }
    }
    results
}

// ── Map reconciliation ────────────────────────────────────────────────────────

fn reconcile_pid_map(
    pid_bases: &mut HashMap<aya::maps::MapData, u32, u64>,
) -> (usize, usize) {
    let live = find_all_postgres_processes();
    let live_set: HashSet<u32> = live.iter().map(|(pid, _)| *pid).collect();

    let existing: HashSet<u32> = pid_bases
        .keys()
        .filter_map(|r| r.ok())
        .collect();

    // Remove stale entries
    let dead: Vec<u32> = existing.iter()
        .filter(|pid| !live_set.contains(pid))
        .copied()
        .collect();
    let removed = dead.len();
    for pid in &dead {
        if let Err(e) = pid_bases.remove(pid) {
            error!("Failed to remove stale PID {}: {}", pid, e);
        }
    }

    // Insert only genuinely new PIDs — store raw base, eBPF adds offset
    let mut added = 0usize;
    for (pid, base_addr) in &live {
        if existing.contains(pid) {
            continue;
        }
        match pid_bases.insert(*pid, *base_addr, 0) {
            Ok(_) => {
                info!("Registered new PID {} (base=0x{:x})", pid, base_addr);
                added += 1;
            }
            Err(e) => error!("Failed to insert PID {}: {}", pid, e),
        }
    }

    (added, removed)
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    info!("Starting pgdam-agent...");

    let bpf_bytes = include_bytes_aligned!("../../target/bpfel-unknown-none/release/pgdam-ebpf");
    let mut bpf = Bpf::load(bpf_bytes)?;

    let bin_path = loop {
        if let Some(p) = discover_postgres_path() {
            break p;
        }
        info!("No Postgres binary found. Retrying in 30 s...");
        tokio::time::sleep(Duration::from_secs(30)).await;
    };
    info!("Found Postgres binary: {}", bin_path);

    let symbol_offset = find_symbol_offset(&bin_path, "MyProcPort")
        .expect("Could not find MyProcPort symbol in Postgres binary");
    info!("MyProcPort symbol offset: 0x{:x}", symbol_offset);

    // Write offset into CONFIG_OFFSET — eBPF reads this to compute abs address.
    let mut config_offset: HashMap<_, u32, u64> =
        HashMap::try_from(bpf.take_map("CONFIG_OFFSET").unwrap())?;
    config_offset.insert(0u32, symbol_offset, 0)?;

    let mut pid_bases: HashMap<_, u32, u64> =
        HashMap::try_from(bpf.take_map("PID_BASES").unwrap())?;
    let mut watched_parents: HashMap<_, u32, u8> =
        HashMap::try_from(bpf.take_map("WATCHED_PARENTS").unwrap())?;
    let mut new_pids_buf =
        RingBuf::try_from(bpf.take_map("NEW_PIDS").unwrap())?;
    let mut ring_buf =
        RingBuf::try_from(bpf.take_map("EVENTS").unwrap())?;

    // Initial population — store raw base addresses, not pre-computed absolutes.
    loop {
        let live = find_all_postgres_processes();
        if !live.is_empty() {
            for (pid, base_addr) in &live {
                pid_bases.insert(*pid, *base_addr, 0)?;
                watched_parents.insert(*pid, 1u8, 0)?;
                info!("Registered initial PID {} (base=0x{:x})", pid, base_addr);
            }
            break;
        }
        info!("Waiting for Postgres processes...");
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    let uprobe: &mut UProbe = bpf.program_mut("pg_pg_parse_query").unwrap().try_into()?;
    uprobe.load()?;
    uprobe.attach(Some("pg_parse_query"), 0, &bin_path, None)?;
    info!("Attached uprobe to {}", bin_path);

    let fork_prog: &mut TracePoint = bpf.program_mut("on_fork").unwrap().try_into()?;
    fork_prog.load()?;
    fork_prog.attach("sched", "sched_process_fork")?;
    info!("Attached sched_process_fork tracepoint");

    let socket_path = "/tmp/pgdam.sock";
    let mut processor_stream: Option<UnixStream> = None;
    for attempt in 1..=10 {
        match UnixStream::connect(socket_path).await {
            Ok(s) => {
                info!("Connected to processor at {}", socket_path);
                processor_stream = Some(s);
                break;
            }
            Err(e) => {
                error!("Attempt {}/10 to connect to processor: {}. Retrying...", attempt, e);
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
    if processor_stream.is_none() {
        warn!("Could not connect to processor; events will be logged only.");
    }

    let mut last_refresh = tokio::time::Instant::now();

    loop {
        // ── Fork notifications ────────────────────────────────────────────
        while let Some(item) = new_pids_buf.next() {
            let child_pid = unsafe { *(item.as_ptr() as *const u32) };
            if let Some((_, base_addr)) = find_all_postgres_processes()
                .into_iter()
                .find(|(pid, _)| *pid == child_pid)
            {
                // Store raw base — eBPF adds symbol_offset itself
                match pid_bases.insert(child_pid, base_addr, 0) {
                    Ok(_) => info!("Fork-registered PID {} (base=0x{:x})", child_pid, base_addr),
                    Err(e) => error!("Failed to fork-register PID {}: {}", child_pid, e),
                }
            }
        }

        // ── Periodic /proc reconciliation ─────────────────────────────────
        if last_refresh.elapsed() >= PID_REFRESH_INTERVAL {
            let (added, removed) = reconcile_pid_map(&mut pid_bases);
            if added > 0 || removed > 0 {
                info!("PID map refresh: +{} added, -{} removed", added, removed);
            }
            last_refresh = tokio::time::Instant::now();
        }

        // ── SQL ring buffer ───────────────────────────────────────────────
        if let Some(item) = ring_buf.next() {
            let wrapper = unsafe { &*(item.as_ptr() as *const SqlEventWrapper) };
            let event = &wrapper.0;

            let sql = std::str::from_utf8(
                &event.payload[..event.payload_len as usize]
            ).unwrap_or("<invalid utf8>");

            let incomplete = (event.flags & pgdam_common::FLAG_NO_PORT_INFO) != 0;
            let bg_worker  = (event.flags & pgdam_common::FLAG_NO_CLIENT)    != 0;

            // Background workers have no client connection — skip entirely.
            if bg_worker {
                continue;
            }

            // Decode fields regardless — they will be empty on incomplete events.
            let user = std::str::from_utf8(&event.user_name)
                .unwrap_or("").trim_matches('\0').to_string();
            let db = std::str::from_utf8(&event.database_name)
                .unwrap_or("").trim_matches('\0').to_string();
            let src_ip = std::str::from_utf8(&event.remote_host)
                .unwrap_or("").trim_matches('\0').to_string();

            if incomplete {
                warn!(
                    "Incomplete event (PID {} not yet registered): sql=\"{}\"",
                    event.pid, sql.trim()
                );
            } else {
                info!(
                    "pid={} user={} db={} src={} sql=\"{}\"",
                    event.pid, user, db, src_ip, sql.trim()
                );
            }

            let audit = AuditEventJson {
                pid: event.pid,
                timestamp: event.timestamp,
                raw_sql: sql.to_string(),
                user,
                db,
                src_ip,
                incomplete,
            };

            if let Some(ref mut stream) = processor_stream {
                let mut payload = serde_json::to_vec(&audit)?;
                payload.push(b'\n');
                if let Err(e) = stream.write_all(&payload).await {
                    error!("Lost processor connection: {}. Reconnecting...", e);
                    processor_stream = match UnixStream::connect(socket_path).await {
                        Ok(s) => { info!("Reconnected to processor."); Some(s) }
                        Err(e) => { error!("Reconnect failed: {}", e); None }
                    };
                }
            }
        } else {
            tokio::select! {
                _ = signal::ctrl_c() => {
                    info!("Shutting down.");
                    break;
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }
    }

    Ok(())
}