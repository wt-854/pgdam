use aya::{
    include_bytes_aligned,
    maps::{Array, HashMap, RingBuf},
    programs::{TracePoint, UProbe},
    Bpf,
};
use log::{error, info, warn};
use object::{Object, ObjectSegment, ObjectSymbol};
use pgdam_common::{BinaryConfig, PidInfo, SqlEvent, PORT_FLAG_HOST_IS_INLINE};
use serde::Serialize;
use std::{
    collections::{HashMap as StdHashMap, HashSet},
    convert::TryFrom,
    os::unix::fs::MetadataExt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::AsyncWriteExt,
    net::UnixStream,
    signal,
    signal::unix::{signal as unix_signal, SignalKind},
};

mod metrics;

const PID_REFRESH_INTERVAL: Duration = Duration::from_secs(5);
const DROP_READ_INTERVAL: Duration = Duration::from_secs(10);
const SOCKET_PATH: &str = "/tmp/pgdam.sock";
const METRICS_PORT: u16 = 9090;
const SHUTDOWN_DRAIN_SECS: u64 = 5;

#[derive(Serialize)]
struct AuditEventJson {
    pid: u32,
    timestamp: u64,
    event_type: String,
    raw_sql: String,
    user: String,
    db: String,
    src_ip: String,
    incomplete: bool,
    truncated: bool,
}

// ── Per-binary profile ────────────────────────────────────────────────────────

/// Everything the agent learns about a unique Postgres binary on disk.
/// Keyed by host-namespace inode so that two containers running different
/// images always produce separate entries, even if their binaries happen to
/// live at identical mount-relative paths.
#[derive(Clone, Debug)]
struct BinaryProfile {
    /// Absolute host-side path suitable for ELF reading and uprobe attachment.
    path: String,
    /// Host-namespace inode — stable primary key.
    inode: u64,
    /// MyProcPort VA − load_base (PIE-corrected).
    symbol_offset: u64,
    /// Port struct field offsets for this specific build.
    off_remote_host: u32,
    off_database_name: u32,
    off_user_name: u32,
    is_edb: bool,
    port_flags: u32,
}

/// One live postgres process.
#[derive(Clone, Debug)]
struct ProcessEntry {
    pid: u32,
    load_base: u64,
    /// Matches BinaryProfile.inode for the binary this process runs.
    inode: u64,
}
/// Function to calculate timestamp accurately
fn boot_to_wall_offset_ns() -> i64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid pointer, standard syscall
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    let monotonic_ns = ts.tv_sec as i64 * 1_000_000_000 + ts.tv_nsec as i64;

    let realtime_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as i64;

    realtime_ns - monotonic_ns
}

// ── ELF analysis ─────────────────────────────────────────────────────────────

/// Compute the PIE-corrected offset of `symbol_name` from the first LOAD
/// segment.  This is the value that, when added to the runtime load base,
/// gives the absolute address of the symbol in any running instance of the
/// binary regardless of ASLR.
fn find_symbol_offset(path: &str, symbol_name: &str) -> Option<u64> {
    let data = std::fs::read(path).ok()?;
    let obj = object::File::parse(&*data).ok()?;

    // For PIE binaries, the ELF LOAD segment's p_vaddr is non-zero and is
    // what the dynamic linker subtracts from all symbol addresses to produce
    // the file-relative offset.  For non-PIE binaries it's 0.
    let load_base_vma: u64 = obj
        .segments()
        .map(|s| s.address())
        .filter(|&a| a > 0)
        .min()
        .unwrap_or(0);

    obj.symbols()
        .chain(obj.dynamic_symbols())
        .find(|s| s.name() == Ok(symbol_name) && s.address() != 0)
        .map(|s| s.address() - load_base_vma)
}

/// Attempt to read the PostgreSQL major version number that is embedded as a
/// plain ASCII string in the binary (e.g. "PostgreSQL 18.1").
fn detect_pg_major(path: &str) -> Option<u32> {
    let data = std::fs::read(path).ok()?;
    let marker = b"PostgreSQL ";
    let mut max_version = 0u32;
    for i in 0..data.len().saturating_sub(marker.len()) {
        if &data[i..i + marker.len()] == marker {
            let mut j = i + marker.len();
            let mut v = String::new();
            while j < data.len() && data[j].is_ascii_digit() {
                v.push(data[j] as char);
                j += 1;
            }
            if let Ok(n) = v.parse::<u32>() {
                if n > max_version {
                    max_version = n;
                }
            }
        }
    }
    if max_version > 0 {
        Some(max_version)
    } else {
        None
    }
}

/// Detect whether a process is running an EDB Advanced Server binary by
/// checking if /usr/edb exists in the process's mount namespace.
///
/// This approach handles cases where the binary version string does not
/// contain "EnterpriseDB" (e.g. docker.enterprisedb.com/k8s/postgresql
/// images that use EDB's Port struct layout but report as standard postgres).
fn detect_is_edb(pid: u32) -> bool {
    let path = format!("/proc/{}/root/usr/edb", pid);
    std::path::Path::new(&path).exists()
}

/// TODO: Verify PORT_FLAG_HOST_IS_INLINE logic
/// Returns (off_remote_host, off_database_name, off_user_name, port_flags).
fn port_field_offsets(major: u32, is_edb: bool) -> (u32, u32, u32, u32) {
    if is_edb {
        // Offsets match standard PG for the same major version.
        return match major {
            17 => (288, 320, 328, 0),
            18 => (288, 384, 392, 0),
            _ => {
                warn!(
                    "Unknown EDB major version {}; falling back to EDB18 offsets.",
                    major
                );
                (288, 384, 392, 0)
            }
        };
    }

    match major {
        14 => (288, 328, 336, 0),
        15 => (288, 328, 336, 0),
        16 => (288, 328, 336, 0),
        17 => (288, 320, 328, 0),
        18 => (288, 384, 392, 0),
        _ => {
            warn!(
                "Unknown PG major version {}; falling back to PG18 offsets.",
                major
            );
            (288, 384, 392, 0)
        }
    }
}

/// Read, parse, and profile a Postgres binary: compute the symbol offset and
/// choose the correct Port field offsets for its version.
fn analyze_binary(pid: u32, path: &str) -> Option<BinaryProfile> {
    let meta = std::fs::metadata(path).ok()?;
    let inode = meta.ino();
    let offset = find_symbol_offset(path, "MyProcPort")?;
    let major = detect_pg_major(path).unwrap_or(18);
    let is_edb = detect_is_edb(pid);
    let (off_remote_host, off_database_name, off_user_name, port_flags) =
        port_field_offsets(major, is_edb);

    info!(
        "Binary analysis: path={} inode={} pg{} edb={} MyProcPort+0x{:x} \
         remote_host+{} database_name+{} user_name+{} port_flags=0x{:x}",
        path,
        inode,
        major,
        is_edb,
        offset,
        off_remote_host,
        off_database_name,
        off_user_name,
        port_flags
    );
    Some(BinaryProfile {
        path: path.to_string(),
        inode,
        symbol_offset: offset,
        off_remote_host,
        off_database_name,
        off_user_name,
        is_edb,
        port_flags,
    })
}

// ── Process discovery ─────────────────────────────────────────────────────────

/// Scan /proc and return one ProcessEntry for every live process whose comm is
/// "postgres", resolving the host-side exe path and inode for each.
///
/// Using /proc/<pid>/exe gives us the real host-namespace path even for
/// containerised processes, which is exactly what we need for:
///   1. stat() to get the host inode
///   2. ELF reading for symbol analysis
///   3. uprobe attachment (the kernel resolves the inode from this path)
fn scan_postgres_processes() -> Vec<ProcessEntry> {
    let mut out = Vec::new();
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return out;
    };

    for entry in dir.flatten() {
        let proc_dir = entry.path();
        if !proc_dir.is_dir() {
            continue;
        }

        let Ok(comm) = std::fs::read_to_string(proc_dir.join("comm")) else {
            continue;
        };
        let comm = comm.trim();
        if comm != "postgres" && comm != "edb-postgres" {
            continue;
        }

        let pid: u32 = match proc_dir
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|s| s.parse().ok())
        {
            Some(p) => p,
            None => continue,
        };

        // Resolve the exe symlink on the host side.
        let exe_link = proc_dir.join("exe");

        // stat through procfs — works regardless of mount namespace
        let inode = match std::fs::metadata(&exe_link) {
            Ok(m) => m.ino(),
            Err(_) => continue,
        };

        // read_link only to check for deleted binaries and get a display path
        let exe = match std::fs::read_link(&exe_link) {
            Ok(p) => p,
            Err(_) => continue,
        };

        if exe.to_string_lossy().ends_with("(deleted)") {
            continue;
        }

        let Ok(maps) = std::fs::read_to_string(proc_dir.join("maps")) else {
            continue;
        };

        let exe_name = exe
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("postgres");

        // EDB binaries are not PIE — their first mapping is the load base.
        // Standard PG binaries are PIE — look specifically for the r-xp segment.
        let is_edb = detect_is_edb(pid);

        let load_base_line = if is_edb {
            // EDB strategy: Take the very first mapping containing the exe_name
            maps.lines().find(|l| l.contains(exe_name))
        } else {
            // Standard PG strategy: Look specifically for the executable segment
            maps.lines()
                .find(|l| l.contains("r-xp") && l.contains(exe_name))
        };

        let load_base = load_base_line
            .and_then(|l| l.split('-').next())
            .and_then(|s| u64::from_str_radix(s, 16).ok());

        if let Some(base) = load_base {
            out.push(ProcessEntry {
                pid,
                load_base: base,
                inode,
            });
        }
    }
    out
}

// ── Map write helpers ─────────────────────────────────────────────────────────

fn push_binary_config(
    map: &mut HashMap<aya::maps::MapData, u64, BinaryConfig>,
    profile: &BinaryProfile,
) -> anyhow::Result<()> {
    map.insert(
        profile.inode,
        BinaryConfig {
            symbol_offset: profile.symbol_offset,
            off_remote_host: profile.off_remote_host,
            off_database_name: profile.off_database_name,
            off_user_name: profile.off_user_name,
            port_flags: profile.port_flags,
        },
        0,
    )?;
    Ok(())
}

fn push_pid_info(
    map: &mut HashMap<aya::maps::MapData, u32, PidInfo>,
    proc: &ProcessEntry,
) -> anyhow::Result<()> {
    map.insert(
        proc.pid,
        PidInfo {
            load_base: proc.load_base,
            binary_inode: proc.inode,
        },
        0,
    )?;
    Ok(())
}

// ── Uprobe attachment ─────────────────────────────────────────────────────────

/// Analyse a newly discovered binary, write its config to BINARY_CONFIGS, and
/// attach the already-loaded uprobe program to it.
///
/// The uprobe program (pg_pg_parse_query) is loaded once; `attach()` can be
/// called multiple times on the same loaded program to hook multiple binaries.
/// Each call creates an independent kernel probe; all remain active until the
/// Bpf object is dropped.
///
/// IMPORTANT: call this AFTER push_binary_config so the eBPF program can never
/// fire on the new binary without a corresponding BINARY_CONFIGS entry.
fn attach_new_binary(
    bpf: &mut Bpf,
    binary_configs: &mut HashMap<aya::maps::MapData, u64, BinaryConfig>,
    known_binaries: &mut StdHashMap<u64, BinaryProfile>,
    profile: BinaryProfile,
) -> anyhow::Result<()> {
    // Write the config first so the eBPF hot path always finds it.
    push_binary_config(binary_configs, &profile)?;

    let uprobe: &mut UProbe = bpf
        .program_mut("pg_pg_parse_query")
        .ok_or_else(|| anyhow::anyhow!("uprobe program not found"))?
        .try_into()?;

    // attach() on an already-loaded UProbe adds another probe point without
    // disturbing the existing ones.  The returned LinkId is managed internally
    // by aya and the probe stays live for the lifetime of `bpf`.
    uprobe.attach(Some("pg_parse_query"), 0, &profile.path, None)?;
    info!(
        "Uprobe attached → {} (inode={}, offset=0x{:x})",
        profile.path, profile.inode, profile.symbol_offset
    );

    known_binaries.insert(profile.inode, profile);
    Ok(())
}

/// Reconcile agent state against the live /proc snapshot.
/// Returns (pids_added, pids_removed, binaries_added, stale_pids).
/// stale_pids is returned so the caller can emit pid_exit events.
fn reconcile(
    bpf: &mut Bpf,
    binary_configs: &mut HashMap<aya::maps::MapData, u64, BinaryConfig>,
    pid_info_map: &mut HashMap<aya::maps::MapData, u32, PidInfo>,
    watched_parents: &mut HashMap<aya::maps::MapData, u32, u8>,
    known_binaries: &mut StdHashMap<u64, BinaryProfile>,
    known_pids: &mut HashSet<u32>,
) -> anyhow::Result<(usize, usize, usize, Vec<u32>)> {
    let live = scan_postgres_processes();
    let live_pid_set: HashSet<u32> = live.iter().map(|p| p.pid).collect();

    // ── Remove stale PIDs ─────────────────────────────────────────────────────
    let stale: Vec<u32> = known_pids
        .iter()
        .filter(|p| !live_pid_set.contains(p))
        .copied()
        .collect();
    let removed = stale.len();
    for pid in &stale {
        known_pids.remove(pid);
        if let Err(e) = pid_info_map.remove(pid) {
            error!("Failed to remove stale PID {} from PID_INFO: {}", pid, e);
        }
    }

    let mut pids_added = 0usize;
    let mut binaries_added = 0usize;

    for proc in &live {
        // New binary: resolve host path, analyse, attach, write config.
        if !known_binaries.contains_key(&proc.inode) {
            let exe_path = format!("/proc/{}/exe", proc.pid);
            if !std::path::Path::new(&exe_path).exists() {
                continue;
            }

            if exe_path.ends_with("(deleted)") {
                continue;
            }

            match analyze_binary(proc.pid, &exe_path) {
                Some(profile) => {
                    match attach_new_binary(bpf, binary_configs, known_binaries, profile) {
                        Ok(_) => binaries_added += 1,
                        Err(e) => error!("Failed to attach binary at {}: {}", exe_path, e),
                    }
                }
                None => warn!("Could not analyse binary at {} — skipping.", exe_path),
            }
        }

        // New PID: write PID_INFO and mark as watched parent.
        if !known_pids.contains(&proc.pid) {
            match push_pid_info(pid_info_map, proc) {
                Ok(_) => {
                    known_pids.insert(proc.pid);
                    let _ = watched_parents.insert(proc.pid, 1u8, 0);
                    pids_added += 1;
                    info!(
                        "PID registered: pid={} inode={} base=0x{:x}",
                        proc.pid, proc.inode, proc.load_base
                    );
                }
                Err(e) => error!("Failed to register PID {}: {}", proc.pid, e),
            }
        }
    }

    Ok((pids_added, removed, binaries_added, stale))
}

// ── Processor socket helpers ──────────────────────────────────────────────────

async fn connect_to_processor() -> Option<UnixStream> {
    for attempt in 1..=10 {
        match UnixStream::connect(SOCKET_PATH).await {
            Ok(s) => {
                info!("Connected to processor at {}", SOCKET_PATH);
                return Some(s);
            }
            Err(e) => {
                error!(
                    "Attempt {}/10 connecting to processor: {}. Retrying...",
                    attempt, e
                );
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
    warn!("Could not connect to processor; events will be logged only.");
    None
}

async fn send_event(stream: &mut UnixStream, payload: &[u8]) -> bool {
    let mut data = payload.to_vec();
    data.push(b'\n');
    stream.write_all(&data).await.is_ok()
}

fn utf8_trim(buf: &[u8]) -> &str {
    std::str::from_utf8(buf).unwrap_or("").trim_matches('\0')
}

// ── Event processing helper ───────────────────────────────────────────────────

/// Process a single SqlEvent from the ring buffer and forward it to the
/// processor. Extracted so it can be called identically in both the main
/// loop and the shutdown drain loop.
async fn process_sql_event(
    event: &SqlEvent,
    processor_stream: &mut Option<UnixStream>,
    wall_offset_ns: i64,
) {
    let sql = std::str::from_utf8(&event.payload[..event.payload_len as usize])
        .unwrap_or("<invalid utf8>");

    let incomplete = (event.flags & pgdam_common::FLAG_NO_PORT_INFO) != 0;
    let bg_worker = (event.flags & pgdam_common::FLAG_NO_CLIENT) != 0;
    let truncated = (event.flags & pgdam_common::FLAG_TRUNCATED) != 0;

    if truncated {
        metrics::TRUNCATED_EVENTS_TOTAL.inc();
    }

    let event_type = if incomplete {
        "incomplete"
    } else if bg_worker {
        "background_worker"
    } else {
        "user_query"
    }
    .to_string();

    metrics::EVENTS_CAPTURED_TOTAL.inc();
    if incomplete {
        metrics::INCOMPLETE_EVENTS_TOTAL.inc();
    }
    if bg_worker {
        metrics::BG_WORKER_EVENTS_TOTAL.inc();
    }

    let user = utf8_trim(&event.user_name);
    let db = utf8_trim(&event.database_name);
    let src_ip = utf8_trim(&event.remote_host);

    if incomplete {
        warn!(
            "Incomplete event PID {}: sql=\"{}\" \
             (PID_INFO race — context unavailable, event will not be replayed)",
            event.pid,
            sql.trim()
        );
    } else {
        info!(
            "pid={} type={} user={} db={} src={} truncated={} sql=\"{}\"",
            event.pid,
            event_type,
            user,
            db,
            src_ip,
            truncated,
            sql.trim()
        );
    }

    let audit = AuditEventJson {
        pid: event.pid,
        timestamp: (event.timestamp as i64 + wall_offset_ns) as u64,
        event_type,
        raw_sql: sql.to_string(),
        user: user.to_string(),
        db: db.to_string(),
        src_ip: src_ip.to_string(),
        incomplete,
        truncated,
    };

    if let Some(ref mut stream) = processor_stream {
        if let Ok(payload) = serde_json::to_vec(&audit) {
            if !send_event(stream, &payload).await {
                error!("Lost processor connection. Reconnecting...");
                *processor_stream = connect_to_processor().await;
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    info!("Starting pgdam-agent (multi-binary mode)...");

    let wall_offset_ns: i64 = boot_to_wall_offset_ns();
    info!("Boot-to-wall offset: {}ns", wall_offset_ns);

    // Start metrics server in background.
    tokio::spawn(metrics::start_metrics_server(METRICS_PORT));

    metrics::init_metrics();

    // ── Install signal handlers before doing any real work ────────────────────
    // Both handlers must be installed before the event loop; re-creating them
    // inside the loop would miss signals delivered between iterations.
    let mut sigterm =
        unix_signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");

    let bpf_bytes = include_bytes_aligned!("../../target/bpfel-unknown-none/release/pgdam-ebpf");
    let mut bpf = Bpf::load(bpf_bytes)?;

    // ── Load eBPF maps ────────────────────────────────────────────────────────
    // Maps are taken out of the Bpf object so they can be mutated independently
    // of program access (which also borrows &mut Bpf).  This is safe because
    // take_map() moves the MapData out; subsequent program_mut() calls do not
    // touch the moved data.
    let mut pid_info_map: HashMap<_, u32, PidInfo> =
        HashMap::try_from(bpf.take_map("PID_INFO").unwrap())?;
    let mut binary_configs: HashMap<_, u64, BinaryConfig> =
        HashMap::try_from(bpf.take_map("BINARY_CONFIGS").unwrap())?;
    let mut watched_parents: HashMap<_, u32, u8> =
        HashMap::try_from(bpf.take_map("WATCHED_PARENTS").unwrap())?;
    let mut new_pids_buf: RingBuf<_> = RingBuf::try_from(bpf.take_map("NEW_PIDS").unwrap())?;
    let mut ring_buf: RingBuf<_> = RingBuf::try_from(bpf.take_map("EVENTS").unwrap())?;
    let drop_map: Array<_, u32> = Array::try_from(bpf.take_map("DROPPED_EVENTS").unwrap())?;

    // ── Load programs ─────────────────────────────────────────────────────────
    // Programs are loaded in isolated blocks so the &mut Bpf borrow ends before
    // the reconcile loop begins.  Uprobe attachment (in attach_new_binary) calls
    // bpf.program_mut() on demand; the program is already loaded by then.
    {
        let uprobe: &mut UProbe = bpf.program_mut("pg_pg_parse_query").unwrap().try_into()?;
        uprobe.load()?;
    }
    {
        let fork_prog: &mut TracePoint = bpf.program_mut("on_fork").unwrap().try_into()?;
        fork_prog.load()?;
        fork_prog.attach("sched", "sched_process_fork")?;
        info!("Attached sched_process_fork tracepoint");
    }

    // ── Agent state ───────────────────────────────────────────────────────────
    // known_binaries: inode → BinaryProfile for all binaries we have a probe on.
    // known_pids: set of PIDs currently in PID_INFO.
    let mut known_binaries: StdHashMap<u64, BinaryProfile> = StdHashMap::new();
    let mut known_pids: HashSet<u32> = HashSet::new();

    // ── Initial population ────────────────────────────────────────────────────
    // Block until at least one postgres process is visible.  This handles the
    // case where the agent starts before any postgres container is scheduled.
    loop {
        let (added, _removed, _new_bins, _) = reconcile(
            &mut bpf,
            &mut binary_configs,
            &mut pid_info_map,
            &mut watched_parents,
            &mut known_binaries,
            &mut known_pids,
        )?;
        if added > 0 {
            info!(
                "Initial scan complete: {} PID(s), {} binary image(s) registered.",
                known_pids.len(),
                known_binaries.len()
            );
            // Log each binary that was found.
            for (inode, profile) in &known_binaries {
                info!("  inode={} path={}", inode, profile.path);
            }
            metrics::PID_MAP_SIZE.set(known_pids.len() as i64);
            metrics::BINARY_COUNT.set(known_binaries.len() as i64);
            break;
        }
        info!("No Postgres processes found yet. Retrying in 2 s...");
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    // ── Connect to processor ──────────────────────────────────────────────────
    let mut processor_stream = connect_to_processor().await;
    let mut last_refresh = tokio::time::Instant::now();
    let mut last_drop_read = tokio::time::Instant::now();
    let mut last_drop_count: u32 = 0;

    // ── Shutdown state ────────────────────────────────────────────────────────
    // When a signal arrives we set shutting_down = true and stop accepting new
    // work (fork fast-path, reconciliation, drop counter reads) while continuing
    // to drain whatever remains in the eBPF ring buffer.  The drain runs until
    // the buffer is empty or the deadline expires, whichever comes first.
    let mut shutting_down = false;
    let mut shutdown_deadline: Option<tokio::time::Instant> = None;

    // ── Event loop ────────────────────────────────────────────────────────────
    loop {
        // ── Shutdown deadline check ───────────────────────────────────────────
        if let Some(deadline) = shutdown_deadline {
            if tokio::time::Instant::now() >= deadline {
                warn!(
                    "Shutdown drain deadline ({}s) exceeded — some in-flight \
                     events may have been lost.",
                    SHUTDOWN_DRAIN_SECS
                );
                break;
            }
        }

        // ── Fork fast-path (skip during shutdown) ─────────────────────────────
        if !shutting_down {
            while let Some(item) = new_pids_buf.next() {
                let child_pid = unsafe { *(item.as_ptr() as *const u32) };
                if known_pids.contains(&child_pid) {
                    continue;
                }

                // The child inherits its parent's binary image; its inode is
                // already in known_binaries.  We just need to write PID_INFO.
                // /proc/<child>/maps may not be populated yet immediately after
                // fork — scan_postgres_processes() returns None in that case, and
                // reconcile() will catch it on the next tick.
                if let Some(proc) = scan_postgres_processes()
                    .into_iter()
                    .find(|p| p.pid == child_pid)
                {
                    match push_pid_info(&mut pid_info_map, &proc) {
                        Ok(_) => {
                            let _ = watched_parents.insert(child_pid, 1u8, 0);
                            known_pids.insert(child_pid);
                            info!(
                                "Fork-registered PID {} (inode={} base=0x{:x})",
                                child_pid, proc.inode, proc.load_base
                            );
                        }
                        Err(e) => error!("Fork-register PID {}: {}", child_pid, e),
                    }
                }
            }
            // If /proc/<child> isn't ready yet, reconcile() picks it up.
        }

        // ── Periodic reconciliation (skip during shutdown) ────────────────────
        if !shutting_down && last_refresh.elapsed() >= PID_REFRESH_INTERVAL {
            match reconcile(
                &mut bpf,
                &mut binary_configs,
                &mut pid_info_map,
                &mut watched_parents,
                &mut known_binaries,
                &mut known_pids,
            ) {
                Ok((added, removed, new_bins, stale_pids)) => {
                    if added > 0 || removed > 0 || new_bins > 0 {
                        info!(
                            "Reconcile: +{} PIDs  -{} PIDs  +{} binary images  \
                             (total: {} PIDs  {} binaries)",
                            added,
                            removed,
                            new_bins,
                            known_pids.len(),
                            known_binaries.len()
                        );
                    }
                    metrics::PID_MAP_SIZE.set(known_pids.len() as i64);
                    metrics::BINARY_COUNT.set(known_binaries.len() as i64);

                    // Emit pid_exit for each stale PID so the processor can
                    // clean up session state for that connection.
                    if let Some(ref mut stream) = processor_stream {
                        for pid in stale_pids {
                            let exit_event = serde_json::json!({
                                "event_type": "pid_exit",
                                "pid": pid,
                            });
                            if let Ok(payload) = serde_json::to_vec(&exit_event) {
                                if !send_event(stream, &payload).await {
                                    error!("Lost processor connection sending pid_exit. Reconnecting...");
                                    processor_stream = connect_to_processor().await;
                                    break;
                                }
                                metrics::PID_EXIT_EVENTS_TOTAL.inc();
                            }
                        }
                    }
                }
                Err(e) => error!("Reconcile error: {}", e),
            }
            last_refresh = tokio::time::Instant::now();
        }

        // ── Periodic drop counter read (skip during shutdown) ─────────────────
        if !shutting_down && last_drop_read.elapsed() >= DROP_READ_INTERVAL {
            if let Ok(current) = drop_map.get(&0, 0) {
                if current > last_drop_count {
                    let delta = current - last_drop_count;
                    metrics::EVENTS_DROPPED_TOTAL.inc_by(delta as u64);
                    if delta > 0 {
                        warn!(
                            "Ring buffer overflow: {} events dropped in last {}s",
                            delta,
                            DROP_READ_INTERVAL.as_secs()
                        );
                    }
                    last_drop_count = current;
                }
            }
            last_drop_read = tokio::time::Instant::now();
        }

        // ── SQL event processing ──────────────────────────────────────────────
        if let Some(item) = ring_buf.next() {
            let event = unsafe { &*(item.as_ptr() as *const SqlEvent) };
            process_sql_event(event, &mut processor_stream, wall_offset_ns).await;
        } else {
            // Ring buffer is empty.
            if shutting_down {
                // Buffer confirmed empty — clean exit.
                info!("Ring buffer drained. Shutdown complete.");
                break;
            }

            // Normal idle: wait for either a signal or the next poll tick.
            tokio::select! {
                _ = signal::ctrl_c() => {
                    info!(
                        "SIGINT received — draining ring buffer (max {}s)...",
                        SHUTDOWN_DRAIN_SECS
                    );
                    shutting_down = true;
                    shutdown_deadline = Some(
                        tokio::time::Instant::now() + Duration::from_secs(SHUTDOWN_DRAIN_SECS)
                    );
                }
                _ = sigterm.recv() => {
                    info!(
                        "SIGTERM received — draining ring buffer (max {}s)...",
                        SHUTDOWN_DRAIN_SECS
                    );
                    shutting_down = true;
                    shutdown_deadline = Some(
                        tokio::time::Instant::now() + Duration::from_secs(SHUTDOWN_DRAIN_SECS)
                    );
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── port_field_offsets — standard PG ─────────────────────────────────────

    // TODO: cleanup test after verifying PORT_FLAG_HOST_IS_INLINE logic
    // #[test]
    // fn test_pg14_offsets() {
    //     let (host, db, user, flags) = port_field_offsets(14, false);
    //     assert_eq!((host, db, user), (288, 328, 336));
    //     assert_eq!(flags, PORT_FLAG_HOST_IS_INLINE);
    // }

    // TODO: cleanup test after verifying PORT_FLAG_HOST_IS_INLINE logic
    // #[test]
    // fn test_pg15_offsets() {
    //     let (host, db, user, flags) = port_field_offsets(15, false);
    //     assert_eq!((host, db, user), (288, 328, 336));
    //     assert_eq!(flags, PORT_FLAG_HOST_IS_INLINE);
    // }

    // TODO: cleanup test after verifying PORT_FLAG_HOST_IS_INLINE logic
    // #[test]
    // fn test_pg16_offsets() {
    //     let (host, db, user, flags) = port_field_offsets(16, false);
    //     assert_eq!((host, db, user), (288, 328, 336));
    //     assert_eq!(flags, PORT_FLAG_HOST_IS_INLINE);
    // }

    #[test]
    fn test_pg17_offsets() {
        let (host, db, user, flags) = port_field_offsets(17, false);
        assert_eq!((host, db, user), (288, 320, 328));
        assert_eq!(flags, 0);
    }

    #[test]
    fn test_pg18_offsets() {
        let (host, db, user, flags) = port_field_offsets(18, false);
        assert_eq!((host, db, user), (288, 384, 392));
        assert_eq!(flags, 0);
    }

    #[test]
    fn test_unknown_pg_falls_back_to_pg18() {
        let (host, db, user, flags) = port_field_offsets(99, false);
        assert_eq!((host, db, user), (288, 384, 392));
        assert_eq!(flags, 0);

        let (host, db, user, flags) = port_field_offsets(0, false);
        assert_eq!((host, db, user), (288, 384, 392));
        assert_eq!(flags, 0);
    }

    // ── port_field_offsets — EDB ──────────────────────────────────────────────

    #[test]
    fn test_edb17_offsets() {
        let (host, db, user, flags) = port_field_offsets(17, true);
        assert_eq!((host, db, user), (288, 320, 328));
        assert_eq!(flags, 0);
    }

    #[test]
    fn test_edb18_offsets() {
        let (host, db, user, flags) = port_field_offsets(18, true);
        assert_eq!((host, db, user), (288, 384, 392));
        assert_eq!(flags, 0);
    }

    #[test]
    fn test_unknown_edb_falls_back_to_edb18() {
        let (host, db, user, flags) = port_field_offsets(99, true);
        assert_eq!((host, db, user), (288, 384, 392));
        assert_eq!(flags, 0);
    }

    #[test]
    fn test_edb_and_pg17_offsets_match() {
        let pg17 = port_field_offsets(17, false);
        let edb17 = port_field_offsets(17, true);
        assert_eq!(pg17.0, edb17.0, "remote_host offset should match");
        assert_eq!(pg17.1, edb17.1, "database_name offset should match");
        assert_eq!(pg17.2, edb17.2, "user_name offset should match");
        assert_eq!(pg17.3, edb17.3);
    }

    #[test]
    fn test_edb_and_pg18_offsets_match() {
        let pg18 = port_field_offsets(18, false);
        let edb18 = port_field_offsets(18, true);
        assert_eq!(pg18.0, edb18.0);
        assert_eq!(pg18.1, edb18.1);
        assert_eq!(pg18.2, edb18.2);
        assert_eq!(pg18.3, edb18.3);
    }

    // TODO: cleanup test after verifying PORT_FLAG_HOST_IS_INLINE logic
    // #[test]
    // fn test_pg14_has_host_inline_flag_edb_does_not() {
    //     // Standard PG14 has inline remote_host; EDB14 would not (if it existed).
    //     let (_, _, _, pg14_flags) = port_field_offsets(14, false);
    //     let (_, _, _, edb14_flags) = port_field_offsets(14, true);
    //     assert_ne!(
    //         pg14_flags, edb14_flags,
    //         "Standard PG14 should have PORT_FLAG_HOST_IS_INLINE, EDB should not"
    //     );
    // }

    // ── detect_is_edb ─────────────────────────────────────────────────────────

    #[test]
    fn test_detect_is_edb_nonexistent_pid_returns_false() {
        let result = detect_is_edb(999999999);
        assert!(!result);
    }

    // ── detect_pg_major ───────────────────────────────────────────────────────

    #[test]
    fn test_detect_pg_major_pg18() {
        use std::io::Write;
        let path = std::env::temp_dir().join("pgdam_test_pg18");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"some binary data PostgreSQL 18.3 more data")
            .unwrap();
        drop(f);
        assert_eq!(detect_pg_major(path.to_str().unwrap()), Some(18));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_detect_pg_major_pg17() {
        use std::io::Write;
        let path = std::env::temp_dir().join("pgdam_test_pg17");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"PostgreSQL 17.1 (Debian 17.1-1.pgdg120+1)")
            .unwrap();
        drop(f);
        assert_eq!(detect_pg_major(path.to_str().unwrap()), Some(17));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_detect_pg_major_edb_version_string() {
        use std::io::Write;
        let path = std::env::temp_dir().join("pgdam_test_edb18");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"edb-postgres (EnterpriseDB) 18.1.0, based on PostgreSQL 18")
            .unwrap();
        drop(f);
        assert_eq!(detect_pg_major(path.to_str().unwrap()), Some(18));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_detect_pg_major_no_version() {
        use std::io::Write;
        let path = std::env::temp_dir().join("pgdam_test_noversion");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"some random binary data").unwrap();
        drop(f);
        assert_eq!(detect_pg_major(path.to_str().unwrap()), None);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_detect_pg_major_picks_highest() {
        use std::io::Write;
        let path = std::env::temp_dir().join("pgdam_test_multi");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"PostgreSQL 14 compat PostgreSQL 18 actual")
            .unwrap();
        drop(f);
        assert_eq!(detect_pg_major(path.to_str().unwrap()), Some(18));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_detect_pg_major_nonexistent_file() {
        assert_eq!(detect_pg_major("/nonexistent/path"), None);
    }

    // ── utf8_trim ─────────────────────────────────────────────────────────────

    #[test]
    fn test_utf8_trim_null_terminated() {
        let mut buf = [0u8; 64];
        buf[..8].copy_from_slice(b"postgres");
        assert_eq!(utf8_trim(&buf), "postgres");
    }

    #[test]
    fn test_utf8_trim_empty() {
        assert_eq!(utf8_trim(&[0u8; 64]), "");
    }

    #[test]
    fn test_utf8_trim_full_buffer() {
        assert_eq!(utf8_trim(&[b'a'; 64]), "a".repeat(64));
    }

    // ── stale PID detection ───────────────────────────────────────────────────

    #[test]
    fn test_stale_pid_detection() {
        let mut known: HashSet<u32> = [1, 2, 3, 4, 5].iter().copied().collect();
        let live: HashSet<u32> = [1, 3, 5].iter().copied().collect();

        let stale: Vec<u32> = known
            .iter()
            .filter(|p| !live.contains(p))
            .copied()
            .collect();

        assert_eq!(stale.len(), 2);
        assert!(stale.contains(&2));
        assert!(stale.contains(&4));

        for pid in &stale {
            known.remove(pid);
        }
        assert_eq!(known.len(), 3);
    }

    // ── load base strategy ────────────────────────────────────────────────────

    #[test]
    fn test_edb_load_base_picks_first_mapping() {
        // EDB binaries are not PIE — the first mapping is the load base,
        // not necessarily the r-xp segment.
        let maps = "\
            400000-500000 r--p 00000000 fd:01 1234 /usr/edb/as18/bin/edb-postgres\n\
            500000-600000 r-xp 00100000 fd:01 1234 /usr/edb/as18/bin/edb-postgres\n\
            600000-700000 rw-p 00200000 fd:01 1234 /usr/edb/as18/bin/edb-postgres\n";

        let exe_name = "edb-postgres";

        let edb_base = maps
            .lines()
            .find(|l| l.contains(exe_name))
            .and_then(|l| l.split('-').next())
            .and_then(|s| u64::from_str_radix(s, 16).ok());

        let std_base = maps
            .lines()
            .find(|l| l.contains("r-xp") && l.contains(exe_name))
            .and_then(|l| l.split('-').next())
            .and_then(|s| u64::from_str_radix(s, 16).ok());

        assert_eq!(edb_base, Some(0x400000));
        assert_eq!(std_base, Some(0x500000));
        assert_ne!(
            edb_base, std_base,
            "EDB and standard strategies should pick different base addresses"
        );
    }

    #[test]
    fn test_standard_load_base_picks_rxp_segment() {
        let maps = "\
            7f1234000000-7f1234100000 r--p 00000000 fd:01 5678 /usr/pgsql-18/bin/postgres\n\
            7f1234100000-7f1234200000 r-xp 00100000 fd:01 5678 /usr/pgsql-18/bin/postgres\n\
            7f1234200000-7f1234300000 rw-p 00200000 fd:01 5678 /usr/pgsql-18/bin/postgres\n";

        let exe_name = "postgres";

        let std_base = maps
            .lines()
            .find(|l| l.contains("r-xp") && l.contains(exe_name))
            .and_then(|l| l.split('-').next())
            .and_then(|s| u64::from_str_radix(s, 16).ok());

        assert_eq!(std_base, Some(0x7f1234100000u64));
    }
}
