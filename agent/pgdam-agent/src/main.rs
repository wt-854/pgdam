// pgdam-agent/src/main.rs
use aya::{
    include_bytes_aligned,
    maps::{HashMap, RingBuf},
    programs::{TracePoint, UProbe},
    Bpf,
};
use log::{error, info, warn};
use object::{Object, ObjectSegment, ObjectSymbol};
use pgdam_common::{BinaryConfig, PidInfo, SqlEvent};
use serde::Serialize;
use std::{
    collections::{HashMap as StdHashMap, HashSet},
    convert::TryFrom,
    os::unix::fs::MetadataExt,
    time::Duration,
};
use tokio::{io::AsyncWriteExt, net::UnixStream, signal};

// SqlEvent is only read from the ring-buffer via raw pointer cast, so it does
// not need Pod.

const PID_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const SOCKET_PATH: &str = "/tmp/pgdam.sock";

// ── Serialisable audit record ─────────────────────────────────────────────────

#[derive(Serialize)]
struct AuditEventJson {
    pid: u32,
    timestamp: u64,
    raw_sql: String,
    user: String,
    db: String,
    src_ip: String,
    incomplete: bool,
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
}

/// One live postgres process.
#[derive(Clone, Debug)]
struct ProcessEntry {
    pid: u32,
    load_base: u64,
    /// Matches BinaryProfile.inode for the binary this process runs.
    inode: u64,
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
    let pos = data.windows(marker.len()).position(|w| w == marker)?;
    let tail = &data[pos + marker.len()..][..8];
    std::str::from_utf8(tail)
        .ok()?
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()
}

/// Return Port struct field offsets (remote_host, database_name, user_name)
/// for a given PostgreSQL major version.
///
/// These offsets were validated against stock Debian/Ubuntu packages compiled
/// with the default flags.  Alpine (musl libc) and RHEL builds may produce
/// different struct layouts due to alignment differences — extend this table
/// with empirical measurements when those flavours are encountered.
///
/// A future enhancement can replace this table with DWARF-based offset
/// extraction using the `gimli` crate: parse `.debug_info`, walk to the Port
/// type, and read field offsets directly from the debug info.  That would make
/// the agent correct for every build without any manual table maintenance.
fn port_field_offsets(major: u32) -> (u32, u32, u32) {
    // (off_remote_host, off_database_name, off_user_name)
    match major {
        16 | 17 | 18 => (288, 384, 392),
        _ => {
            warn!(
                "Unknown PG major version {}; falling back to PG18 Port offsets. \
                 Consider adding an entry to port_field_offsets().",
                major
            );
            (288, 384, 392)
        }
    }
}

/// Read, parse, and profile a Postgres binary: compute the symbol offset and
/// choose the correct Port field offsets for its version.
fn analyze_binary(path: &str) -> Option<BinaryProfile> {
    let meta = std::fs::metadata(path).ok()?;
    let inode = meta.ino();
    let offset = find_symbol_offset(path, "MyProcPort")?;
    let major = detect_pg_major(path).unwrap_or(18);
    let (off_remote_host, off_database_name, off_user_name) = port_field_offsets(major);

    info!(
        "Binary analysis: path={} inode={} pg{} MyProcPort+0x{:x} \
         remote_host+{} database_name+{} user_name+{}",
        path, inode, major, offset, off_remote_host, off_database_name, off_user_name
    );
    Some(BinaryProfile {
        path: path.to_string(),
        inode,
        symbol_offset: offset,
        off_remote_host,
        off_database_name,
        off_user_name,
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
        if comm.trim() != "postgres" {
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

        // Extract the r-xp load base from /proc/<pid>/maps.  We match by exe
        // filename rather than full path because overlayfs may expose a
        // shortened path in the maps file.
        let Ok(maps) = std::fs::read_to_string(proc_dir.join("maps")) else {
            continue;
        };
        let exe_name = exe
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("postgres");
        let load_base = maps
            .lines()
            .find(|l| l.contains("r-xp") && l.contains(exe_name))
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
            _pad: 0,
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
        .ok_or_else(|| anyhow::anyhow!("uprobe program not found in eBPF object"))?
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

// ── Reconciliation ────────────────────────────────────────────────────────────

/// Reconcile agent state against the live /proc snapshot:
///
///  1. For every process whose binary inode has not been seen before:
///     analyse the binary, attach a new uprobe, write BINARY_CONFIGS.
///
///  2. For every process not yet in known_pids:
///     write PID_INFO and add to WATCHED_PARENTS.
///
///  3. For every PID in known_pids that no longer exists in /proc:
///     remove from PID_INFO and known_pids.
///
/// Returns (pids_added, pids_removed, binaries_added).
fn reconcile(
    bpf: &mut Bpf,
    binary_configs: &mut HashMap<aya::maps::MapData, u64, BinaryConfig>,
    pid_info_map: &mut HashMap<aya::maps::MapData, u32, PidInfo>,
    watched_parents: &mut HashMap<aya::maps::MapData, u32, u8>,
    known_binaries: &mut StdHashMap<u64, BinaryProfile>,
    known_pids: &mut HashSet<u32>,
) -> anyhow::Result<(usize, usize, usize)> {
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
        // WATCHED_PARENTS is not cleaned up here intentionally: the fork
        // tracepoint silently discards events for unknown child PIDs, so
        // leaving stale entries only wastes a tiny amount of map space and
        // avoids a second map syscall per removed PID.
    }

    // ── Register new binaries and PIDs ────────────────────────────────────────
    let mut pids_added = 0usize;
    let mut binaries_added = 0usize;

    for proc in &live {
        // New binary: resolve host path, analyse, attach, write config.
        if !known_binaries.contains_key(&proc.inode) {
            let exe_path = format!("/proc/{}/exe", proc.pid);
            if !std::path::Path::new(&exe_path).exists() {
                continue;
            }

            if exe_path.is_empty() || exe_path.ends_with("(deleted)") {
                continue;
            }

            match analyze_binary(&exe_path) {
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

    Ok((pids_added, removed, binaries_added))
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

// ── Utility ───────────────────────────────────────────────────────────────────

fn utf8_trim(buf: &[u8]) -> &str {
    std::str::from_utf8(buf).unwrap_or("").trim_matches('\0')
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    info!("Starting pgdam-agent (multi-binary mode)...");

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
        let (added, _removed, _new_bins) = reconcile(
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
            break;
        }
        info!("No Postgres processes found yet. Retrying in 2 s...");
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    // ── Connect to processor ──────────────────────────────────────────────────
    let mut processor_stream = connect_to_processor().await;
    let mut last_refresh = tokio::time::Instant::now();

    // ── Event loop ────────────────────────────────────────────────────────────
    loop {
        // -- Fork fast-path ─────────────────────────────────────────────────
        // The fork tracepoint fires in kernel context and immediately writes
        // child PIDs here.  Processing them now (before the next reconcile
        // tick) minimises the window where a forked worker fires pg_parse_query
        // before its PID_INFO entry exists.
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
            // If /proc/<child> isn't ready yet, reconcile() picks it up.
        }

        // -- Periodic reconciliation ─────────────────────────────────────────
        // Catches new containers/binaries that started since the last tick,
        // removes PIDs that exited, and attaches probes to new binary images.
        if last_refresh.elapsed() >= PID_REFRESH_INTERVAL {
            match reconcile(
                &mut bpf,
                &mut binary_configs,
                &mut pid_info_map,
                &mut watched_parents,
                &mut known_binaries,
                &mut known_pids,
            ) {
                Ok((added, removed, new_bins)) => {
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
                }
                Err(e) => error!("Reconcile error: {}", e),
            }
            last_refresh = tokio::time::Instant::now();
        }

        // -- SQL event processing ─────────────────────────────────────────────
        if let Some(item) = ring_buf.next() {
            let event = unsafe { &*(item.as_ptr() as *const SqlEvent) };

            let sql = std::str::from_utf8(&event.payload[..event.payload_len as usize])
                .unwrap_or("<invalid utf8>");

            let incomplete = (event.flags & pgdam_common::FLAG_NO_PORT_INFO) != 0;
            let bg_worker = (event.flags & pgdam_common::FLAG_NO_CLIENT) != 0;

            // Background workers have no client connection and no meaningful
            // user/db context; skip them entirely.
            if bg_worker {
                continue;
            }

            let user = utf8_trim(&event.user_name);
            let db = utf8_trim(&event.database_name);
            let src_ip = utf8_trim(&event.remote_host);

            if incomplete {
                warn!(
                    "Incomplete event PID {}: sql=\"{}\" \
                     (PID_INFO race — will resolve after next reconcile)",
                    event.pid,
                    sql.trim()
                );
            } else {
                info!(
                    "pid={} user={} db={} src={} sql=\"{}\"",
                    event.pid,
                    user,
                    db,
                    src_ip,
                    sql.trim()
                );
            }

            let audit = AuditEventJson {
                pid: event.pid,
                timestamp: event.timestamp,
                raw_sql: sql.to_string(),
                user: user.to_string(),
                db: db.to_string(),
                src_ip: src_ip.to_string(),
                incomplete,
            };

            if let Some(ref mut stream) = processor_stream {
                let mut payload = serde_json::to_vec(&audit)?;
                payload.push(b'\n');
                if let Err(e) = stream.write_all(&payload).await {
                    error!("Lost processor connection: {}. Reconnecting...", e);
                    processor_stream = connect_to_processor().await;
                }
            }
        } else {
            // Ring buffer is empty — yield to the runtime or handle Ctrl-C.
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
