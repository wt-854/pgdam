#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{uprobe, map, tracepoint},
    maps::{RingBuf, HashMap},
    programs::{ProbeContext, TracePointContext},  // both needed
    helpers::{
        bpf_get_current_pid_tgid,
        bpf_ktime_get_tai_ns,
        bpf_probe_read_user,
        bpf_probe_read_user_str_bytes,
    },
    EbpfContext,
};
use pgdam_common::SqlEvent;

// Single entry (key=0): MyProcPort symbol offset from binary load base.
// Written once at agent startup, never changes.
#[map]
static mut CONFIG_OFFSET: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

// Per-PID map: pid -> absolute runtime address of MyProcPort for that process.
// Populated by both the agent refresh loop and the fork tracepoint path.
#[map]
static mut PID_BASES: HashMap<u32, u64> = HashMap::with_max_entries(10240, 0);

// Master postgres PIDs to watch for forks.
// Agent writes the long-lived postmaster PID(s) here at startup.
#[map]
static mut WATCHED_PARENTS: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);

// Fork tracepoint writes child PIDs here so the agent can register them
// instantly without waiting for the next /proc poll.
#[map]
static mut NEW_PIDS: RingBuf = RingBuf::with_byte_size(4096, 0);

// SQL events forwarded to the agent's ring buffer consumer.
#[map]
static mut EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

// Offsets within Port struct for PostgreSQL 18.
const OFFSET_REMOTE_HOST: usize = 288;
const OFFSET_DATABASE_NAME: usize = 384;
const OFFSET_USER_NAME: usize = 392;

// Tracepoint context layout for sched_process_fork.
#[repr(C)]
struct ForkArgs {
    _common: [u8; 8], // common tracepoint header fields
    parent_pid: u32,
    child_pid: u32,
}

/// Fires at fork() time. If the forking process is a watched postgres master,
/// emit the child PID into NEW_PIDS so the agent can register it immediately
/// before the child runs its first query.
#[tracepoint(name = "on_fork", category = "sched")]
pub fn on_fork(ctx: TracePointContext) -> i64 {
    let args = unsafe {
        match (ctx.as_ptr() as *const ForkArgs).as_ref() {
            Some(a) => a,
            None => return 0,
        }
    };

    let parent_pid: u32 = args.parent_pid;
    let child_pid: u32 = args.child_pid;

    if unsafe { WATCHED_PARENTS.get(&parent_pid).is_none() } {
        return 0;
    }

    if let Some(mut entry) = unsafe { NEW_PIDS.reserve::<u32>(0) } {
        unsafe { *entry.as_mut_ptr() = child_pid; }
        entry.submit(0);
    }

    0
}

#[uprobe]
pub fn pg_pg_parse_query(ctx: ProbeContext) -> u32 {
    match try_pg_parse_query(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_pg_parse_query(ctx: ProbeContext) -> Result<u32, i64> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let query_ptr: *const u8 = ctx.arg(0).ok_or(0i64)?;

    let mut event = unsafe { EVENTS.reserve::<SqlEvent>(0) }.ok_or(0i64)?;
    let ep = event.as_mut_ptr();

    unsafe {
        (*ep).pid = pid;
        (*ep).flags = 0;
        (*ep).timestamp = bpf_ktime_get_tai_ns();

        let read_res = bpf_probe_read_user_str_bytes(query_ptr, &mut (*ep).payload);
        (*ep).payload_len = match read_res {
            Ok(bytes) => bytes.len() as u32,
            Err(_) => 0,
        };

        // Resolve: abs_addr = PID_BASES[pid] + CONFIG_OFFSET[0]
        let base_ptr   = PID_BASES.get(&pid);
        let offset_ptr = CONFIG_OFFSET.get(&0u32);

        match (base_ptr, offset_ptr) {
            (Some(base), Some(offset)) => {
                let abs_addr = *base + *offset;

                match bpf_probe_read_user::<*const core::ffi::c_void>(abs_addr as *const _) {
                    Ok(port_ptr) if !port_ptr.is_null() => {
                        if let Ok(user_ptr) = bpf_probe_read_user::<*const u8>(
                            (port_ptr as usize + OFFSET_USER_NAME) as *const _,
                        ) {
                            if !user_ptr.is_null() {
                                let _ = bpf_probe_read_user_str_bytes(user_ptr, &mut (*ep).user_name);
                            }
                        }

                        if let Ok(db_ptr) = bpf_probe_read_user::<*const u8>(
                            (port_ptr as usize + OFFSET_DATABASE_NAME) as *const _,
                        ) {
                            if !db_ptr.is_null() {
                                let _ = bpf_probe_read_user_str_bytes(db_ptr, &mut (*ep).database_name);
                            }
                        }

                        if let Ok(host_ptr) = bpf_probe_read_user::<*const u8>(
                            (port_ptr as usize + OFFSET_REMOTE_HOST) as *const _,
                        ) {
                            if !host_ptr.is_null() {
                                let _ = bpf_probe_read_user_str_bytes(host_ptr, &mut (*ep).remote_host);
                            }
                        }
                    }
                    _ => {
                        (*ep).flags |= pgdam_common::FLAG_NO_CLIENT;
                    }
                }
            }
            _ => {
                (*ep).flags |= pgdam_common::FLAG_NO_PORT_INFO;
            }
        }
    }

    event.submit(0);
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}