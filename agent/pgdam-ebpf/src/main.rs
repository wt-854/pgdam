#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_ktime_get_tai_ns, bpf_probe_read_user,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint, uprobe},
    maps::{Array, HashMap, RingBuf},
    programs::{ProbeContext, TracePointContext},
};
use pgdam_common::{BinaryConfig, PidInfo, SqlEvent};

#[map]
static mut PID_INFO: HashMap<u32, PidInfo> = HashMap::with_max_entries(10240, 0);

#[map]
static mut BINARY_CONFIGS: HashMap<u64, BinaryConfig> = HashMap::with_max_entries(256, 0);

#[map]
static mut WATCHED_PARENTS: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);

#[map]
static mut NEW_PIDS: RingBuf = RingBuf::with_byte_size(4096, 0);

// Ring buffer for SQL events. Set to 64 MB as a baseline for high query volumes
// Tune upward if pgdam_events_dropped_total increments under load.
#[map]
static mut EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024 * 1024, 0);

// Single-entry counter incremented when EVENTS ring buffer is full.
// Read periodically by the agent and exposed as a Prometheus metric.
#[map]
static mut DROPPED_EVENTS: Array<u32> = Array::with_max_entries(1, 0);

// sched_process_fork tracepoint memory layout:
// offset  0–7  : common header
// offset  8–23 : parent_comm[16]
// offset 24–27 : parent_pid
// offset 28–43 : child_comm[16]
// offset 44–47 : child_pid
#[tracepoint(name = "on_fork", category = "sched")]
pub fn on_fork(ctx: TracePointContext) -> i64 {
    let parent_pid: u32 = unsafe {
        match ctx.read_at::<u32>(24) {
            Ok(v) => v,
            Err(_) => return 0,
        }
    };
    let child_pid: u32 = unsafe {
        match ctx.read_at::<u32>(44) {
            Ok(v) => v,
            Err(_) => return 0,
        }
    };

    if unsafe { WATCHED_PARENTS.get(&parent_pid).is_none() } {
        return 0;
    }

    if let Some(mut slot) = unsafe { NEW_PIDS.reserve::<u32>(0) } {
        unsafe {
            *slot.as_mut_ptr() = child_pid;
        }
        slot.submit(0);
    }
    0
}

#[uprobe]
pub fn pg_pg_parse_query(ctx: ProbeContext) -> u32 {
    match try_pg_parse_query(ctx) {
        Ok(r) => r,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_pg_parse_query(ctx: ProbeContext) -> Result<u32, i64> {
    let pid: u32 = (bpf_get_current_pid_tgid() >> 32) as u32;
    let query_ptr: *const u8 = ctx.arg(0).ok_or(0i64)?;

    // Reserve ring buffer space. If the buffer is full, increment the drop
    // counter and return — the event is lost but we have visibility into it.
    let mut event = match unsafe { EVENTS.reserve::<SqlEvent>(0) } {
        Some(e) => e,
        None => {
            unsafe {
                if let Some(ptr) = DROPPED_EVENTS.get_ptr_mut(0) {
                    *ptr += 1;
                }
            }
            return Ok(0);
        }
    };

    let ep = event.as_mut_ptr();

    unsafe {
        (*ep).pid = pid;
        (*ep).flags = 0;
        (*ep).timestamp = bpf_ktime_get_tai_ns();

        let bytes_read = match bpf_probe_read_user_str_bytes(query_ptr, &mut (*ep).payload) {
            Ok(b) => b.len() as u32,
            Err(_) => 0,
        };
        (*ep).payload_len = bytes_read;

        // bpf_probe_read_user_str_bytes always null-terminates, so a full
        // buffer (512 bytes including the null terminator) means the SQL was
        // longer than the buffer and was truncated.
        if bytes_read == (*ep).payload.len() as u32 {
            (*ep).flags |= pgdam_common::FLAG_TRUNCATED;
        }

        let Some(info) = PID_INFO.get(&pid) else {
            (*ep).flags |= pgdam_common::FLAG_NO_PORT_INFO;
            event.submit(0);
            return Ok(0);
        };

        let Some(cfg) = BINARY_CONFIGS.get(&info.binary_inode) else {
            (*ep).flags |= pgdam_common::FLAG_NO_PORT_INFO;
            event.submit(0);
            return Ok(0);
        };

        let abs_addr = info.load_base + cfg.symbol_offset;

        match bpf_probe_read_user::<*const core::ffi::c_void>(abs_addr as *const _) {
            Ok(port_ptr) if !port_ptr.is_null() => {
                macro_rules! read_str {
                    ($off:expr, $buf:expr) => {
                        if let Ok(ptr) = bpf_probe_read_user::<*const u8>(
                            (port_ptr as usize + $off as usize) as *const _,
                        ) {
                            if !ptr.is_null() {
                                let _ = bpf_probe_read_user_str_bytes(ptr, $buf);
                            }
                        }
                    };
                }
                read_str!(cfg.off_user_name, &mut (*ep).user_name);
                read_str!(cfg.off_database_name, &mut (*ep).database_name);
                read_str!(cfg.off_remote_host, &mut (*ep).remote_host);
            }
            _ => {
                (*ep).flags |= pgdam_common::FLAG_NO_CLIENT;
            }
        }
    }

    event.submit(0);
    Ok(0)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
