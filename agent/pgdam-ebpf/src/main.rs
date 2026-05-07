#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{uprobe, map},
    maps::{RingBuf, HashMap},
    programs::ProbeContext,
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_tai_ns, bpf_probe_read_user, bpf_probe_read_user_str_bytes},
};
use pgdam_common::SqlEvent;

#[map]
static mut EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

#[map]
static mut CONFIG: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

const KEY_MY_PROC_PORT_ADDR: u32 = 1;   // hardcoded key, not per-PID

// Offsets for PostgreSQL 18 (adjust if needed for older versions)
const OFFSET_REMOTE_HOST: usize = 288;
const OFFSET_DATABASE_NAME: usize = 384;
const OFFSET_USER_NAME: usize = 392;

#[uprobe]
pub fn pg_pg_parse_query(ctx: ProbeContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let query_ptr: *const u8 = match ctx.arg(0) {
        Some(ptr) => ptr,
        None => return 0,
    };

    let mut event = match unsafe { EVENTS.reserve::<SqlEvent>(0) } {
        Some(e) => e,
        None => return 0,
    };

    let event_ptr = event.as_mut_ptr();
    unsafe {
        (*event_ptr).pid = pid;
        (*event_ptr).timestamp = bpf_ktime_get_tai_ns();

        // Read SQL string
        let read_res = bpf_probe_read_user_str_bytes(query_ptr, &mut (*event_ptr).payload);
        (*event_ptr).payload_len = match read_res {
            Ok(bytes) => bytes.len() as u32,
            Err(_) => 0,
        };

        // 2. Attribution Logic: Read session info from MyProcPort
        if let Some(addr_ptr) = CONFIG.get(&KEY_MY_PROC_PORT_ADDR) {
            let addr = *addr_ptr;
            if addr != 0 {
                if let Ok(port_ptr) = bpf_probe_read_user::<*const core::ffi::c_void>(addr as *const _) {
                    if !port_ptr.is_null() {
                        // Read user_name pointer from Port struct
                        if let Ok(user_ptr) = bpf_probe_read_user::<*const u8>((port_ptr as usize + OFFSET_USER_NAME) as *const _) {
                            if !user_ptr.is_null() {
                                let _ = bpf_probe_read_user_str_bytes(user_ptr, &mut (*event_ptr).user_name);
                            }
                        }

                        // Read database_name pointer from Port struct
                        if let Ok(db_ptr) = bpf_probe_read_user::<*const u8>((port_ptr as usize + OFFSET_DATABASE_NAME) as *const _) {
                            if !db_ptr.is_null() {
                                let _ = bpf_probe_read_user_str_bytes(db_ptr, &mut (*event_ptr).database_name);
                            }
                        }

                        // Read remote_host pointer from Port struct
                        if let Ok(host_ptr) = bpf_probe_read_user::<*const u8>((port_ptr as usize + OFFSET_REMOTE_HOST) as *const _) {
                            if !host_ptr.is_null() {
                                let _ = bpf_probe_read_user_str_bytes(host_ptr, &mut (*event_ptr).remote_host);
                            }
                        }
                    }
                }
            }
        }
    }

    event.submit(0);
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}