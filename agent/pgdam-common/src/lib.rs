#![no_std]

pub const FLAG_NO_PORT_INFO: u32 = 1 << 0; // PID not in map yet — registration race
pub const FLAG_NO_CLIENT:    u32 = 1 << 1; // PID known but port_ptr is null — background worker

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SqlEvent {
    pub pid: u32,
    pub flags: u32,
    pub timestamp: u64,
    pub payload_len: u32,
    pub payload: [u8; 128],
    pub user_name: [u8; 64],
    pub database_name: [u8; 64],
    pub remote_host: [u8; 48],
}
