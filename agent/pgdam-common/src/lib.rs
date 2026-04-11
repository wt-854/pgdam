#![no_std]

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SqlEvent {
    pub pid: u32,
    pub timestamp: u64,
    pub payload_len: u32,
    pub payload: [u8; 128],
    pub user_name: [u8; 64],
    pub database_name: [u8; 64],
    pub remote_host: [u8; 48],
}
