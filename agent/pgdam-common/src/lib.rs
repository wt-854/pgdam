#![no_std]

pub const FLAG_NO_PORT_INFO: u32 = 1 << 0;
pub const FLAG_NO_CLIENT: u32 = 1 << 1;
pub const FLAG_TRUNCATED: u32 = 1 << 2;
pub const PORT_FLAG_HOST_IS_INLINE: u32 = 1 << 0; // remote_host is char[] not char*
pub const PORT_FLAG_DB_IS_INLINE: u32 = 1 << 1; // database_name is char[] not char*
pub const PORT_FLAG_USER_IS_INLINE: u32 = 1 << 2; // user_name is char[] not char*

/// Per-process runtime info written by the agent, consumed by every uprobe
/// firing.  Stored in the PID_INFO map, keyed by PID (u32).
///
/// Combining load_base and binary_inode in a single struct halves the number
/// of BPF map lookups in the hot path compared to two separate maps.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct PidInfo {
    /// Virtual base address of the first r-xp segment (from /proc/<pid>/maps).
    /// Combined with BinaryConfig.symbol_offset this gives the absolute runtime
    /// address of MyProcPort for this specific process instance.
    pub load_base: u64,

    /// Host-namespace inode number of /proc/<pid>/exe.  Used as the key into
    /// BINARY_CONFIGS so the eBPF program selects the correct per-binary ruler
    /// without any userspace involvement at query time.
    pub binary_inode: u64,
}

/// Static analysis results for one unique Postgres binary, identified by its
/// host-namespace inode.  Written once at binary discovery time; never mutated.
/// Stored in BINARY_CONFIGS, keyed by inode (u64).
///
/// Using inode as key is correct even for multi-container environments: two
/// containers that share the same inode share the same on-disk bytes and
/// therefore the same symbol offsets and struct layout — any binary compiled
/// differently will have a different inode.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct BinaryConfig {
    /// MyProcPort virtual address − load_base, i.e. the PIE-corrected ELF
    /// symbol offset.  Produced by find_symbol_offset() in the agent.
    pub symbol_offset: u64,

    /// Byte offset of Port.remote_host within the Port struct.
    pub off_remote_host: u32,

    /// Byte offset of Port.database_name within the Port struct.
    pub off_database_name: u32,

    /// Byte offset of Port.user_name within the Port struct.
    pub off_user_name: u32,

    /// Explicit padding so the struct size is a multiple of 8 bytes and the
    /// eBPF verifier does not reject it as unaligned.
    pub port_flags: u32,
}

/// Ring-buffer event: one SQL query capture forwarded to the agent.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SqlEvent {
    pub pid: u32,
    pub flags: u32,
    pub timestamp: u64,
    pub payload_len: u32,
    pub payload: [u8; 512],
    pub user_name: [u8; 64],
    pub database_name: [u8; 64],
    pub remote_host: [u8; 48],
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for BinaryConfig {}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for PidInfo {}
