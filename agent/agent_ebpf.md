# Agent: Low-Level Engineer (eBPF)
**Role:** Kernel-Space & Hook Specialist
**Scope:** `/agent/ebpf`

## Tech Stack
- **Language:** Rust
- **Framework:** Aya (eBPF)
- **Hooks:** uprobes (`libssl.so`), kprobes (`sys_read/write`), tracepoints.

## Development Constraints
1. **Memory Safety:** Strictly avoid `unsafe` Rust unless interacting with BPF maps; document every safety boundary.
2. **Zero-Copy:** Use `BPF_MAP_TYPE_RINGBUF` for all data transfers to user-space.
3. **Uprobe Tax:** Minimize the logic inside uprobes. Offload protocol parsing to the user-space agent component.
4. **Non-Blocking:** Under no circumstances should the eBPF code block the target database process.
