use log::{error, info, warn};

/// Terminate a postgres backend process by sending SIGTERM to its PID.
///
/// This is equivalent to `SELECT pg_terminate_backend(pid)` but requires
/// no postgres credentials — the processor runs with `privileged: true`
/// and `hostPID: true` so it can signal any process on the host.
///
/// SIGTERM allows the backend to clean up (release locks, roll back any
/// open transaction) before exiting. If the process does not exit within
/// postgres's deadlock_timeout, postgres will send SIGKILL automatically.
pub fn terminate_session(pid: u32) -> bool {
    info!(
        "Kill-switch: sending SIGTERM to postgres backend PID {}",
        pid
    );

    let result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };

    if result == 0 {
        info!("Kill-switch: SIGTERM delivered to PID {}", pid);
        true
    } else {
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            // ESRCH — process no longer exists, already gone.
            Some(libc::ESRCH) => {
                warn!("Kill-switch: PID {} no longer exists (already exited)", pid);
                true
            }
            // EPERM — insufficient permissions. Should not happen with
            // privileged: true but log clearly if it does.
            Some(libc::EPERM) => {
                error!(
                    "Kill-switch: permission denied sending SIGTERM to PID {}. \
                     Ensure the processor container has privileged: true.",
                    pid
                );
                false
            }
            _ => {
                error!(
                    "Kill-switch: failed to send SIGTERM to PID {}: {}",
                    pid, err
                );
                false
            }
        }
    }
}
