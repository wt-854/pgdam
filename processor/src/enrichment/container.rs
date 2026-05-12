use super::{Enricher, EnrichmentContext};
use async_trait::async_trait;
use hostname;
use log::warn;

pub fn read_container_id(pid: u32) -> Option<String> {
    let cgroup = std::fs::read_to_string(format!("/proc/{}/cgroup", pid)).ok()?;

    for line in cgroup.lines() {
        // cgroup v2 containerd format:
        // 0::/../../kubepods-*.slice/cri-containerd-<ID>.scope
        if let Some(rest) = line.split("cri-containerd-").nth(1) {
            if let Some(id) = rest.split('.').next() {
                if id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Some(id.to_string());
                }
            }
        }

        // cgroup v2 docker format:
        // 0::/../../kubepods-*.slice/docker-<ID>.scope
        if let Some(rest) = line.split("docker-").nth(1) {
            if let Some(id) = rest.split('.').next() {
                if id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Some(id.to_string());
                }
            }
        }

        // cgroup v1 fallback — container ID as a 64-char path segment
        if let Some(id) = line
            .split('/')
            .find(|s| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()))
        {
            return Some(id.to_string());
        }
    }
    None
}

/// Check if the current process itself is running inside a container.
pub fn is_containerized() -> bool {
    read_container_id(1).is_some()
}

pub struct ContainerEnricher {
    hostname: String,
}

impl ContainerEnricher {
    pub fn new() -> Self {
        let hostname = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "unknown".to_string());
        Self { hostname }
    }
}

#[async_trait]
impl Enricher for ContainerEnricher {
    async fn enrich(&self, pid: u32) -> Option<EnrichmentContext> {
        let container_id = match read_container_id(pid) {
            Some(id) => id,
            None => {
                warn!("Could not read container ID for PID {}", pid);
                return Some(EnrichmentContext {
                    hostname: self.hostname.clone(),
                    ..Default::default()
                });
            }
        };

        Some(EnrichmentContext {
            hostname: self.hostname.clone(),
            container_id: container_id.clone(),
            container_name: container_id[..12].to_string(), // short ID as fallback name
            ..Default::default()
        })
    }
}
