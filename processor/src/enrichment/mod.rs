pub mod bare_metal;
pub mod container;
pub mod k8s;

use async_trait::async_trait;
use log::warn;

/// Metadata attached to every processed event after enrichment.
/// Fields are empty strings when the enricher cannot determine them.
#[derive(Debug, Clone, Default)]
pub struct EnrichmentContext {
    pub hostname: String,
    pub container_id: String,
    pub container_name: String,
    pub k8s_pod: String,
    pub k8s_namespace: String,
    pub k8s_node: String,
    pub k8s_labels: std::collections::HashMap<String, String>,
}

#[async_trait]
pub trait Enricher: Send + Sync {
    /// Attempt to enrich. Returns None if this enricher is not applicable
    /// in the current environment.
    async fn enrich(&self, pid: u32) -> Option<EnrichmentContext>;
}

/// Detects the environment and returns the appropriate enricher chain.
/// Tries K8s first, then container runtime, then bare metal.
pub fn detect_enricher() -> Box<dyn Enricher> {
    // K8s injects this env var into every pod automatically.
    if std::env::var("KUBERNETES_SERVICE_HOST").is_ok() {
        let node_name = std::env::var("NODE_NAME").unwrap_or_else(|_| {
            warn!("NODE_NAME env var not set; K8s enrichment will be degraded.");
            String::new()
        });
        return Box::new(k8s::K8sEnricher::new(node_name));
    }

    // Not in K8s — check if we can read a container ID from /proc cgroup.
    // If so, use the container enricher (Docker/containerd/podman).
    if container::is_containerized() {
        return Box::new(container::ContainerEnricher::new());
    }

    // Pure bare metal — hostname only.
    Box::new(bare_metal::BareMetalEnricher::new())
}
