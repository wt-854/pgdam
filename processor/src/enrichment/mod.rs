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
pub async fn detect_enricher() -> Box<dyn Enricher> {
    // K8s injects this env var into every pod automatically.
    if std::env::var("KUBERNETES_SERVICE_HOST").is_ok() {
        let node_name = std::env::var("NODE_NAME").unwrap_or_else(|_| {
            warn!("NODE_NAME env var not set; K8s enrichment will be degraded.");
            String::new()
        });
        match k8s::K8sEnricher::new(node_name).await {
            Ok(e) => {
                log::info!("K8s enricher initialized");
                return Box::new(e);
            }
            Err(e) => {
                warn!("Failed to initialize K8s enricher: {} — falling back.", e);
            }
        }
    }

    if container::is_containerized() {
        log::info!("Container enricher initialized");
        return Box::new(container::ContainerEnricher::new());
    }

    log::info!("Bare metal enricher initialized");
    Box::new(bare_metal::BareMetalEnricher::new())
}
