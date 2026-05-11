use super::{Enricher, EnrichmentContext};
use async_trait::async_trait;

pub struct BareMetalEnricher {
    hostname: String,
}

impl BareMetalEnricher {
    pub fn new() -> Self {
        let hostname = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "unknown".to_string());
        Self { hostname }
    }
}

#[async_trait]
impl Enricher for BareMetalEnricher {
    async fn enrich(&self, _pid: u32) -> Option<EnrichmentContext> {
        Some(EnrichmentContext {
            hostname: self.hostname.clone(),
            ..Default::default()
        })
    }
}
