use super::{Enricher, EnrichmentContext};
use crate::metrics;
use async_trait::async_trait;
use k8s_openapi::api::core::v1::Pod;
use kube::{api::ListParams, Api, Client};
use log::{debug, warn};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

const CACHE_TTL: Duration = Duration::from_secs(300); // 5 minutes

#[derive(Clone)]
struct CacheEntry {
    context: EnrichmentContext,
    inserted_at: Instant,
}

pub struct K8sEnricher {
    node_name: String,
    /// pid → EnrichmentContext cache to avoid hammering the K8s API
    cache: Arc<Mutex<HashMap<u32, CacheEntry>>>,
}

impl K8sEnricher {
    pub fn new(node_name: String) -> Self {
        Self {
            node_name,
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Read the container ID from /proc/<pid>/cgroup.
    fn container_id_for(pid: u32) -> Option<String> {
        crate::enrichment::container::read_container_id(pid)
    }

    /// Query the K8s API for the pod running this container on this node.
    async fn lookup_pod(&self, client: &Client, container_id: &str) -> Option<EnrichmentContext> {
        let pods: Api<Pod> = Api::all(client.clone());
        let lp = ListParams::default().fields(&format!("spec.nodeName={}", self.node_name));

        let start = std::time::Instant::now();
        let pod_list = match pods.list(&lp).await {
            Ok(l) => l,
            Err(e) => {
                warn!("K8s API error listing pods: {}", e);
                return None;
            }
        };
        metrics::ENRICHMENT_LATENCY.observe(start.elapsed().as_secs_f64());

        for pod in pod_list.items {
            let statuses = pod
                .status
                .as_ref()
                .and_then(|s| s.container_statuses.as_ref());

            let matched = statuses.map_or(false, |css| {
                css.iter().any(|cs| {
                    cs.container_id
                        .as_deref()
                        .map_or(false, |cid| cid.contains(container_id))
                })
            });

            if matched {
                let meta = pod.metadata;
                let name = meta.name.unwrap_or_default();
                let namespace = meta.namespace.unwrap_or_default();
                let labels = meta.labels.unwrap_or_default();

                debug!(
                    "Matched container {} → pod={} ns={}",
                    container_id, name, namespace
                );

                return Some(EnrichmentContext {
                    hostname: self.node_name.clone(),
                    container_id: container_id.to_string(),
                    container_name: name.clone(),
                    k8s_pod: name,
                    k8s_namespace: namespace,
                    k8s_node: self.node_name.clone(),
                    k8s_labels: labels.into_iter().collect(),
                });
            }
        }

        warn!(
            "No pod found on node {} for container {}",
            self.node_name, container_id
        );
        None
    }
}

#[async_trait]
impl Enricher for K8sEnricher {
    async fn enrich(&self, pid: u32) -> Option<EnrichmentContext> {
        // Check cache first
        {
            let cache = self.cache.lock().await;
            if let Some(entry) = cache.get(&pid) {
                if entry.inserted_at.elapsed() < CACHE_TTL {
                    metrics::ENRICHMENT_CACHE_HITS_TOTAL.inc();
                    return Some(entry.context.clone());
                }
            }
        }

        let container_id = match Self::container_id_for(pid) {
            Some(id) => id,
            None => {
                // PID is not in a container — bare metal postgres on this node
                return Some(EnrichmentContext {
                    hostname: self.node_name.clone(),
                    k8s_node: self.node_name.clone(),
                    ..Default::default()
                });
            }
        };

        let client = match Client::try_default().await {
            Ok(c) => c,
            Err(e) => {
                warn!("Could not create K8s client: {}", e);
                return Some(EnrichmentContext {
                    hostname: self.node_name.clone(),
                    container_id: container_id.clone(),
                    ..Default::default()
                });
            }
        };

        let ctx = self
            .lookup_pod(&client, &container_id)
            .await
            .unwrap_or_else(|| EnrichmentContext {
                hostname: self.node_name.clone(),
                container_id: container_id.clone(),
                k8s_node: self.node_name.clone(),
                ..Default::default()
            });

        // Store in cache
        {
            let mut cache = self.cache.lock().await;
            cache.insert(
                pid,
                CacheEntry {
                    context: ctx.clone(),
                    inserted_at: Instant::now(),
                },
            );
        }

        Some(ctx)
    }
}
