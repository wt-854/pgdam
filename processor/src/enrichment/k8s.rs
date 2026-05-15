use super::{Enricher, EnrichmentContext};
use crate::metrics;
use async_trait::async_trait;
use futures::StreamExt;
use k8s_openapi::api::core::v1::Pod;
use kube::{
    runtime::{reflector, watcher, WatchStreamExt},
    Api, Client,
};
use log::{debug, info, warn};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

// How long a resolved PID → context mapping is trusted before we re-scan.
// Even with the reflector the pod state is always current, but re-scanning
// for every query from a long-lived connection is unnecessary work.
const CACHE_TTL: Duration = Duration::from_secs(300); // 5 minutes

// How long we wait for the reflector's initial LIST to populate the store
// before giving up and allowing lookups to proceed (they will just miss
// until the store is ready, which is handled gracefully).
const REFLECTOR_READY_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
struct CacheEntry {
    context: EnrichmentContext,
    inserted_at: Instant,
}

pub struct K8sEnricher {
    node_name: String,
    /// In-memory pod store kept current by a background watcher goroutine.
    /// Lookups scan this store — O(n_pods_on_node) over local memory, no
    /// API server round-trip per miss.
    pod_store: reflector::Store<Pod>,
    /// PID → resolved context.  Avoids re-scanning the store for every
    /// query issued by a long-lived Postgres backend.
    cache: Arc<Mutex<HashMap<u32, CacheEntry>>>,
}

impl K8sEnricher {
    /// Initialise the enricher.
    ///
    /// This method:
    /// 1. Builds a Kubernetes client from the in-cluster service account.
    /// 2. Creates a reflector that watches pods on `node_name` and keeps
    ///    `pod_store` up-to-date via a single long-lived Watch connection.
    /// 3. Spawns the reflector as a background task (auto-reconnects on error).
    /// 4. Waits up to `REFLECTOR_READY_TIMEOUT` for the initial LIST to land
    ///    so that the first enrichment call has a populated store.
    pub async fn new(node_name: String) -> Result<Self, kube::Error> {
        let client = Client::try_default().await?;
        let pods: Api<Pod> = Api::all(client);

        let (reader, writer) = reflector::store::<Pod>();

        // Field selector: only pods scheduled on this node.
        let watcher_config =
            watcher::Config::default().fields(&format!("spec.nodeName={}", node_name));

        // The reflector wraps the watcher stream and writes every applied/deleted
        // event into `writer`, which updates `reader` atomically.
        let reflector_stream = reflector(writer, watcher(pods, watcher_config));

        // Drive the stream in a background task.  The stream never returns
        // Ok(None) — it reconnects internally on transient errors.  Log
        // hard failures but keep the task alive so that the store stays
        // populated after a temporary API-server blip.
        let bg_node = node_name.clone();
        tokio::spawn(async move {
            // `applied_objects()` discards Bookmark/Delete events and yields
            // only Pod objects that were added or modified — we only need to
            // keep the stream alive here, not inspect individual events.
            reflector_stream
                .applied_objects()
                .for_each(|result| {
                    if let Err(e) = result {
                        warn!(
                            "K8s reflector error for node {}: {} — will reconnect",
                            bg_node, e
                        );
                    }
                    std::future::ready(())
                })
                .await;
            // If we reach here the stream ended, which should not happen.
            warn!(
                "K8s reflector stream for node {} ended unexpectedly.",
                bg_node
            );
        });

        // Wait for the initial LIST to populate the store so the first batch
        // of enrichment calls isn't a guaranteed miss.
        let wait_start = Instant::now();
        loop {
            if !reader.state().is_empty() {
                info!(
                    "K8s reflector ready: {} pod(s) on node {} (waited {:.1}s)",
                    reader.state().len(),
                    node_name,
                    wait_start.elapsed().as_secs_f64()
                );
                break;
            }
            if wait_start.elapsed() >= REFLECTOR_READY_TIMEOUT {
                warn!(
                    "K8s reflector not yet ready after {:.0}s — proceeding anyway; \
                     enrichment will populate as pods become visible.",
                    REFLECTOR_READY_TIMEOUT.as_secs_f64()
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        Ok(Self {
            node_name,
            pod_store: reader,
            cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn container_id_for(pid: u32) -> Option<String> {
        crate::enrichment::container::read_container_id(pid)
    }

    /// Scan the in-memory pod store for the pod that owns `container_id`.
    ///
    /// This is an O(n_pods_on_node) walk over a `Vec<Arc<Pod>>` held
    /// entirely in process memory — no network I/O, no API server load.
    /// The reflector background task keeps the store current via a single
    /// Watch stream.
    fn scan_store(&self, container_id: &str) -> Option<EnrichmentContext> {
        let start = Instant::now();
        let pods = self.pod_store.state();
        metrics::ENRICHMENT_LATENCY.observe(start.elapsed().as_secs_f64());

        for pod in pods {
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
                let meta = &pod.metadata;
                let name = meta.name.clone().unwrap_or_default();
                let namespace = meta.namespace.clone().unwrap_or_default();
                let labels: HashMap<String, String> = meta
                    .labels
                    .clone()
                    .unwrap_or_default()
                    .into_iter()
                    .collect();

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
                    k8s_labels: labels,
                });
            }
        }

        warn!(
            "No pod found in reflector store for container {} on node {} \
             (store has {} pods — may still be populating)",
            container_id,
            self.node_name,
            self.pod_store.state().len()
        );
        None
    }
}

#[async_trait]
impl Enricher for K8sEnricher {
    async fn enrich(&self, pid: u32) -> Option<EnrichmentContext> {
        // Fast path: PID is already resolved and cache entry is fresh.
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
                // PID is not inside a container — bare-metal Postgres on this node.
                return Some(EnrichmentContext {
                    hostname: self.node_name.clone(),
                    k8s_node: self.node_name.clone(),
                    ..Default::default()
                });
            }
        };

        // Scan the reflector store — in-memory, no API call.
        let ctx = self
            .scan_store(&container_id)
            .unwrap_or_else(|| EnrichmentContext {
                hostname: self.node_name.clone(),
                container_id: container_id.clone(),
                k8s_node: self.node_name.clone(),
                ..Default::default()
            });

        // Populate cache for subsequent queries from this PID.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that a cache TTL of exactly 5 minutes is configured.
    /// If you change CACHE_TTL intentionally, update this test too.
    #[test]
    fn test_cache_ttl_is_five_minutes() {
        assert_eq!(CACHE_TTL, Duration::from_secs(300));
    }

    /// Verify that the reflector ready-wait timeout is bounded.
    #[test]
    fn test_reflector_ready_timeout_is_bounded() {
        assert!(
            REFLECTOR_READY_TIMEOUT <= Duration::from_secs(30),
            "REFLECTOR_READY_TIMEOUT is too long — it blocks processor startup"
        );
    }

    /// Verify that container_id_for returns None for a clearly invalid PID.
    #[test]
    fn test_container_id_for_invalid_pid() {
        // PID u32::MAX will never exist; should return None without panicking.
        let result = K8sEnricher::container_id_for(u32::MAX);
        assert!(result.is_none());
    }
}
