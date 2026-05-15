use crate::metrics;
use crate::sink::Sink;
use crate::ProcessedEvent;
use async_trait::async_trait;
use log::error;
use reqwest::Client;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

struct ElasticConfig {
    name: String,
    url: String,
    user: String,
    pass: String,
}

pub struct ElasticSink {
    client: Client,
    config: Arc<ElasticConfig>,
    semaphore: Arc<Semaphore>,
}

impl ElasticSink {
    pub fn new(name: String, url: String, user: String, pass: String) -> Self {
        metrics::ELASTICSEARCH_ERRORS_TOTAL
            .with_label_values(&[&name])
            .reset();

        metrics::SINK_LATENCY
            .with_label_values(&["elasticsearch", &name])
            .observe(0.0);

        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_else(|e| {
                error!("Failed to create HTTP client: {}", e);
                Client::new()
            });

        Self {
            client,
            config: Arc::new(ElasticConfig {
                name,
                url,
                user,
                pass,
            }),
            semaphore: Arc::new(Semaphore::new(64)),
        }
    }
}

#[async_trait]
impl Sink for ElasticSink {
    async fn send(&self, event: ProcessedEvent) {
        // Acquire permit BEFORE spawning. This provides backpressure to the processor loop.
        let permit = match self.semaphore.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => return, // Only happens if semaphore is explicitly closed
        };

        let client = self.client.clone();
        let config = Arc::clone(&self.config);

        let index_date = event
            .timestamp
            .parse::<i64>()
            .ok()
            .and_then(|nanos| {
                let secs = nanos / 1_000_000_000;
                let nsec_part = (nanos % 1_000_000_000) as u32;
                chrono::DateTime::from_timestamp(secs, nsec_part)
            })
            .map(|dt| dt.format("%Y.%m.%d").to_string())
            .unwrap_or_else(|| chrono::Utc::now().format("%Y.%m.%d").to_string());
        let url = format!("{}/pgdam-audit-{}/_doc", config.url, index_date);

        tokio::spawn(async move {
            let _permit: OwnedSemaphorePermit = permit;
            let start = std::time::Instant::now();

            let res = client
                .post(&url)
                .basic_auth(&config.user, Some(&config.pass))
                .json(&event)
                .send()
                .await;

            match res {
                Ok(resp) => {
                    metrics::SINK_LATENCY
                        .with_label_values(&["elasticsearch", &config.name])
                        .observe(start.elapsed().as_secs_f64());

                    if !resp.status().is_success() {
                        metrics::ELASTICSEARCH_ERRORS_TOTAL
                            .with_label_values(&[&config.name])
                            .inc();

                        let status = resp.status();
                        let body = resp.text().await.unwrap_or_default();
                        error!("[{}] Elastic error ({}): {}", config.name, status, body);
                    }
                }
                Err(e) => {
                    metrics::ELASTICSEARCH_ERRORS_TOTAL
                        .with_label_values(&[&config.name])
                        .inc();
                    error!("[{}] Request failed for {}: {}", config.name, config.url, e);
                }
            }
        });
    }
}
