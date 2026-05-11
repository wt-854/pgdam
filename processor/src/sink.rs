use crate::ProcessedEvent;
use async_trait::async_trait;
use chrono::Utc;
use log::error;
use reqwest::Client;
use serde_json::json;

#[async_trait]
pub trait Sink: Send + Sync {
    async fn send(&self, event: ProcessedEvent);
}

pub struct StdoutSink;

#[async_trait]
impl Sink for StdoutSink {
    async fn send(&self, event: ProcessedEvent) {
        if let Ok(json) = serde_json::to_string(&event) {
            println!("{}", json);
        }
    }
}

pub struct ElasticSink {
    client: Client,
    url: String,
    user: String,
    pass: String,
}

impl ElasticSink {
    pub fn new(url: String, user: String, pass: String) -> Self {
        Self {
            client: Client::new(),
            url,
            user,
            pass,
        }
    }
}

#[async_trait]
impl Sink for ElasticSink {
    async fn send(&self, event: ProcessedEvent) {
        let client = self.client.clone();
        let user = self.user.clone();
        let pass = self.pass.clone();
        let base_url = self.url.clone();

        // Dynamic index based on timestamp
        let index_name = format!("pgdam-audit-{}", Utc::now().format("%Y.%m.%d"));
        let url = format!("{}/{}/_doc", base_url, index_name);

        // Fire and forget: spawn a task to avoid blocking the main processing loop
        tokio::spawn(async move {
            let res = client
                .post(url)
                .basic_auth(user, Some(pass))
                .json(&json!({
                    "pid": event.pid,
                    "timestamp": event.timestamp,
                    "user": event.user,
                    "db": event.db,
                    "src_ip": event.src_ip,
                    "normalized_sql": event.normalized_sql
                }))
                .send()
                .await;

            match res {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        let status = resp.status();
                        let body = resp
                            .text()
                            .await
                            .unwrap_or_else(|_| "unreadable body".to_string());
                        error!(
                            "Failed to sink to Elastic. Status: {}, Body: {}",
                            status, body
                        );
                    }
                }
                Err(e) => {
                    error!("Connection error while sinking to Elastic: {}", e);
                }
            }
        });
    }
}
