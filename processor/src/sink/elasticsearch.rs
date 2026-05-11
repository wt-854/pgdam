use crate::sink::Sink;
use crate::ProcessedEvent;
use async_trait::async_trait;
use chrono::Utc;
use log::error;
use reqwest::Client;
use serde_json::json;

pub struct ElasticSink {
    client: Client,
    name: String,
    url: String,
    user: String,
    pass: String,
}

impl ElasticSink {
    pub fn new(name: String, url: String, user: String, pass: String) -> Self {
        Self {
            client: Client::new(),
            name,
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
        let name = self.name.clone();
        let user = self.user.clone();
        let pass = self.pass.clone();
        let base_url = self.url.clone();

        let index_name = format!("pgdam-audit-{}", Utc::now().format("%Y.%m.%d"));
        let url = format!("{}/{}/_doc", base_url, index_name);

        tokio::spawn(async move {
            let res = client
                .post(&url)
                .basic_auth(&user, Some(&pass))
                .json(&json!({
                    "pid":               event.pid,
                    "timestamp":         event.timestamp,
                    "event_type":        event.event_type,
                    "user":              event.user,
                    "db":                event.db,
                    "src_ip":            event.src_ip,
                    "normalized_sql":    event.normalized_sql,
                    "masked_sql":        event.masked_sql,
                    "hostname":          event.hostname,
                    "container_id":      event.container_id,
                    "container_name":    event.container_name,
                    "k8s_pod":           event.k8s_pod,
                    "k8s_namespace":     event.k8s_namespace,
                    "k8s_node":          event.k8s_node,
                    "k8s_labels":        event.k8s_labels,
                    "session_id":        event.session_id,
                    "session_start":     event.session_start,
                    "transaction_id":    event.transaction_id,
                    "transaction_state": event.transaction_state,
                    "query_sequence":    event.query_sequence,
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
                            "[{}] Failed to sink to Elastic. Status: {}, Body: {}",
                            name, status, body
                        );
                    }
                }
                Err(e) => error!(
                    "[{}] Connection error while sinking to Elastic: {}",
                    name, e
                ),
            }
        });
    }
}
