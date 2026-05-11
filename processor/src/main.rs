use log::{error, info};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixListener;

pub mod enrichment;
pub mod normalize;
pub mod opa;
pub mod sink;

use crate::enrichment::{detect_enricher, Enricher};
use crate::sink::{ElasticSink, Sink, StdoutSink};

#[derive(Debug, Serialize, Clone, Deserialize)]
pub struct ProcessedEvent {
    pub pid: i32,
    pub timestamp: String,
    pub event_type: String,
    pub user: String,
    pub db: String,
    pub src_ip: String,
    pub raw_sql: String,
    pub normalized_sql: String,
    pub masked_sql: String,
    // enrichment fields
    pub hostname: String,
    pub container_id: String,
    pub container_name: String,
    pub k8s_pod: String,
    pub k8s_namespace: String,
    pub k8s_node: String,
    pub k8s_labels: HashMap<String, String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    info!("Starting pgdam-processor...");

    let enricher: Arc<Box<dyn Enricher>> = Arc::new(detect_enricher());

    let mut sinks: Vec<Box<dyn Sink>> = vec![Box::new(StdoutSink)];

    if let (Ok(url), Ok(user), Ok(pass)) = (
        std::env::var("ELASTIC_URL"),
        std::env::var("ELASTIC_USER"),
        std::env::var("ELASTIC_PASS"),
    ) {
        info!("Elasticsearch sink enabled: {}", url);
        sinks.push(Box::new(ElasticSink::new(url, user, pass)));
    } else {
        info!("Elasticsearch sink disabled (missing configuration)");
    }

    let sinks = Arc::new(sinks);

    let socket_path = "/tmp/pgdam.sock";
    if Path::new(socket_path).exists() {
        std::fs::remove_file(socket_path)?;
    }

    let listener = UnixListener::bind(socket_path)?;
    info!("Listening on Unix Domain Socket: {}", socket_path);

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let sinks_clone = Arc::clone(&sinks);
                let enricher_clone = Arc::clone(&enricher);
                tokio::spawn(async move {
                    let mut reader = BufReader::new(stream);
                    let mut line = String::new();
                    loop {
                        line.clear();
                        match reader.read_line(&mut line).await {
                            Ok(0) => break,
                            Ok(_) => {
                                if let Err(e) =
                                    handle_payload(line.as_bytes(), &sinks_clone, &enricher_clone)
                                        .await
                                {
                                    error!("Error handling payload: {}", e);
                                }
                            }
                            Err(e) => {
                                error!("Failed to read from socket: {}", e);
                                break;
                            }
                        }
                    }
                });
            }
            Err(e) => error!("Failed to accept connection: {}", e),
        }
    }
}

async fn handle_payload(
    data: &[u8],
    sinks: &[Box<dyn Sink>],
    enricher: &Box<dyn Enricher>,
) -> Result<(), Box<dyn Error>> {
    let event: serde_json::Value = serde_json::from_slice(data)?;

    let raw_sql = event["raw_sql"].as_str().unwrap_or("");
    let pid = event["pid"].as_i64().unwrap_or(0) as i32;
    let ts = event["timestamp"].as_u64().unwrap_or(0).to_string();
    let user = event["user"].as_str().unwrap_or("").to_string();
    let db = event["db"].as_str().unwrap_or("").to_string();
    let src_ip = event["src_ip"].as_str().unwrap_or("").to_string();
    let event_type = event["event_type"]
        .as_str()
        .unwrap_or("user_query")
        .to_string();

    if event_type == "incomplete" {
        return Ok(());
    }

    // 1. Enrich with environment metadata
    let enrichment = enricher.enrich(pid as u32).await.unwrap_or_default();

    // 2. Normalize
    let normalized = normalize::normalize_sql(raw_sql);

    // 3. Mask via OPA — skip for background workers
    let masked = if event_type == "background_worker" {
        raw_sql.to_string()
    } else {
        opa::mask_sql_via_opa(raw_sql).await?
    };

    let processed = ProcessedEvent {
        pid,
        timestamp: ts,
        event_type,
        user,
        db,
        src_ip,
        raw_sql: raw_sql.to_string(),
        normalized_sql: normalized,
        masked_sql: masked,
        hostname: enrichment.hostname,
        container_id: enrichment.container_id,
        container_name: enrichment.container_name,
        k8s_pod: enrichment.k8s_pod,
        k8s_namespace: enrichment.k8s_namespace,
        k8s_node: enrichment.k8s_node,
        k8s_labels: enrichment.k8s_labels,
    };

    // 4. Dispatch to all active sinks
    for sink in sinks {
        sink.send(processed.clone()).await;
    }

    Ok(())
}
