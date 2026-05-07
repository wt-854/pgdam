use std::error::Error;
use tokio::net::UnixListener;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{BufReader, AsyncBufReadExt};
use serde::{Deserialize, Serialize};
use log::{info, error};

pub mod opa;
pub mod normalize;
pub mod sink;

use crate::sink::{Sink, StdoutSink, ElasticSink};

#[derive(Debug, Serialize, Clone, Deserialize)]
pub struct ProcessedEvent {
    pub pid: i32,
    pub timestamp: String,
    pub user: String,
    pub db: String,
    pub src_ip: String,
    pub raw_sql: String,
    pub normalized_sql: String,
    pub masked_sql: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    info!("Starting pgdam-processor...");

    // Initialize Sinks
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
            Ok((mut stream, _)) => {
                let sinks_clone = Arc::clone(&sinks);
                tokio::spawn(async move {
                    let mut reader = tokio::io::BufReader::new(stream);
                    let mut line = String::new();
                    loop {
                        line.clear();
                        match reader.read_line(&mut line).await {
                            Ok(0) => break,
                            Ok(_) => {
                                if let Err(e) = handle_payload(line.as_bytes(), &sinks_clone).await {
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

async fn handle_payload(data: &[u8], sinks: &[Box<dyn Sink>]) -> Result<(), Box<dyn Error>> {
    let event: serde_json::Value = serde_json::from_slice(data)?;
    let raw_sql = event["raw_sql"].as_str().unwrap_or("");
    let pid = event["pid"].as_i64().unwrap_or(0) as i32;
    let ts = event["timestamp"].as_u64().unwrap_or(0).to_string();
    let user = event["user"].as_str().unwrap_or("unknown").to_string();
    let db = event["db"].as_str().unwrap_or("unknown").to_string();
    let src_ip = event["src_ip"].as_str().unwrap_or("unknown").to_string();

    // 1. Normalize
    let normalized = normalize::normalize_sql(raw_sql);

    // 2. Mask via OPA
    let masked = opa::mask_sql_via_opa(raw_sql).await?;

    let processed = ProcessedEvent {
        pid,
        timestamp: ts,
        user,
        db,
        src_ip,
        raw_sql: raw_sql.to_string(),
        normalized_sql: normalized,
        masked_sql: masked,
    };

    // 3. Dispatch to all active sinks
    for sink in sinks {
        sink.send(processed.clone()).await;
    }

    Ok(())
}
