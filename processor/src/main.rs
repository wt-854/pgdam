use log::{error, info, warn};
use pgdam_processor::config::{Config, KillMode};
use pgdam_processor::enrichment::{detect_enricher, Enricher};
use pgdam_processor::kill::terminate_session;
use pgdam_processor::opa::{mask_sql_via_opa, should_kill_via_opa};
use pgdam_processor::session::SessionStore;
use pgdam_processor::sink::{ElasticSink, KafkaSink, Sink, StdoutSink};
use pgdam_processor::{metrics, normalize, ProcessedEvent};
use std::error::Error;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixListener;

const METRICS_PORT: u16 = 9091;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    info!("Starting pgdam-processor...");

    // Start metrics server in background.
    tokio::spawn(metrics::start_metrics_server(METRICS_PORT));
    metrics::init_metrics();

    // ── Load config ───────────────────────────────────────────────────────────
    let config_path =
        std::env::var("PGDAM_CONFIG").unwrap_or_else(|_| "/etc/pgdam/config.yaml".to_string());
    let config = Config::load(&config_path)?;
    info!("Loaded config from {}", config_path);
    info!(
        "Kill mode: {}",
        match config.kill_mode {
            KillMode::Disabled => "disabled",
            KillMode::Manual => "manual",
            KillMode::Auto => "auto",
        }
    );

    // ── Initialize sinks ──────────────────────────────────────────────────────
    let mut sinks: Vec<Box<dyn Sink>> = vec![Box::new(StdoutSink)];

    if let Some(es_config) = &config.sinks.elasticsearch {
        if es_config.enabled {
            for instance in &es_config.instances {
                if !instance.enabled {
                    info!(
                        "Elasticsearch instance '{}' is disabled — skipping",
                        instance.name
                    );
                    continue;
                }
                let user = instance.resolve_username();
                let pass = instance.resolve_password();
                info!(
                    "Elasticsearch sink enabled: {} ({})",
                    instance.name, instance.url
                );
                sinks.push(Box::new(ElasticSink::new(
                    instance.name.clone(),
                    instance.url.clone(),
                    user,
                    pass,
                )));
            }
        } else {
            info!("Elasticsearch sink disabled");
        }
    }

    if let Some(kafka_config) = &config.sinks.kafka {
        if kafka_config.enabled {
            for instance in &kafka_config.instances {
                if !instance.enabled {
                    info!("Kafka instance '{}' is disabled — skipping", instance.name);
                    continue;
                }
                match KafkaSink::new(instance) {
                    Ok(sink) => {
                        info!("Kafka sink enabled: {}", instance.name);
                        sinks.push(Box::new(sink));
                    }
                    Err(e) => error!("Failed to create Kafka sink '{}': {}", instance.name, e),
                }
            }
        } else {
            info!("Kafka sink disabled");
        }
    }

    let sinks: Arc<Vec<Box<dyn Sink>>> = Arc::new(sinks);
    let enricher: Arc<dyn Enricher> = Arc::from(detect_enricher().await);
    let session_store: Arc<SessionStore> = Arc::new(SessionStore::new());
    let kill_mode: Arc<KillMode> = Arc::new(config.kill_mode);

    // Periodically update session store size metric.
    let session_store_for_metrics = Arc::clone(&session_store);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let size = session_store_for_metrics.len().await;
            metrics::SESSION_STORE_SIZE.set(size as i64);
        }
    });

    // ── Unix socket ───────────────────────────────────────────────────────────
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
                let session_store_clone = Arc::clone(&session_store);
                let kill_mode_clone = Arc::clone(&kill_mode);
                tokio::spawn(async move {
                    let mut reader = BufReader::new(stream);
                    let mut line = String::new();
                    loop {
                        line.clear();
                        match reader.read_line(&mut line).await {
                            Ok(0) => break,
                            Ok(_) => {
                                if let Err(e) = handle_payload(
                                    line.as_bytes(),
                                    &sinks_clone,
                                    enricher_clone.as_ref(),
                                    &session_store_clone,
                                    &kill_mode_clone,
                                )
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
    enricher: &dyn Enricher,
    session_store: &SessionStore,
    kill_mode: &KillMode,
) -> Result<(), Box<dyn Error>> {
    let event: serde_json::Value = serde_json::from_slice(data)?;

    let raw_sql = event["raw_sql"].as_str().unwrap_or("");
    let pid = event["pid"].as_i64().unwrap_or(0) as i32;
    let ts = event["timestamp"].as_u64().unwrap_or(0);
    let user = event["user"].as_str().unwrap_or("").to_string();
    let db = event["db"].as_str().unwrap_or("").to_string();
    let src_ip = event["src_ip"].as_str().unwrap_or("").to_string();
    let truncated = event["truncated"].as_bool().unwrap_or(false);
    let event_type = event["event_type"]
        .as_str()
        .unwrap_or("user_query")
        .to_string();

    // pid_exit — clean up session state and return, nothing else to do.
    if event_type == "pid_exit" {
        session_store.remove(pid as u32).await;
        return Ok(());
    }

    if event_type == "incomplete" {
        return Ok(());
    }

    metrics::EVENTS_PROCESSED_TOTAL
        .with_label_values(&[&event_type])
        .inc();

    // 1. Enrich
    let enrich_start = std::time::Instant::now();
    let enrichment = enricher.enrich(pid as u32).await.unwrap_or_default();
    metrics::ENRICHMENT_LATENCY.observe(enrich_start.elapsed().as_secs_f64());

    // 2. Session and transaction tracking
    let query_ctx = session_store.process(pid as u32, ts, raw_sql).await;

    // 3. Normalize
    let normalized = normalize::normalize_sql(raw_sql);

    // 4. Kill policy — only evaluated for user queries, not background workers
    let mut kill_triggered = false;
    if event_type == "user_query" && !matches!(kill_mode, KillMode::Disabled) {
        let should_kill = should_kill_via_opa(raw_sql, &user, &db, &src_ip, pid as u32).await;

        if should_kill {
            match kill_mode {
                KillMode::Auto => {
                    warn!(
                        "Kill-switch AUTO: terminating PID {} (user={} db={} src={}) sql=\"{}\"",
                        pid,
                        user,
                        db,
                        src_ip,
                        raw_sql.trim()
                    );
                    kill_triggered = terminate_session(pid as u32);
                }
                KillMode::Manual => {
                    warn!(
                        "Kill-switch MANUAL: PID {} flagged for termination \
                         (user={} db={} src={}) sql=\"{}\" — awaiting manual action",
                        pid,
                        user,
                        db,
                        src_ip,
                        raw_sql.trim()
                    );
                    // In manual mode we set kill_triggered so the event is
                    // visible in audit logs and dashboards, but do not act.
                    kill_triggered = true;
                }
                KillMode::Disabled => {}
            }
        }
    }

    // 5. Mask via OPA — skip for background workers
    let masked = if event_type == "background_worker" {
        raw_sql.to_string()
    } else {
        let opa_start = std::time::Instant::now();
        let result = mask_sql_via_opa(raw_sql).await?;
        metrics::OPA_LATENCY.observe(opa_start.elapsed().as_secs_f64());
        result
    };

    let processed = ProcessedEvent {
        pid,
        timestamp: ts.to_string(),
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
        session_id: query_ctx.session_id,
        session_start: query_ctx.session_start.to_string(),
        transaction_id: query_ctx.transaction_id,
        transaction_state: query_ctx.transaction_state,
        query_sequence: query_ctx.query_sequence,
        truncated,
        kill_triggered,
    };

    for sink in sinks {
        sink.send(processed.clone()).await;
    }

    Ok(())
}
