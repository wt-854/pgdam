use axum::{routing::get, Router};
use lazy_static::lazy_static;
use prometheus::{
    register_histogram, register_histogram_vec, register_int_counter, register_int_counter_vec,
    register_int_gauge, Encoder, Histogram, HistogramVec, IntCounter, IntCounterVec, IntGauge,
    TextEncoder,
};

lazy_static! {
    pub static ref EVENTS_PROCESSED_TOTAL: IntCounterVec = register_int_counter_vec!(
        "pgdam_events_processed_total",
        "Total events processed by the processor",
        &["event_type"]
    )
    .unwrap();
    pub static ref OPA_LATENCY: Histogram = register_histogram!(
        "pgdam_opa_latency_seconds",
        "OPA masking call latency in seconds",
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
    )
    .unwrap();
    pub static ref ENRICHMENT_LATENCY: Histogram = register_histogram!(
        "pgdam_enrichment_latency_seconds",
        "K8s API / enrichment lookup latency in seconds",
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
    )
    .unwrap();
    pub static ref ENRICHMENT_CACHE_HITS_TOTAL: IntCounter = register_int_counter!(
        "pgdam_enrichment_cache_hits_total",
        "Total enrichment cache hits (K8s API call avoided)"
    )
    .unwrap();
    pub static ref SESSION_STORE_SIZE: IntGauge = register_int_gauge!(
        "pgdam_session_store_size",
        "Current number of active sessions in the session store"
    )
    .unwrap();
    pub static ref SINK_LATENCY: HistogramVec = register_histogram_vec!(
        "pgdam_sink_latency_seconds",
        "Sink dispatch latency in seconds",
        &["sink_type", "instance"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
    )
    .unwrap();
    pub static ref KAFKA_ERRORS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "pgdam_kafka_errors_total",
        "Total Kafka produce errors",
        &["instance", "topic"]
    )
    .unwrap();
    pub static ref ELASTICSEARCH_ERRORS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "pgdam_elasticsearch_errors_total",
        "Total Elasticsearch indexing errors",
        &["instance"]
    )
    .unwrap();
}

pub fn init_metrics() {
    // Non-label metrics — touch to force registration at 0.
    ENRICHMENT_CACHE_HITS_TOTAL.reset();
    SESSION_STORE_SIZE.set(0);
    // Histograms appear only after first observation — a 0.0 observation
    // forces them into the registry immediately.
    OPA_LATENCY.observe(0.0);
    ENRICHMENT_LATENCY.observe(0.0);

    // Label vec metrics — pre-populate known event_type combinations.
    // Sink-specific label combinations (instance names, topics) are
    // pre-populated in KafkaSink::new() and ElasticSink::new() instead,
    // since only those constructors know the configured instance names.
    EVENTS_PROCESSED_TOTAL
        .with_label_values(&["user_query"])
        .reset();
    EVENTS_PROCESSED_TOTAL
        .with_label_values(&["background_worker"])
        .reset();
}

async fn metrics_handler() -> String {
    let encoder = TextEncoder::new();
    let families = prometheus::gather();
    let mut buf = Vec::new();
    encoder.encode(&families, &mut buf).unwrap_or_default();
    String::from_utf8(buf).unwrap_or_default()
}

pub async fn start_metrics_server(port: u16) {
    let app = Router::new().route("/metrics", get(metrics_handler));
    let addr = format!("0.0.0.0:{}", port);
    match tokio::net::TcpListener::bind(&addr).await {
        Ok(listener) => {
            log::info!(
                "Processor metrics server listening on http://{}/metrics",
                addr
            );
            if let Err(e) = axum::serve(listener, app).await {
                log::error!("Processor metrics server error: {}", e);
            }
        }
        Err(e) => log::error!("Failed to bind processor metrics server on {}: {}", addr, e),
    }
}
