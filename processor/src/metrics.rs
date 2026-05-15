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
        "K8s pod store scan latency in seconds (in-memory; sub-millisecond expected)",
        vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25]
    )
    .unwrap();
    pub static ref ENRICHMENT_CACHE_HITS_TOTAL: IntCounter = register_int_counter!(
        "pgdam_enrichment_cache_hits_total",
        "Total enrichment cache hits (pod store scan avoided)"
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
    pub static ref INCOMPLETE_EVENTS_DROPPED_TOTAL: IntCounter = register_int_counter!(
        "pgdam_incomplete_events_dropped_total",
        "Total incomplete events (FLAG_NO_PORT_INFO) discarded by the processor"
    )
    .unwrap();
}

pub fn init_metrics() {
    // Touch all non-label counters so they appear in /metrics at 0 immediately
    // rather than only after the first increment.
    ENRICHMENT_CACHE_HITS_TOTAL.reset();
    INCOMPLETE_EVENTS_DROPPED_TOTAL.reset();
    SESSION_STORE_SIZE.set(0);

    // Histograms only appear after their first observation.  A 0.0 seed
    // forces them into the Prometheus registry at startup.
    OPA_LATENCY.observe(0.0);
    ENRICHMENT_LATENCY.observe(0.0);

    // Pre-populate known label combinations for vector counters so that
    // dashboards don't show missing series on a fresh deployment.
    EVENTS_PROCESSED_TOTAL
        .with_label_values(&["user_query"])
        .reset();
    EVENTS_PROCESSED_TOTAL
        .with_label_values(&["background_worker"])
        .reset();
    EVENTS_PROCESSED_TOTAL
        .with_label_values(&["incomplete"])
        .reset();
    EVENTS_PROCESSED_TOTAL
        .with_label_values(&["pid_exit"])
        .reset();
    // Sink-specific label combinations (instance names, topics) are
    // pre-populated in KafkaSink::new() and ElasticSink::new() because only
    // those constructors know the configured instance names.
}

async fn metrics_handler() -> String {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

pub async fn start_metrics_server(port: u16) {
    let app = Router::new().route("/metrics", get(metrics_handler));
    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    log::info!("Processor metrics server listening on {}", addr);
    axum::serve(listener, app).await.unwrap();
}
