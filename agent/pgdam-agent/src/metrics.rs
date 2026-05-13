use axum::{routing::get, Router};
use lazy_static::lazy_static;
use prometheus::{
    register_int_counter, register_int_gauge, Encoder, IntCounter, IntGauge, TextEncoder,
};

lazy_static! {
    pub static ref EVENTS_CAPTURED_TOTAL: IntCounter = register_int_counter!(
        "pgdam_events_captured_total",
        "Total SQL events captured from the eBPF ring buffer"
    )
    .unwrap();
    pub static ref EVENTS_DROPPED_TOTAL: IntCounter = register_int_counter!(
        "pgdam_events_dropped_total",
        "Total events dropped due to ring buffer overflow"
    )
    .unwrap();
    pub static ref INCOMPLETE_EVENTS_TOTAL: IntCounter = register_int_counter!(
        "pgdam_incomplete_events_total",
        "Total events emitted before PID was registered (PID_INFO race)"
    )
    .unwrap();
    pub static ref BG_WORKER_EVENTS_TOTAL: IntCounter = register_int_counter!(
        "pgdam_background_worker_events_total",
        "Total background worker events captured"
    )
    .unwrap();
    pub static ref TRUNCATED_EVENTS_TOTAL: IntCounter = register_int_counter!(
        "pgdam_truncated_events_total",
        "Total events where SQL was truncated due to payload buffer limit"
    )
    .unwrap();
    pub static ref PID_EXIT_EVENTS_TOTAL: IntCounter = register_int_counter!(
        "pgdam_pid_exit_events_total",
        "Total pid_exit events sent to processor for session cleanup"
    )
    .unwrap();
    pub static ref PID_MAP_SIZE: IntGauge = register_int_gauge!(
        "pgdam_pid_map_size",
        "Current number of PIDs registered in PID_INFO"
    )
    .unwrap();
    pub static ref BINARY_COUNT: IntGauge = register_int_gauge!(
        "pgdam_binary_count",
        "Number of unique postgres binaries with active uprobes"
    )
    .unwrap();
}

pub fn init_metrics() {
    EVENTS_CAPTURED_TOTAL.reset();
    EVENTS_DROPPED_TOTAL.reset();
    INCOMPLETE_EVENTS_TOTAL.reset();
    BG_WORKER_EVENTS_TOTAL.reset();
    TRUNCATED_EVENTS_TOTAL.reset();
    PID_EXIT_EVENTS_TOTAL.reset();
    PID_MAP_SIZE.set(0);
    BINARY_COUNT.set(0);
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
            log::info!("Agent metrics server listening on http://{}/metrics", addr);
            if let Err(e) = axum::serve(listener, app).await {
                log::error!("Agent metrics server error: {}", e);
            }
        }
        Err(e) => log::error!("Failed to bind agent metrics server on {}: {}", addr, e),
    }
}
