pub mod config;
pub mod enrichment;
pub mod kill;
pub mod metrics;
pub mod normalize;
pub mod opa;
pub mod session;
pub mod sink;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
    pub hostname: String,
    pub container_id: String,
    pub container_name: String,
    pub k8s_pod: String,
    pub k8s_namespace: String,
    pub k8s_node: String,
    pub k8s_labels: HashMap<String, String>,
    pub session_id: String,
    pub session_start: String,
    pub transaction_id: String,
    pub transaction_state: String,
    pub query_sequence: u64,
    pub truncated: bool,
    pub kill_triggered: bool,
}
