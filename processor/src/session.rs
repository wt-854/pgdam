use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct SessionState {
    pub session_id: String,
    pub session_start: u64,
    pub query_sequence: u64,
    pub transaction_id: Option<String>,
    pub transaction_state: TransactionState,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TransactionState {
    Autocommit,
    Open,
    Committed,
    RolledBack,
}

impl TransactionState {
    pub fn as_str(&self) -> &'static str {
        match self {
            TransactionState::Autocommit => "autocommit",
            TransactionState::Open => "open",
            TransactionState::Committed => "committed",
            TransactionState::RolledBack => "rolled_back",
        }
    }
}

pub struct QueryContext {
    pub session_id: String,
    pub session_start: u64,
    pub query_sequence: u64,
    pub transaction_id: String,
    pub transaction_state: String,
}

pub struct SessionStore {
    sessions: Arc<Mutex<HashMap<u32, SessionState>>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn len(&self) -> usize {
        self.sessions.lock().await.len()
    }

    pub async fn process(&self, pid: u32, timestamp: u64, sql: &str) -> QueryContext {
        let mut sessions = self.sessions.lock().await;

        let state = sessions.entry(pid).or_insert_with(|| SessionState {
            session_id: Uuid::new_v4().to_string(),
            session_start: timestamp,
            query_sequence: 0,
            transaction_id: None,
            transaction_state: TransactionState::Autocommit,
        });

        state.query_sequence += 1;

        let sql_upper = sql.trim().trim_end_matches(';').to_uppercase();
        let mut words = sql_upper.split_whitespace();
        let first = words.next().unwrap_or("");
        let second = words.next().unwrap_or("");
        let keyword = if first == "START" && second == "TRANSACTION" {
            "START TRANSACTION"
        } else {
            first
        };

        match keyword {
            "BEGIN" | "START" | "START TRANSACTION" => {
                if state.transaction_state != TransactionState::Open {
                    state.transaction_id = Some(Uuid::new_v4().to_string());
                    state.transaction_state = TransactionState::Open;
                }
            }
            "COMMIT" => {
                state.transaction_state = TransactionState::Committed;
            }
            "ROLLBACK" => {
                state.transaction_state = TransactionState::RolledBack;
            }
            _ => {
                if matches!(
                    state.transaction_state,
                    TransactionState::Committed | TransactionState::RolledBack
                ) {
                    state.transaction_id = None;
                    state.transaction_state = TransactionState::Autocommit;
                }
            }
        }

        QueryContext {
            session_id: state.session_id.clone(),
            session_start: state.session_start,
            query_sequence: state.query_sequence,
            transaction_id: state.transaction_id.clone().unwrap_or_default(),
            transaction_state: state.transaction_state.as_str().to_string(),
        }
    }

    pub async fn remove(&self, pid: u32) {
        self.sessions.lock().await.remove(&pid);
    }
}
