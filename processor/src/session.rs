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

#[cfg(test)]
mod tests {
    use super::*;

    async fn make_store() -> SessionStore {
        SessionStore::new()
    }

    #[tokio::test]
    async fn test_autocommit_query() {
        let store = make_store().await;
        let ctx = store.process(1, 1000, "SELECT 1").await;

        assert_eq!(ctx.transaction_state, "autocommit");
        assert_eq!(ctx.transaction_id, "");
        assert_eq!(ctx.query_sequence, 1);
    }

    #[tokio::test]
    async fn test_begin_commit() {
        let store = make_store().await;

        let ctx1 = store.process(1, 1000, "BEGIN").await;
        assert_eq!(ctx1.transaction_state, "open");
        assert!(!ctx1.transaction_id.is_empty());

        let txn_id = ctx1.transaction_id.clone();

        let ctx2 = store.process(1, 1001, "INSERT INTO t VALUES (1)").await;
        assert_eq!(ctx2.transaction_state, "open");
        assert_eq!(ctx2.transaction_id, txn_id);
        assert_eq!(ctx2.query_sequence, 2);

        let ctx3 = store.process(1, 1002, "COMMIT").await;
        assert_eq!(ctx3.transaction_state, "committed");
        assert_eq!(ctx3.transaction_id, txn_id);
        assert_eq!(ctx3.query_sequence, 3);
    }

    #[tokio::test]
    async fn test_begin_rollback() {
        let store = make_store().await;

        let ctx1 = store.process(1, 1000, "BEGIN").await;
        assert_eq!(ctx1.transaction_state, "open");
        let txn_id = ctx1.transaction_id.clone();

        let ctx2 = store.process(1, 1001, "INSERT INTO t VALUES (1)").await;
        assert_eq!(ctx2.transaction_id, txn_id);

        let ctx3 = store.process(1, 1002, "ROLLBACK").await;
        assert_eq!(ctx3.transaction_state, "rolled_back");
        assert_eq!(ctx3.transaction_id, txn_id);
    }

    #[tokio::test]
    async fn test_after_commit_resets_to_autocommit() {
        let store = make_store().await;

        store.process(1, 1000, "BEGIN").await;
        store.process(1, 1001, "SELECT 1").await;
        store.process(1, 1002, "COMMIT").await;

        let ctx = store.process(1, 1003, "SELECT 2").await;
        assert_eq!(ctx.transaction_state, "autocommit");
        assert_eq!(ctx.transaction_id, "");
    }

    #[tokio::test]
    async fn test_after_rollback_resets_to_autocommit() {
        let store = make_store().await;

        store.process(1, 1000, "BEGIN").await;
        store.process(1, 1001, "SELECT 1").await;
        store.process(1, 1002, "ROLLBACK").await;

        let ctx = store.process(1, 1003, "SELECT 2").await;
        assert_eq!(ctx.transaction_state, "autocommit");
        assert_eq!(ctx.transaction_id, "");
    }

    #[tokio::test]
    async fn test_nested_begin_ignored() {
        let store = make_store().await;

        let ctx1 = store.process(1, 1000, "BEGIN").await;
        let txn_id = ctx1.transaction_id.clone();

        // Second BEGIN inside open transaction must not create a new transaction_id
        let ctx2 = store.process(1, 1001, "BEGIN").await;
        assert_eq!(ctx2.transaction_id, txn_id);
        assert_eq!(ctx2.transaction_state, "open");
    }

    #[tokio::test]
    async fn test_begin_with_semicolon() {
        let store = make_store().await;
        let ctx = store.process(1, 1000, "BEGIN;").await;
        assert_eq!(ctx.transaction_state, "open");
        assert!(!ctx.transaction_id.is_empty());
    }

    #[tokio::test]
    async fn test_commit_with_semicolon() {
        let store = make_store().await;
        store.process(1, 1000, "BEGIN;").await;
        let ctx = store.process(1, 1001, "COMMIT;").await;
        assert_eq!(ctx.transaction_state, "committed");
    }

    #[tokio::test]
    async fn test_session_id_stable_across_queries() {
        let store = make_store().await;

        let ctx1 = store.process(1, 1000, "SELECT 1").await;
        let ctx2 = store.process(1, 1001, "SELECT 2").await;
        let ctx3 = store.process(1, 1002, "SELECT 3").await;

        assert_eq!(ctx1.session_id, ctx2.session_id);
        assert_eq!(ctx2.session_id, ctx3.session_id);
    }

    #[tokio::test]
    async fn test_different_pids_different_sessions() {
        let store = make_store().await;

        let ctx1 = store.process(1, 1000, "SELECT 1").await;
        let ctx2 = store.process(2, 1000, "SELECT 1").await;

        assert_ne!(ctx1.session_id, ctx2.session_id);
        assert_eq!(ctx1.query_sequence, 1);
        assert_eq!(ctx2.query_sequence, 1);
    }

    #[tokio::test]
    async fn test_query_sequence_increments() {
        let store = make_store().await;

        for i in 1..=5 {
            let ctx = store.process(1, i as u64 * 1000, "SELECT 1").await;
            assert_eq!(ctx.query_sequence, i);
        }
    }

    #[tokio::test]
    async fn test_session_start_is_first_query_timestamp() {
        let store = make_store().await;

        let ctx1 = store.process(1, 5000, "SELECT 1").await;
        let ctx2 = store.process(1, 6000, "SELECT 2").await;

        assert_eq!(ctx1.session_start, 5000);
        assert_eq!(ctx2.session_start, 5000); // unchanged
    }

    #[tokio::test]
    async fn test_remove_clears_session() {
        let store = make_store().await;

        store.process(1, 1000, "SELECT 1").await;
        assert_eq!(store.len().await, 1);

        store.remove(1).await;
        assert_eq!(store.len().await, 0);
    }

    #[tokio::test]
    async fn test_start_transaction_keyword() {
        let store = make_store().await;
        let ctx = store.process(1, 1000, "START TRANSACTION").await;
        assert_eq!(ctx.transaction_state, "open");
        assert!(!ctx.transaction_id.is_empty());
    }
}
