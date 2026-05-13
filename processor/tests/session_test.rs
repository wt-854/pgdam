use pgdam_processor::session::SessionStore;

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
