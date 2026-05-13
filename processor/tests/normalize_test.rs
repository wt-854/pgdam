use pgdam_processor::normalize::normalize_sql;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integer_literal_normalized() {
        assert_eq!(
            normalize_sql("SELECT * FROM users WHERE id = 42"),
            "SELECT * FROM users WHERE id = $1"
        );
    }

    #[test]
    fn test_string_literal_normalized() {
        assert_eq!(
            normalize_sql("SELECT * FROM users WHERE name = 'John'"),
            "SELECT * FROM users WHERE name = $1"
        );
    }

    #[test]
    fn test_multiple_literals_normalized() {
        assert_eq!(
            normalize_sql("INSERT INTO users VALUES (1, 'hello')"),
            "INSERT INTO users VALUES ($1, $2)"
        );
    }

    #[test]
    fn test_select_star_unchanged() {
        assert_eq!(normalize_sql("SELECT * FROM users"), "SELECT * FROM users");
    }

    #[test]
    fn test_begin_unchanged() {
        assert_eq!(normalize_sql("BEGIN"), "BEGIN");
    }

    #[test]
    fn test_commit_unchanged() {
        assert_eq!(normalize_sql("COMMIT"), "COMMIT");
    }

    #[test]
    fn test_rollback_unchanged() {
        assert_eq!(normalize_sql("ROLLBACK"), "ROLLBACK");
    }

    #[test]
    fn test_invalid_sql_returns_original() {
        let bad = "this is not sql @@##";
        assert_eq!(normalize_sql(bad), bad);
    }

    #[test]
    fn test_empty_string_returns_empty() {
        assert_eq!(normalize_sql(""), "");
    }

    #[test]
    fn test_update_with_literals() {
        assert_eq!(
            normalize_sql("UPDATE users SET name = 'Jane' WHERE id = 5"),
            "UPDATE users SET name = $1 WHERE id = $2"
        );
    }

    #[test]
    fn test_in_clause_normalized() {
        assert_eq!(
            normalize_sql("SELECT * FROM users WHERE id IN (1, 2, 3)"),
            "SELECT * FROM users WHERE id IN ($1, $2, $3)"
        );
    }

    #[test]
    fn test_ping_comment_unchanged() {
        assert_eq!(normalize_sql("-- ping"), "-- ping");
    }
}
