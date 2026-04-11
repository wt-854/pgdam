pub fn normalize_sql(sql: &str) -> String {
    match pg_query::normalize(sql) {
        Ok(normalized) => normalized,
        Err(_) => {
            // If parsing fails (e.g., partial SQL or invalid syntax), return raw as fallback
            sql.to_string()
        }
    }
}
