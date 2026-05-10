use log::{debug, warn};
use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Serialize)]
struct OpaInput {
    value: String,
    column_name: Option<String>,
}

#[derive(Serialize)]
struct OpaQuery {
    input: OpaInput,
}

#[derive(Deserialize)]
struct OpaResponse {
    result: bool,
}

pub async fn mask_sql_via_opa(sql: &str) -> Result<String, Box<dyn Error>> {
    let client = reqwest::Client::new();
    let opa_url = "http://127.0.0.1:8181/v1/data/pgdam/masking/mask_field";

    // 1. Parse SQL to identify literals
    // Using pg_query to evaluate if the SQL is valid
    let _parsed = match pg_query::parse(sql) {
        Ok(r) => r,
        Err(_) => return Ok(sql.to_string()), // Fallback
    };

    let mut masked_sql = sql.to_string();

    // The protobuf representation of the AST allows us to find literals.
    // However, finding the exact byte offset for replacement in the raw string
    // is easier if we use the AST locations.

    // For MVP, let's use a simpler approach: Extract all string literals using regex
    // or just pass the whole query to OPA if OPA can identify the sensitive parts.
    // The user said "one policy for credit_card number".

    // Let's do a high-fidelity approach:
    // OPA can't easily "redact" a string; it typically returns a decision.
    // So we will:
    // 1. Extract potential sensitive strings (simple regex for now or AST walk).
    // 2. Ask OPA for each.
    // 3. Replace in masked_sql.

    // Let's use a simple regex to find sequences of 13-16 digits OR quoted strings.
    let re = regex::Regex::new(r"'(.*?)'|\b\d{13,16}\b").unwrap();

    // Use a reverse replacement strategy to keep offsets valid
    let mut replacements = Vec::new();

    for cap in re.captures_iter(sql) {
        let value = cap.get(0).unwrap().as_str();
        let stripped_value = value.trim_matches('\'');

        let query = OpaQuery {
            input: OpaInput {
                value: stripped_value.to_string(),
                column_name: None,
            },
        };

        let mut opa_res_matched = false;
        for attempt in 0..3 {
            match client.post(opa_url).json(&query).send().await {
                Ok(resp) => {
                    if resp.status().is_success() {
                        if let Ok(opa_res) = resp.json::<OpaResponse>().await {
                            opa_res_matched = opa_res.result;
                            break;
                        }
                    } else {
                        warn!(
                            "OPA returned error status: {}. Attempt {}/3",
                            resp.status(),
                            attempt + 1
                        );
                    }
                }
                Err(e) => {
                    warn!("Failed to query OPA: {}. Attempt {}/3", e, attempt + 1);
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }

        if opa_res_matched {
            debug!("OPA decided to mask value: {}", value);
            let range = cap.get(0).unwrap().range();
            replacements.push((range, "<REDACTED>".to_string()));
        }
    }

    // Apply replacements from back to front
    replacements.sort_by(|a, b| b.0.start.cmp(&a.0.start));
    for (range, replacement) in replacements {
        masked_sql.replace_range(range, &replacement);
    }

    Ok(masked_sql)
}
