use crate::metrics;
use log::{debug, warn};
use once_cell::sync::Lazy;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::error::Error;

static OPA_CLIENT: Lazy<Client> = Lazy::new(Client::new);

#[derive(Serialize)]
struct MaskInput {
    value: String,
    column_name: Option<String>,
}

#[derive(Serialize)]
struct MaskQuery {
    input: MaskInput,
}

#[derive(Deserialize)]
struct MaskResponse {
    result: bool,
}

/// Input shape for the kill policy.
#[derive(Serialize)]
struct KillInput {
    sql: String,
    user: String,
    db: String,
    src_ip: String,
    pid: u32,
}

#[derive(Serialize)]
struct KillQuery {
    input: KillInput,
}

#[derive(Deserialize)]
struct KillResponse {
    result: bool,
}

const OPA_MASK_URL: &str = "http://127.0.0.1:8181/v1/data/pgdam/mask/mask_field";
const OPA_KILL_URL: &str = "http://127.0.0.1:8181/v1/data/pgdam/kill/should_kill";
const OPA_MAX_RETRY: u32 = 3;
const OPA_RETRY_MS: u64 = 500;

pub async fn mask_sql_via_opa(sql: &str) -> Result<String, Box<dyn Error>> {
    let _parsed = match pg_query::parse(sql) {
        Ok(r) => r,
        Err(_) => return Ok(sql.to_string()),
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

        let query = MaskQuery {
            input: MaskInput {
                value: stripped_value.to_string(),
                column_name: None,
            },
        };

        let mut matched = false;
        for attempt in 0..OPA_MAX_RETRY {
            let opa_start = std::time::Instant::now();
            match OPA_CLIENT.post(OPA_MASK_URL).json(&query).send().await {
                Ok(resp) => {
                    metrics::OPA_LATENCY.observe(opa_start.elapsed().as_secs_f64());
                    if resp.status().is_success() {
                        if let Ok(r) = resp.json::<MaskResponse>().await {
                            matched = r.result;
                            break;
                        }
                    } else {
                        warn!(
                            "OPA mask returned error status: {}. Attempt {}/{}",
                            resp.status(),
                            attempt + 1,
                            OPA_MAX_RETRY
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to query OPA mask: {}. Attempt {}/{}",
                        e,
                        attempt + 1,
                        OPA_MAX_RETRY
                    );
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(OPA_RETRY_MS)).await;
        }

        if matched {
            debug!("OPA decided to mask value: {}", value);
            replacements.push((cap.get(0).unwrap().range(), "<REDACTED>".to_string()));
        }
    }

    // Apply replacements from back to front
    replacements.sort_by(|a, b| b.0.start.cmp(&a.0.start));
    for (range, replacement) in replacements {
        masked_sql.replace_range(range, &replacement);
    }

    Ok(masked_sql)
}

/// Ask OPA whether this query event should trigger a session kill.
/// Returns `true` if the kill policy fires.
pub async fn should_kill_via_opa(sql: &str, user: &str, db: &str, src_ip: &str, pid: u32) -> bool {
    let query = KillQuery {
        input: KillInput {
            sql: sql.to_string(),
            user: user.to_string(),
            db: db.to_string(),
            src_ip: src_ip.to_string(),
            pid,
        },
    };

    for attempt in 0..OPA_MAX_RETRY {
        match OPA_CLIENT.post(OPA_KILL_URL).json(&query).send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    match resp.json::<KillResponse>().await {
                        Ok(r) => return r.result,
                        Err(e) => warn!("Failed to parse OPA kill response: {}", e),
                    }
                } else {
                    warn!(
                        "OPA kill returned error status: {}. Attempt {}/{}",
                        resp.status(),
                        attempt + 1,
                        OPA_MAX_RETRY
                    );
                }
            }
            Err(e) => {
                warn!(
                    "Failed to query OPA kill: {}. Attempt {}/{}",
                    e,
                    attempt + 1,
                    OPA_MAX_RETRY
                );
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(OPA_RETRY_MS)).await;
    }

    // Fail open — if OPA is unreachable, do not kill.
    warn!(
        "OPA kill policy unreachable after {} attempts — failing open (no kill)",
        OPA_MAX_RETRY
    );
    false
}
