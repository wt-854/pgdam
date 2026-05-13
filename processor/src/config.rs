use log::warn;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum KillMode {
    /// Kill decisions are never acted on. Safe default.
    Disabled,
    /// OPA flags the query; the kill is logged as recommended but not executed.
    /// Useful for tuning policies before enabling auto.
    Manual,
    /// OPA flags the query; the session is terminated immediately.
    Auto,
}

impl Default for KillMode {
    fn default() -> Self {
        KillMode::Disabled
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub sinks: SinksConfig,
    #[serde(default)]
    pub kill_mode: KillMode,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SinksConfig {
    pub elasticsearch: Option<ElasticsearchConfig>,
    pub kafka: Option<KafkaConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ElasticsearchConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub instances: Vec<ElasticsearchInstance>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ElasticsearchInstance {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub url: String,
    pub credentials: Option<ElasticsearchCredentials>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ElasticsearchCredentials {
    pub username_env: String,
    pub password_env: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct KafkaConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub instances: Vec<KafkaInstance>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct KafkaInstance {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub brokers: Vec<String>,
    pub auth: KafkaAuth,
    /// event_type → list of topics to publish to
    pub topics: HashMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct KafkaAuth {
    pub mechanism: AuthMechanism,
    pub username_env: Option<String>,
    pub password_env: Option<String>,
    /// Path to client certificate (mTLS)
    pub cert_path: Option<String>,
    /// Path to client key (mTLS)
    pub key_path: Option<String>,
    /// Path to CA certificate (mTLS)
    pub ca_path: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum AuthMechanism {
    None,
    SaslPlain,
    SaslScram256,
    SaslScram512,
    Mtls,
}

fn default_true() -> bool {
    true
}

impl Config {
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }
}

impl ElasticsearchInstance {
    pub fn resolve_username(&self) -> String {
        self.credentials.as_ref().map_or_else(String::new, |c| {
            std::env::var(&c.username_env).unwrap_or_else(|_| {
                warn!(
                    "Env var {} not set for ES instance {}",
                    c.username_env, self.name
                );
                String::new()
            })
        })
    }

    pub fn resolve_password(&self) -> String {
        self.credentials.as_ref().map_or_else(String::new, |c| {
            std::env::var(&c.password_env).unwrap_or_else(|_| {
                warn!(
                    "Env var {} not set for ES instance {}",
                    c.password_env, self.name
                );
                String::new()
            })
        })
    }
}

impl KafkaInstance {
    pub fn resolve_username(&self) -> Option<String> {
        self.auth.username_env.as_ref().and_then(|env| {
            std::env::var(env).ok().or_else(|| {
                warn!("Env var {} not set for Kafka instance {}", env, self.name);
                None
            })
        })
    }

    pub fn resolve_password(&self) -> Option<String> {
        self.auth.password_env.as_ref().and_then(|env| {
            std::env::var(env).ok().or_else(|| {
                warn!("Env var {} not set for Kafka instance {}", env, self.name);
                None
            })
        })
    }

    pub fn brokers_string(&self) -> String {
        self.brokers.join(",")
    }
}
