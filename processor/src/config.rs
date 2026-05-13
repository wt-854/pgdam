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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Config {
        serde_yaml::from_str(yaml).expect("Failed to parse config")
    }

    #[test]
    fn test_kill_mode_defaults_to_disabled() {
        let config = parse("sinks: {}");
        assert_eq!(config.kill_mode, KillMode::Disabled);
    }

    #[test]
    fn test_kill_mode_auto() {
        let config = parse("sinks: {}\nkill_mode: auto");
        assert_eq!(config.kill_mode, KillMode::Auto);
    }

    #[test]
    fn test_kill_mode_manual() {
        let config = parse("sinks: {}\nkill_mode: manual");
        assert_eq!(config.kill_mode, KillMode::Manual);
    }

    #[test]
    fn test_kill_mode_disabled() {
        let config = parse("sinks: {}\nkill_mode: disabled");
        assert_eq!(config.kill_mode, KillMode::Disabled);
    }

    #[test]
    fn test_minimal_config_no_sinks() {
        let config = parse("sinks: {}");
        assert!(config.sinks.elasticsearch.is_none());
        assert!(config.sinks.kafka.is_none());
    }

    #[test]
    fn test_elasticsearch_enabled() {
        let config = parse(
            r#"
sinks:
  elasticsearch:
    enabled: true
    instances:
      - name: prod
        enabled: true
        url: http://localhost:9200
"#,
        );
        let es = config.sinks.elasticsearch.unwrap();
        assert!(es.enabled);
        assert_eq!(es.instances.len(), 1);
        assert_eq!(es.instances[0].name, "prod");
        assert_eq!(es.instances[0].url, "http://localhost:9200");
    }

    #[test]
    fn test_elasticsearch_disabled() {
        let config = parse(
            r#"
sinks:
  elasticsearch:
    enabled: false
    instances: []
"#,
        );
        let es = config.sinks.elasticsearch.unwrap();
        assert!(!es.enabled);
    }

    #[test]
    fn test_elasticsearch_instance_disabled() {
        let config = parse(
            r#"
sinks:
  elasticsearch:
    enabled: true
    instances:
      - name: prod
        enabled: false
        url: http://localhost:9200
"#,
        );
        let es = config.sinks.elasticsearch.unwrap();
        assert!(!es.instances[0].enabled);
    }

    #[test]
    fn test_elasticsearch_defaults_enabled_true() {
        // enabled field should default to true if omitted
        let config = parse(
            r#"
sinks:
  elasticsearch:
    instances:
      - name: prod
        url: http://localhost:9200
"#,
        );
        let es = config.sinks.elasticsearch.unwrap();
        assert!(es.enabled);
        assert!(es.instances[0].enabled);
    }

    #[test]
    fn test_kafka_single_instance_no_auth() {
        let config = parse(
            r#"
sinks:
  kafka:
    enabled: true
    instances:
      - name: dev
        enabled: true
        brokers:
          - kafka:9092
        auth:
          mechanism: none
        topics:
          user_query:
            - pgdam.user-queries
          background_worker:
            - pgdam.bg-workers
"#,
        );
        let kafka = config.sinks.kafka.unwrap();
        assert!(kafka.enabled);
        assert_eq!(kafka.instances.len(), 1);
        let inst = &kafka.instances[0];
        assert_eq!(inst.name, "dev");
        assert_eq!(inst.brokers, vec!["kafka:9092"]);
        assert_eq!(
            inst.topics.get("user_query").unwrap(),
            &vec!["pgdam.user-queries".to_string()]
        );
    }

    #[test]
    fn test_kafka_multiple_instances() {
        let config = parse(
            r#"
sinks:
  kafka:
    enabled: true
    instances:
      - name: prod
        enabled: true
        brokers:
          - kafka-prod-1:9092
          - kafka-prod-2:9092
        auth:
          mechanism: sasl_plain
          username_env: KAFKA_PROD_USER
          password_env: KAFKA_PROD_PASS
        topics:
          user_query:
            - pgdam.user-queries
      - name: nonprod
        enabled: true
        brokers:
          - kafka-nonprod:9092
        auth:
          mechanism: none
        topics:
          user_query:
            - pgdam.user-queries
"#,
        );
        let kafka = config.sinks.kafka.unwrap();
        assert_eq!(kafka.instances.len(), 2);
        assert_eq!(kafka.instances[0].name, "prod");
        assert_eq!(kafka.instances[0].brokers.len(), 2);
        assert_eq!(kafka.instances[1].name, "nonprod");
    }

    #[test]
    fn test_kafka_sasl_plain_auth() {
        let config = parse(
            r#"
sinks:
  kafka:
    enabled: true
    instances:
      - name: prod
        enabled: true
        brokers:
          - kafka:9092
        auth:
          mechanism: sasl_plain
          username_env: KAFKA_USER
          password_env: KAFKA_PASS
        topics:
          user_query:
            - pgdam.user-queries
"#,
        );
        let inst = &config.sinks.kafka.unwrap().instances[0];
        assert!(matches!(inst.auth.mechanism, AuthMechanism::SaslPlain));
        assert_eq!(inst.auth.username_env.as_deref(), Some("KAFKA_USER"));
        assert_eq!(inst.auth.password_env.as_deref(), Some("KAFKA_PASS"));
    }

    #[test]
    fn test_kafka_topic_multiple_destinations() {
        let config = parse(
            r#"
sinks:
  kafka:
    enabled: true
    instances:
      - name: prod
        enabled: true
        brokers:
          - kafka:9092
        auth:
          mechanism: none
        topics:
          user_query:
            - pgdam.user-queries
            - pgdam.security-team
"#,
        );
        let inst = &config.sinks.kafka.unwrap().instances[0];
        let topics = inst.topics.get("user_query").unwrap();
        assert_eq!(topics.len(), 2);
        assert_eq!(topics[0], "pgdam.user-queries");
        assert_eq!(topics[1], "pgdam.security-team");
    }

    #[test]
    fn test_brokers_string() {
        let config = parse(
            r#"
sinks:
  kafka:
    enabled: true
    instances:
      - name: prod
        enabled: true
        brokers:
          - kafka-1:9092
          - kafka-2:9092
          - kafka-3:9092
        auth:
          mechanism: none
        topics:
          user_query:
            - pgdam.user-queries
"#,
        );
        let inst = &config.sinks.kafka.unwrap().instances[0];
        assert_eq!(
            inst.brokers_string(),
            "kafka-1:9092,kafka-2:9092,kafka-3:9092"
        );
    }

    #[test]
    fn test_elasticsearch_credentials_env_vars() {
        std::env::set_var("TEST_ES_USER", "admin");
        std::env::set_var("TEST_ES_PASS", "secret");

        let config = parse(
            r#"
sinks:
  elasticsearch:
    enabled: true
    instances:
      - name: prod
        url: http://localhost:9200
        credentials:
          username_env: TEST_ES_USER
          password_env: TEST_ES_PASS
"#,
        );
        let inst = &config.sinks.elasticsearch.unwrap().instances[0];
        assert_eq!(inst.resolve_username(), "admin");
        assert_eq!(inst.resolve_password(), "secret");

        std::env::remove_var("TEST_ES_USER");
        std::env::remove_var("TEST_ES_PASS");
    }

    #[test]
    fn test_missing_credentials_env_var_returns_empty() {
        std::env::remove_var("NONEXISTENT_VAR");
        let config = parse(
            r#"
sinks:
  elasticsearch:
    enabled: true
    instances:
      - name: prod
        url: http://localhost:9200
        credentials:
          username_env: NONEXISTENT_VAR
          password_env: NONEXISTENT_VAR
"#,
        );
        let inst = &config.sinks.elasticsearch.unwrap().instances[0];
        assert_eq!(inst.resolve_username(), "");
        assert_eq!(inst.resolve_password(), "");
    }
}
