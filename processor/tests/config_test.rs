use pgdam_processor::config::{AuthMechanism, Config, KillMode};

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
