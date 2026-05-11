use crate::config::{AuthMechanism, KafkaInstance};
use crate::sink::Sink;
use crate::ProcessedEvent;
use async_trait::async_trait;
use log::{error, info, warn};
use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use std::collections::HashMap;
use std::time::Duration;

pub struct KafkaSink {
    name: String,
    producer: FutureProducer,
    /// event_type → list of topics
    topics: HashMap<String, Vec<String>>,
}

impl KafkaSink {
    pub fn new(instance: &KafkaInstance) -> Result<Self, Box<dyn std::error::Error>> {
        let mut config = ClientConfig::new();
        config.set("bootstrap.servers", instance.brokers_string());
        config.set("message.timeout.ms", "5000");
        config.set("queue.buffering.max.messages", "100000");
        config.set("queue.buffering.max.ms", "50");

        match &instance.auth.mechanism {
            AuthMechanism::None => {}

            AuthMechanism::SaslPlain => {
                let user = instance.resolve_username().unwrap_or_default();
                let pass = instance.resolve_password().unwrap_or_default();
                config.set("security.protocol", "SASL_PLAINTEXT");
                config.set("sasl.mechanisms", "PLAIN");
                config.set("sasl.username", user);
                config.set("sasl.password", pass);
            }

            AuthMechanism::SaslScram256 => {
                let user = instance.resolve_username().unwrap_or_default();
                let pass = instance.resolve_password().unwrap_or_default();
                config.set("security.protocol", "SASL_PLAINTEXT");
                config.set("sasl.mechanisms", "SCRAM-SHA-256");
                config.set("sasl.username", user);
                config.set("sasl.password", pass);
            }

            AuthMechanism::SaslScram512 => {
                let user = instance.resolve_username().unwrap_or_default();
                let pass = instance.resolve_password().unwrap_or_default();
                config.set("security.protocol", "SASL_PLAINTEXT");
                config.set("sasl.mechanisms", "SCRAM-SHA-512");
                config.set("sasl.username", user);
                config.set("sasl.password", pass);
            }

            AuthMechanism::Mtls => {
                let cert = instance.auth.cert_path.as_deref().unwrap_or_default();
                let key = instance.auth.key_path.as_deref().unwrap_or_default();
                let ca = instance.auth.ca_path.as_deref().unwrap_or_default();
                config.set("security.protocol", "SSL");
                config.set("ssl.certificate.location", cert);
                config.set("ssl.key.location", key);
                config.set("ssl.ca.location", ca);
            }
        }

        let producer: FutureProducer = config.create()?;
        info!(
            "[{}] Kafka producer created (brokers: {})",
            instance.name,
            instance.brokers_string()
        );

        Ok(Self {
            name: instance.name.clone(),
            producer,
            topics: instance.topics.clone(),
        })
    }
}

#[async_trait]
impl Sink for KafkaSink {
    async fn send(&self, event: ProcessedEvent) {
        let payload = match serde_json::to_string(&event) {
            Ok(p) => p,
            Err(e) => {
                error!("[{}] Failed to serialize event: {}", self.name, e);
                return;
            }
        };

        // Use pid as the partition key so all queries from the same
        // postgres backend process land on the same partition — preserving
        // order within a session.
        let key = event.pid.to_string();

        let topics = match self.topics.get(&event.event_type) {
            Some(t) => t,
            None => {
                warn!(
                    "[{}] No topic configured for event_type '{}' — dropping event",
                    self.name, event.event_type
                );
                return;
            }
        };

        for topic in topics {
            let record = FutureRecord::to(topic)
                .payload(payload.as_str())
                .key(key.as_str());

            match self.producer.send(record, Duration::from_secs(5)).await {
                Ok((partition, offset)) => {
                    log::debug!(
                        "[{}] Sent to {} partition={} offset={}",
                        self.name,
                        topic,
                        partition,
                        offset
                    );
                }
                Err((e, _)) => {
                    error!("[{}] Failed to send to topic {}: {}", self.name, topic, e);
                }
            }
        }
    }
}
