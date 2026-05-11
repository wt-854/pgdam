pub mod elasticsearch;
pub mod kafka;
pub mod stdout;

use crate::ProcessedEvent;
use async_trait::async_trait;

#[async_trait]
pub trait Sink: Send + Sync {
    async fn send(&self, event: ProcessedEvent);
}

pub use elasticsearch::ElasticSink;
pub use kafka::KafkaSink;
pub use stdout::StdoutSink;
