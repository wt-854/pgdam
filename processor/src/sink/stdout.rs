use crate::sink::Sink;
use crate::ProcessedEvent;
use async_trait::async_trait;

pub struct StdoutSink;

#[async_trait]
impl Sink for StdoutSink {
    async fn send(&self, event: ProcessedEvent) {
        if let Ok(json) = serde_json::to_string(&event) {
            println!("{}", json);
        }
    }
}
