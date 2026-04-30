use anyhow::Result;
use async_trait::async_trait;

use crate::events::DetectionEvent;

pub mod slack;
pub mod teams;
pub mod webhook;

pub use slack::SlackNotifier;
pub use teams::TeamsNotifier;
pub use webhook::WebhookNotifier;

#[async_trait]
pub trait Notifier: Send + Sync {
    async fn send(&self, event: &DetectionEvent) -> Result<()>;
    fn name(&self) -> &str;
}
