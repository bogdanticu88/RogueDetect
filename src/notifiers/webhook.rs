use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use std::collections::HashMap;

use crate::events::DetectionEvent;
use super::Notifier;

pub struct WebhookNotifier {
    url: String,
    headers: HashMap<String, String>,
    client: Client,
}

impl WebhookNotifier {
    pub fn new(url: String, headers: HashMap<String, String>) -> Self {
        Self {
            url,
            headers,
            client: Client::new(),
        }
    }
}

#[async_trait]
impl Notifier for WebhookNotifier {
    fn name(&self) -> &str {
        "webhook"
    }

    async fn send(&self, event: &DetectionEvent) -> Result<()> {
        let mut builder = self.client.post(&self.url).json(event);
        for (key, value) in &self.headers {
            builder = builder.header(key.as_str(), value.as_str());
        }
        let resp = builder.send().await?;
        if !resp.status().is_success() {
            anyhow::bail!("Webhook returned HTTP {}", resp.status());
        }
        Ok(())
    }
}
