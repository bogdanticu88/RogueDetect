use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use std::collections::HashMap;
use std::sync::Arc;

use super::{check_response, Notifier};
use crate::events::DetectionEvent;

pub struct WebhookNotifier {
    url: String,
    headers: HashMap<String, String>,
    client: Arc<Client>,
}

impl WebhookNotifier {
    pub fn new(url: String, headers: HashMap<String, String>, client: Arc<Client>) -> Self {
        Self {
            url,
            headers,
            client,
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
        check_response(&resp, self.name())
    }
}
