use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use serde_json::json;

use crate::events::DetectionEvent;
use super::Notifier;

pub struct SlackNotifier {
    webhook_url: String,
    client: Client,
}

impl SlackNotifier {
    pub fn new(webhook_url: String) -> Self {
        Self {
            webhook_url,
            client: Client::new(),
        }
    }
}

#[async_trait]
impl Notifier for SlackNotifier {
    fn name(&self) -> &str {
        "slack"
    }

    async fn send(&self, event: &DetectionEvent) -> Result<()> {
        let payload = match event {
            DetectionEvent::UnknownNetworkDevice {
                mac, ip, vendor, hostname, interface, timestamp,
            } => {
                json!({
                    "blocks": [
                        {
                            "type": "header",
                            "text": { "type": "plain_text", "text": ":warning: RogueDetect: Unknown Network Device" }
                        },
                        {
                            "type": "section",
                            "fields": [
                                { "type": "mrkdwn", "text": format!("*MAC*\n`{}`", mac) },
                                { "type": "mrkdwn", "text": format!("*IP*\n`{}`", ip) },
                                { "type": "mrkdwn", "text": format!("*Vendor*\n{}", vendor) },
                                { "type": "mrkdwn", "text": format!("*Interface*\n{}", interface) },
                                { "type": "mrkdwn", "text": format!("*Device Hostname*\n{}", hostname.as_deref().unwrap_or("—")) },
                                { "type": "mrkdwn", "text": format!("*Detected At*\n{}", timestamp.format("%Y-%m-%d %H:%M:%S UTC")) },
                            ]
                        }
                    ]
                })
            }
            DetectionEvent::UsbStorageConnected {
                vendor_id, product_id, manufacturer, serial, host, timestamp,
            } => {
                json!({
                    "blocks": [
                        {
                            "type": "header",
                            "text": { "type": "plain_text", "text": ":rotating_light: RogueDetect: USB Storage Device Connected" }
                        },
                        {
                            "type": "section",
                            "fields": [
                                { "type": "mrkdwn", "text": format!("*Host*\n{}", host) },
                                { "type": "mrkdwn", "text": format!("*Manufacturer*\n{}", manufacturer.as_deref().unwrap_or("Unknown")) },
                                { "type": "mrkdwn", "text": format!("*VID:PID*\n`{:04x}:{:04x}`", vendor_id, product_id) },
                                { "type": "mrkdwn", "text": format!("*Serial*\n{}", serial.as_deref().unwrap_or("—")) },
                                { "type": "mrkdwn", "text": format!("*Detected At*\n{}", timestamp.format("%Y-%m-%d %H:%M:%S UTC")) },
                            ]
                        }
                    ]
                })
            }
        };

        let resp = self.client.post(&self.webhook_url).json(&payload).send().await?;
        if !resp.status().is_success() {
            anyhow::bail!("Slack webhook returned HTTP {}", resp.status());
        }
        Ok(())
    }
}
