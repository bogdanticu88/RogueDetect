use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use serde_json::json;
use std::sync::Arc;

use crate::events::{DetectionEvent, TIMESTAMP_FMT};
use super::{check_response, Notifier};

pub struct TeamsNotifier {
    webhook_url: String,
    client: Arc<Client>,
}

impl TeamsNotifier {
    pub fn new(webhook_url: String, client: Arc<Client>) -> Self {
        Self { webhook_url, client }
    }
}

#[async_trait]
impl Notifier for TeamsNotifier {
    fn name(&self) -> &str {
        "teams"
    }

    async fn send(&self, event: &DetectionEvent) -> Result<()> {
        let (title, color, facts) = match event {
            DetectionEvent::UnknownNetworkDevice {
                mac, ip, vendor, hostname, interface, timestamp,
            } => {
                let facts = json!([
                    { "title": "MAC Address", "value": mac },
                    { "title": "IP Address",  "value": ip },
                    { "title": "Vendor",      "value": vendor },
                    { "title": "Interface",   "value": interface },
                    { "title": "Device Hostname", "value": hostname.as_deref().unwrap_or("—") },
                    { "title": "Detected At", "value": timestamp.format(TIMESTAMP_FMT).to_string() },
                ]);
                ("Unknown Network Device Detected", "Attention", facts)
            }
            DetectionEvent::UsbStorageConnected {
                vendor_id, product_id, manufacturer, serial, host, timestamp,
            } => {
                let facts = json!([
                    { "title": "Host",         "value": host },
                    { "title": "Manufacturer", "value": manufacturer.as_deref().unwrap_or("Unknown") },
                    { "title": "VID:PID",      "value": format!("{:04x}:{:04x}", vendor_id, product_id) },
                    { "title": "Serial",       "value": serial.as_deref().unwrap_or("—") },
                    { "title": "Detected At",  "value": timestamp.format(TIMESTAMP_FMT).to_string() },
                ]);
                ("USB Storage Device Connected", "Attention", facts)
            }
        };

        let payload = json!({
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": "🚨 RogueDetect Alert",
                            "weight": "Bolder",
                            "size": "Medium",
                            "color": color
                        },
                        {
                            "type": "TextBlock",
                            "text": title,
                            "weight": "Bolder"
                        },
                        {
                            "type": "FactSet",
                            "facts": facts
                        }
                    ]
                }
            }]
        });

        let resp = self.client.post(&self.webhook_url).json(&payload).send().await?;
        check_response(&resp, self.name())
    }
}
