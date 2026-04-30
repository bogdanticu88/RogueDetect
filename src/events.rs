use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const TIMESTAMP_FMT: &str = "%Y-%m-%d %H:%M:%S UTC";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DetectionEvent {
    UnknownNetworkDevice {
        mac: String,
        ip: String,
        vendor: String,
        hostname: Option<String>,
        interface: String,
        timestamp: DateTime<Utc>,
    },
    UsbStorageConnected {
        vendor_id: u16,
        product_id: u16,
        manufacturer: Option<String>,
        serial: Option<String>,
        host: String,
        timestamp: DateTime<Utc>,
    },
}

impl DetectionEvent {
    pub fn summary(&self) -> String {
        match self {
            DetectionEvent::UnknownNetworkDevice { mac, ip, vendor, interface, .. } => {
                format!("[ALERT] Unknown network device: {} ({}) on {} — IP: {}", mac, vendor, interface, ip)
            }
            DetectionEvent::UsbStorageConnected { manufacturer, vendor_id, product_id, host, .. } => {
                let mfr = manufacturer.as_deref().unwrap_or("Unknown");
                format!("[ALERT] USB storage on {}: {} ({:04x}:{:04x})", host, mfr, vendor_id, product_id)
            }
        }
    }
}
