use anyhow::Result;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub usb: UsbConfig,
    #[serde(default)]
    pub notifiers: Vec<NotifierConfig>,
    #[serde(default)]
    pub log: LogConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NetworkConfig {
    #[serde(default = "default_interface")]
    pub interface: String,
    #[serde(default)]
    pub approved_macs: Vec<String>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            interface: default_interface(),
            approved_macs: vec![],
        }
    }
}

fn default_interface() -> String {
    "auto".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct UsbConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub approved_vendors: Vec<u16>,
}

impl Default for UsbConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            approved_vendors: vec![],
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum NotifierConfig {
    Slack {
        webhook: String,
    },
    Teams {
        webhook: String,
    },
    Webhook {
        url: String,
        #[serde(default)]
        headers: HashMap<String, String>,
    },
}

#[derive(Debug, Clone, Deserialize)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "text".to_string()
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Cannot read config file {}: {}", path.display(), e))?;
        let config: Config = serde_yaml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Invalid config: {}", e))?;
        Ok(config)
    }
}
