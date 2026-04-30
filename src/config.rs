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
        let config: Config =
            serde_yaml::from_str(&content).map_err(|e| anyhow::anyhow!("Invalid config: {}", e))?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Config {
        serde_yaml::from_str(yaml).expect("config parse failed")
    }

    #[test]
    fn full_config_parses() {
        let config = parse(
            r#"
network:
  interface: eth0
  approved_macs:
    - "AA:BB:CC:DD:EE:FF"
usb:
  enabled: true
  approved_vendors:
    - 0x046d
notifiers:
  - type: slack
    webhook: "https://hooks.slack.com/services/test"
log:
  level: debug
  format: json
"#,
        );
        assert_eq!(config.network.interface, "eth0");
        assert_eq!(config.network.approved_macs, vec!["AA:BB:CC:DD:EE:FF"]);
        assert!(config.usb.enabled);
        assert_eq!(config.usb.approved_vendors, vec![0x046d]);
        assert_eq!(config.log.level, "debug");
        assert_eq!(config.log.format, "json");
    }

    #[test]
    fn empty_config_uses_defaults() {
        let config = parse("{}");
        assert_eq!(config.network.interface, "auto");
        assert!(config.network.approved_macs.is_empty());
        assert!(config.usb.enabled);
        assert!(config.usb.approved_vendors.is_empty());
        assert!(config.notifiers.is_empty());
        assert_eq!(config.log.level, "info");
        assert_eq!(config.log.format, "text");
    }

    #[test]
    fn multiple_notifier_types_parse() {
        let config = parse(
            r#"
notifiers:
  - type: slack
    webhook: "https://hooks.slack.com/services/x"
  - type: teams
    webhook: "https://example.com/teams"
  - type: webhook
    url: "https://siem.internal/events"
    headers:
      Authorization: "Bearer token"
"#,
        );
        assert_eq!(config.notifiers.len(), 3);
    }
}
