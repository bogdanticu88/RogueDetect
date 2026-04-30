use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use reqwest::Client;
use tokio::sync::broadcast;
use tracing::{error, info};

mod config;
mod detectors;
mod events;
mod notifiers;
mod oui;

use config::{Config, NotifierConfig};
use events::DetectionEvent;
use notifiers::{Notifier, SlackNotifier, TeamsNotifier, WebhookNotifier};

#[derive(Parser)]
#[command(
    name = "roguedetect",
    about = "Rogue network device and USB storage exfiltration detector",
    version
)]
struct Cli {
    #[arg(short, long, default_value = "config.yaml")]
    config: PathBuf,

    #[arg(long, help = "List available network interfaces and exit")]
    list_interfaces: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.list_interfaces {
        print_interfaces();
        return Ok(());
    }

    let config = Config::load(&cli.config)?;
    setup_logging(&config.log);

    info!("RogueDetect starting");

    let http = Arc::new(Client::new());

    let notifiers: Vec<Arc<dyn Notifier>> = config
        .notifiers
        .iter()
        .map(|nc| -> Arc<dyn Notifier> {
            match nc {
                NotifierConfig::Slack { webhook } => {
                    Arc::new(SlackNotifier::new(webhook.clone(), Arc::clone(&http)))
                }
                NotifierConfig::Teams { webhook } => {
                    Arc::new(TeamsNotifier::new(webhook.clone(), Arc::clone(&http)))
                }
                NotifierConfig::Webhook { url, headers } => {
                    Arc::new(WebhookNotifier::new(url.clone(), headers.clone(), Arc::clone(&http)))
                }
            }
        })
        .collect();

    if notifiers.is_empty() {
        info!("No notifiers configured — events will be logged only");
    }

    let (tx, _) = broadcast::channel::<DetectionEvent>(256);

    // Fan out each event to all notifiers concurrently — one task per notifier so a
    // slow or failing notifier does not delay the others.
    {
        let notifiers = notifiers.clone();
        let mut rx = tx.subscribe();
        tokio::spawn(async move {
            while let Ok(event) = rx.recv().await {
                let event = Arc::new(event);
                for notifier in &notifiers {
                    let notifier = Arc::clone(notifier);
                    let event = Arc::clone(&event);
                    tokio::spawn(async move {
                        if let Err(e) = notifier.send(&event).await {
                            error!("{} notifier failed: {}", notifier.name(), e);
                            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                            if let Err(e) = notifier.send(&event).await {
                                error!("{} notifier retry failed: {}", notifier.name(), e);
                            }
                        }
                    });
                }
            }
        });
    }

    {
        let network_config = config.network.clone();
        let tx = tx.clone();
        tokio::task::spawn_blocking(move || {
            if let Err(e) = detectors::network::run(network_config, tx) {
                error!("Network detector stopped: {}", e);
            }
        });
    }

    {
        let usb_config = config.usb.clone();
        let tx = tx.clone();
        tokio::task::spawn_blocking(move || {
            detectors::usb::run(usb_config, tx);
        });
    }

    info!("RogueDetect running — press Ctrl+C to stop");
    tokio::signal::ctrl_c().await?;
    info!("Shutting down");
    Ok(())
}

fn setup_logging(config: &config::LogConfig) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&config.level));

    if config.format == "json" {
        tracing_subscriber::fmt().json().with_env_filter(filter).init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
}

fn print_interfaces() {
    match pcap::Device::list() {
        Ok(devices) => {
            println!("Available interfaces:");
            for d in devices {
                let desc = d.desc.as_deref().unwrap_or("");
                println!("  {} — {}", d.name, desc);
            }
        }
        Err(e) => eprintln!("Failed to list interfaces: {}", e),
    }
}
