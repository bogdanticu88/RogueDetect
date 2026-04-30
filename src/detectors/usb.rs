use chrono::Utc;
use rusb::GlobalContext;
use std::collections::HashSet;
use std::time::Duration;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use crate::config::UsbConfig;
use crate::events::DetectionEvent;

const CLASS_HID: u8 = 0x03;
const CLASS_HUB: u8 = 0x09;
const CLASS_MASS_STORAGE: u8 = 0x08;

pub fn run(config: UsbConfig, tx: broadcast::Sender<DetectionEvent>) {
    if !config.enabled {
        info!("USB detector disabled in config");
        return;
    }

    info!("USB detector started (polling every 2s)");

    let mut known = snapshot();

    loop {
        std::thread::sleep(Duration::from_secs(2));

        let current = snapshot();
        let new_devices: Vec<_> = current.difference(&known).cloned().collect();

        for (bus, addr) in new_devices {
            if let Some(event) = inspect_device(bus, addr, &config) {
                let summary = event.summary();
                if tx.send(event).is_err() {
                    debug!("No active receivers");
                }
                info!("{}", summary);
            }
        }

        known = current;
    }
}

fn snapshot() -> HashSet<(u8, u8)> {
    rusb::devices()
        .map(|list| {
            list.iter()
                .map(|d| (d.bus_number(), d.address()))
                .collect()
        })
        .unwrap_or_default()
}

fn inspect_device(
    bus: u8,
    addr: u8,
    config: &UsbConfig,
) -> Option<DetectionEvent> {
    let devices = rusb::devices().ok()?;

    let device = devices
        .iter()
        .find(|d| d.bus_number() == bus && d.address() == addr)?;

    let desc = device.device_descriptor().ok()?;
    let vendor_id = desc.vendor_id();
    let product_id = desc.product_id();
    let class = desc.class_code();

    // Suppress hubs unconditionally
    if class == CLASS_HUB {
        debug!("Hub ignored: {:04x}:{:04x}", vendor_id, product_id);
        return None;
    }

    // Suppress known HID devices (keyboards, mice)
    if class == CLASS_HID && config.approved_vendors.contains(&vendor_id) {
        debug!("Approved HID ignored: {:04x}:{:04x}", vendor_id, product_id);
        return None;
    }

    // Determine if this is a storage device
    let is_storage = class == CLASS_MASS_STORAGE || has_storage_interface(&device);

    if !is_storage {
        // For non-storage, non-HID unknown devices, still alert
        // (could be a BadUSB/rubber ducky masquerading as HID)
        if class == CLASS_HID {
            warn!(
                "Unknown HID device (possible BadUSB): {:04x}:{:04x}",
                vendor_id, product_id
            );
        } else {
            debug!(
                "Non-storage USB device ignored: {:04x}:{:04x} class={:02x}",
                vendor_id, product_id, class
            );
            return None;
        }
    }

    let manufacturer = device
        .open()
        .ok()
        .and_then(|h| h.read_manufacturer_string_ascii(&desc).ok());

    let serial = device
        .open()
        .ok()
        .and_then(|h| h.read_serial_number_string_ascii(&desc).ok());

    let host = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    Some(DetectionEvent::UsbStorageConnected {
        vendor_id,
        product_id,
        manufacturer,
        serial,
        host,
        timestamp: Utc::now(),
    })
}

fn has_storage_interface(device: &rusb::Device<GlobalContext>) -> bool {
    device
        .active_config_descriptor()
        .map(|cfg| {
            cfg.interfaces().any(|iface| {
                iface
                    .descriptors()
                    .any(|d| d.class_code() == CLASS_MASS_STORAGE)
            })
        })
        .unwrap_or(false)
}
