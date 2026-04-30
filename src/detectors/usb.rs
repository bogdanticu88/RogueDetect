use chrono::Utc;
use rusb::GlobalContext;
use std::collections::HashSet;
use std::time::Duration;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use crate::config::UsbConfig;
use crate::events::DetectionEvent;
use super::emit;

const CLASS_HID: u8 = 0x03;
const CLASS_HUB: u8 = 0x09;
const CLASS_MASS_STORAGE: u8 = 0x08;

pub fn run(config: UsbConfig, tx: broadcast::Sender<DetectionEvent>) {
    if !config.enabled {
        info!("USB detector disabled in config");
        return;
    }

    info!("USB detector started (polling every 2s)");

    let host = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    // Initial snapshot - no alerts, just establish baseline.
    let mut known: HashSet<(u8, u8)> = match rusb::devices() {
        Ok(list) => list.iter().map(|d| (d.bus_number(), d.address())).collect(),
        Err(e) => { warn!("USB initial scan failed: {}", e); HashSet::new() }
    };

    loop {
        std::thread::sleep(Duration::from_secs(2));

        let devices = match rusb::devices() {
            Ok(d) => d,
            Err(e) => { warn!("USB scan failed: {}", e); continue; }
        };

        let current: HashSet<(u8, u8)> = devices.iter().map(|d| (d.bus_number(), d.address())).collect();

        for &(bus, addr) in current.difference(&known) {
            if let Some(device) = devices.iter().find(|d| d.bus_number() == bus && d.address() == addr) {
                if let Some(event) = inspect_device(&device, &config, &host) {
                    emit(&tx, event);
                }
            }
        }

        known = current;
    }
}

fn inspect_device(
    device: &rusb::Device<GlobalContext>,
    config: &UsbConfig,
    host: &str,
) -> Option<DetectionEvent> {
    let desc = device.device_descriptor().ok()?;
    let vendor_id = desc.vendor_id();
    let product_id = desc.product_id();
    let class = desc.class_code();

    if class == CLASS_HUB {
        debug!("Hub ignored: {:04x}:{:04x}", vendor_id, product_id);
        return None;
    }

    if class == CLASS_HID && config.approved_vendors.contains(&vendor_id) {
        debug!("Approved HID ignored: {:04x}:{:04x}", vendor_id, product_id);
        return None;
    }

    let is_storage = class == CLASS_MASS_STORAGE || has_storage_interface(device);

    if !is_storage {
        if class == CLASS_HID {
            // Unapproved HID - could be a BadUSB / rubber ducky
            warn!("Unknown HID device (possible BadUSB): {:04x}:{:04x}", vendor_id, product_id);
        } else {
            debug!("Non-storage USB device ignored: {:04x}:{:04x} class={:02x}", vendor_id, product_id, class);
            return None;
        }
    }

    // Open device once to read both manufacturer and serial
    let (manufacturer, serial) = match device.open() {
        Ok(handle) => (
            handle.read_manufacturer_string_ascii(&desc).ok(),
            handle.read_serial_number_string_ascii(&desc).ok(),
        ),
        Err(_) => (None, None),
    };

    Some(DetectionEvent::UsbStorageConnected {
        vendor_id,
        product_id,
        manufacturer,
        serial,
        host: host.to_string(),
        timestamp: Utc::now(),
    })
}

fn has_storage_interface(device: &rusb::Device<GlobalContext>) -> bool {
    device
        .active_config_descriptor()
        .map(|cfg| {
            cfg.interfaces().any(|iface| {
                iface.descriptors().any(|d| d.class_code() == CLASS_MASS_STORAGE)
            })
        })
        .unwrap_or(false)
}
