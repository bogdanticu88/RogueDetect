pub mod network;
pub mod usb;

use tokio::sync::broadcast;
use tracing::{debug, info};

use crate::events::DetectionEvent;

pub fn emit(tx: &broadcast::Sender<DetectionEvent>, event: DetectionEvent) {
    let summary = event.summary();
    if tx.send(event).is_err() {
        debug!("No active receivers for event");
    }
    info!("{}", summary);
}
