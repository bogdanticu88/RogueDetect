use anyhow::Result;
use chrono::Utc;
use pcap::{Capture, Device};
use std::collections::HashSet;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use super::emit;
use crate::config::NetworkConfig;
use crate::events::DetectionEvent;
use crate::oui;

pub fn run(config: NetworkConfig, tx: broadcast::Sender<DetectionEvent>) -> Result<()> {
    let interface = resolve_interface(&config.interface)?;
    info!("Network detector started on interface: {}", interface);

    let approved: HashSet<String> = config
        .approved_macs
        .iter()
        .inspect(|m| {
            if normalise_mac(m).len() != 12 {
                warn!("Approved MAC '{}' does not look valid (expected 12 hex digits after normalisation) - it will never match", m);
            }
        })
        .map(|m| normalise_mac(m))
        .collect();

    let mut cap = Capture::from_device(interface.as_str())
        .map_err(|e| {
            anyhow::anyhow!(
                "Cannot open interface {}: {}. Is npcap/libpcap installed?",
                interface,
                e
            )
        })?
        .promisc(true)
        .snaplen(576)
        .timeout(1000)
        .open()
        .map_err(|e| anyhow::anyhow!("Capture open failed (try running as root/admin): {}", e))?;

    cap.filter("udp port 67 or udp port 68", true)?;

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                if let Some(event) = parse_dhcp(packet.data, &approved, &interface) {
                    emit(&tx, event);
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                warn!("Capture error: {}", e);
                break;
            }
        }
    }

    Ok(())
}

fn resolve_interface(name: &str) -> Result<String> {
    if name != "auto" {
        return Ok(name.to_string());
    }
    let device = Device::lookup()
        .map_err(|e| anyhow::anyhow!("Interface lookup failed: {}", e))?
        .ok_or_else(|| anyhow::anyhow!("No network interfaces found"))?;
    Ok(device.name)
}

fn normalise_mac(mac: &str) -> String {
    mac.to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect()
}

fn parse_dhcp(data: &[u8], approved: &HashSet<String>, interface: &str) -> Option<DetectionEvent> {
    // Handles untagged (0x0800) and single-tag 802.1Q (0x8100); QinQ (0x88a8) not yet supported.
    if data.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    let ip_start = match ethertype {
        0x0800 => 14,
        0x8100 => 18,
        _ => return None,
    };

    if data.len() < ip_start + 28 {
        return None;
    }

    if data[ip_start + 9] != 17 {
        return None;
    }

    let ihl = (data[ip_start] & 0x0f) as usize * 4;
    let udp_start = ip_start + ihl;
    let dhcp_start = udp_start + 8;

    if data.len() < dhcp_start + 240 {
        return None;
    }

    if data[dhcp_start] != 1 {
        return None;
    }

    let mac_bytes = &data[dhcp_start + 28..dhcp_start + 34];
    let mac = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5]
    );

    if approved.contains(&normalise_mac(&mac)) {
        debug!("Known device: {}", mac);
        return None;
    }

    let magic_offset = dhcp_start + 236;
    if data.len() < magic_offset + 4 {
        return None;
    }
    if &data[magic_offset..magic_offset + 4] != &[0x63, 0x82, 0x53, 0x63] {
        return None;
    }

    let mut msg_type: Option<u8> = None;
    let mut hostname: Option<String> = None;
    let mut i = magic_offset + 4;

    while i < data.len() {
        let opt = data[i];
        match opt {
            255 => break,
            0 => {
                i += 1;
                continue;
            }
            _ => {}
        }
        if i + 1 >= data.len() {
            break;
        }
        let len = data[i + 1] as usize;
        if i + 2 + len > data.len() {
            break;
        }
        let val = &data[i + 2..i + 2 + len];
        match opt {
            53 if len == 1 => msg_type = Some(val[0]),
            12 => hostname = String::from_utf8(val.to_vec()).ok(),
            _ => {}
        }
        i += 2 + len;
    }

    if !matches!(msg_type, Some(1) | Some(3)) {
        return None;
    }

    let oui_prefix =
        ((mac_bytes[0] as u32) << 16) | ((mac_bytes[1] as u32) << 8) | (mac_bytes[2] as u32);
    let vendor = oui::lookup(oui_prefix).unwrap_or_else(|| "Unknown".to_string());

    let yiaddr = &data[dhcp_start + 16..dhcp_start + 20];
    let ip = if yiaddr == [0, 0, 0, 0] {
        "0.0.0.0".to_string()
    } else {
        format!("{}.{}.{}.{}", yiaddr[0], yiaddr[1], yiaddr[2], yiaddr[3])
    };

    Some(DetectionEvent::UnknownNetworkDevice {
        mac,
        ip,
        vendor,
        hostname,
        interface: interface.to_string(),
        timestamp: Utc::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalise_colon_separated() {
        assert_eq!(normalise_mac("AA:BB:CC:DD:EE:FF"), "aabbccddeeff");
    }

    #[test]
    fn normalise_hyphen_separated() {
        assert_eq!(normalise_mac("aa-bb-cc-dd-ee-ff"), "aabbccddeeff");
    }

    #[test]
    fn normalise_bare_lowercase() {
        assert_eq!(normalise_mac("aabbccddeeff"), "aabbccddeeff");
    }

    #[test]
    fn approved_mac_matches_case_insensitive() {
        let approved: HashSet<String> = ["AA:BB:CC:DD:EE:FF"]
            .iter()
            .map(|m| normalise_mac(m))
            .collect();
        assert!(approved.contains(&normalise_mac("aa:bb:cc:dd:ee:ff")));
        assert!(approved.contains(&normalise_mac("AA:BB:CC:DD:EE:FF")));
    }

    #[test]
    fn dhcp_discover_unknown_mac_triggers_event() {
        let approved = HashSet::new();
        let pkt = make_test_dhcp_packet([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], 1, None);
        assert!(parse_dhcp(&pkt, &approved, "eth0").is_some());
    }

    #[test]
    fn dhcp_request_unknown_mac_triggers_event() {
        let approved = HashSet::new();
        let pkt = make_test_dhcp_packet([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], 3, None);
        assert!(parse_dhcp(&pkt, &approved, "eth0").is_some());
    }

    #[test]
    fn dhcp_discover_approved_mac_no_event() {
        let mut approved = HashSet::new();
        approved.insert(normalise_mac("AA:BB:CC:DD:EE:FF"));
        let pkt = make_test_dhcp_packet([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], 1, None);
        assert!(parse_dhcp(&pkt, &approved, "eth0").is_none());
    }

    #[test]
    fn dhcp_offer_ignored() {
        // OFFER (2) is server-to-client; alerting on it would be noise.
        let approved = HashSet::new();
        let pkt = make_test_dhcp_packet([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], 2, None);
        assert!(parse_dhcp(&pkt, &approved, "eth0").is_none());
    }

    #[test]
    fn dhcp_hostname_extracted() {
        let approved = HashSet::new();
        let pkt = make_test_dhcp_packet([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], 1, Some("laptop01"));
        if let Some(DetectionEvent::UnknownNetworkDevice { hostname, .. }) =
            parse_dhcp(&pkt, &approved, "eth0")
        {
            assert_eq!(hostname, Some("laptop01".to_string()));
        } else {
            panic!("expected UnknownNetworkDevice event");
        }
    }

    fn make_test_dhcp_packet(client_mac: [u8; 6], msg_type: u8, hostname: Option<&str>) -> Vec<u8> {
        // Ethernet (14) + IP (20) + UDP (8) + DHCP fixed (236) + magic (4) + options
        let mut pkt = vec![0u8; 320];

        // Ethernet header
        pkt[0..6].copy_from_slice(&[0xff; 6]);
        pkt[6..12].copy_from_slice(&client_mac);
        pkt[12] = 0x08;
        pkt[13] = 0x00;

        // IP header: version/IHL=0x45, protocol=UDP(17)
        pkt[14] = 0x45;
        pkt[14 + 9] = 17;

        // DHCP op=BOOTREQUEST(1), chaddr=client_mac
        let dhcp = 42usize;
        pkt[dhcp] = 1;
        pkt[dhcp + 28..dhcp + 34].copy_from_slice(&client_mac);

        // Magic cookie
        let magic = dhcp + 236;
        pkt[magic..magic + 4].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);

        let mut opt = magic + 4;
        pkt[opt] = 53;
        pkt[opt + 1] = 1;
        pkt[opt + 2] = msg_type;
        opt += 3;

        if let Some(hn) = hostname {
            let b = hn.as_bytes();
            pkt[opt] = 12;
            pkt[opt + 1] = b.len() as u8;
            pkt[opt + 2..opt + 2 + b.len()].copy_from_slice(b);
            opt += 2 + b.len();
        }

        pkt[opt] = 255;
        pkt.truncate(opt + 1);
        pkt
    }
}
