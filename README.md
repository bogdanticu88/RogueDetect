# RogueDetect

<p align="center">
  <img src="assets/logo.png" alt="RogueDetect" width="320" />
</p>

[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/github/v/release/bogdanticu88/RogueDetect?style=flat-square&color=green)](https://github.com/bogdanticu88/RogueDetect/releases)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![Linux](https://img.shields.io/badge/Linux-supported-success?style=flat-square&logo=linux&logoColor=white)](https://github.com/bogdanticu88/RogueDetect/releases)
[![macOS](https://img.shields.io/badge/macOS-supported-success?style=flat-square&logo=apple&logoColor=white)](https://github.com/bogdanticu88/RogueDetect/releases)
[![Windows](https://img.shields.io/badge/Windows-supported-success?style=flat-square&logo=windows&logoColor=white)](https://github.com/bogdanticu88/RogueDetect/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/bogdanticu88/RogueDetect/ci.yml?style=flat-square&label=CI)](https://github.com/bogdanticu88/RogueDetect/actions)

**Rogue Device and USB Exfiltration Detector**

RogueDetect is a lightweight, cross-platform security tool that detects unauthorized devices on your network and USB storage devices connecting to monitored hosts. It runs as a single binary with no cloud dependency, alerts in real time through Slack, Microsoft Teams, or any webhook endpoint, and is designed to drop into whatever monitoring stack you already have.

It is built for security teams and system administrators who need to know the moment something unexpected touches their network or a USB drive is plugged in, without deploying another agent-heavy platform.

---

## What problem it solves

Most enterprise environments have strong perimeter security but poor visibility into what is physically connecting to their infrastructure. 

At the same time, insider data theft over USB is one of the most common and least-detected exfiltration vectors. An employee with a flash drive can walk out with gigabytes of sensitive data in minutes. Modern organizations have little legitimate need for USB storage devices; everything can move through approved channels.

RogueDetect addresses both problems with two independent detection modules that can run together or separately, depending on your environment.

---

## How it works

### Phase 1: Network device detection

RogueDetect listens passively on a network interface using DHCP packet capture. When any device requests an IP address, it extracts the MAC address and compares it against your approved device list. Unknown devices trigger an immediate alert.

This approach is agentless: no software needs to be installed on other machines. In environments where wired connections are rare (most modern offices where everyone uses Wi-Fi), any new wired connection is inherently suspicious, which keeps false positives near zero.

The detection latency is under 60 seconds from the moment an unknown device connects.

### Phase 2: USB storage detection

RogueDetect polls connected USB devices every two seconds. When a new device appears, it checks the USB device class:

- **USB hubs** are silently ignored
- **HID devices** (keyboards, mice) from vendors on your approved list are silently ignored
- **Mass storage devices** always trigger an alert, regardless of vendor
- **Unapproved HID devices** trigger a warning; an unrecognized HID device could be a BadUSB or rubber ducky

This classification runs without opening the device handle for most cases, so it works even on devices claimed by the operating system.

---

## Coverage and limitations

Understanding what RogueDetect does not detect is as important as understanding what it does.

**Network detection**

- Devices that configure a static IP address are not visible. RogueDetect only sees devices that send a DHCP DISCOVER or REQUEST.
- MAC address spoofing defeats the approved list. An attacker who knows an approved MAC can clone it.
- Devices on a different VLAN that do not share a broadcast domain with the monitored interface are not seen.
- Double-tagged QinQ (802.1ad) frames are not parsed and are skipped (planned for v0.2).

**USB detection**

- A composite USB device that presents itself as a HID device from an approved vendor will be suppressed. A sufficiently targeted BadUSB attack against a known-vendor ID bypasses this check.
- RogueDetect detects and alerts; it does not block or eject devices. Blocking requires OS-level policy.

**Delivery**

- Alert delivery is best-effort. Notifiers fire HTTP POST with one automatic retry. There is no persistent queue; if the endpoint is down at alert time, the event is logged but not retried again.

---

## Alerting

Alerts are delivered through notifiers configured in your YAML config file. Multiple notifiers can run simultaneously. A failing notifier does not block the others.

**Slack**: rich block-formatted messages with all device details inline.

**Microsoft Teams**: Adaptive Card format using the current Workflow webhook API (not the deprecated Office 365 connector format).

**Generic webhook**: a JSON POST of the raw event to any HTTP endpoint, with optional custom headers. This covers PagerDuty, Discord, Splunk HEC, your own SIEM, or anything else that accepts HTTP.

Each notifier automatically retries once on failure before logging the error and moving on.

---

## JSON event schema

When `format: json` is set in the log config, or when using the generic webhook notifier, events are serialised with the following structure.

**Unknown network device**

```json
{
  "type": "unknown_network_device",
  "mac": "aa:bb:cc:dd:ee:ff",
  "ip": "192.168.1.42",
  "vendor": "Raspberry Pi Foundation",
  "hostname": "rpi-implant",
  "interface": "eth0",
  "timestamp": "2026-04-30T21:00:00Z"
}
```

`hostname` is `null` if the device did not include DHCP option 12. `ip` is `"0.0.0.0"` for a DISCOVER before an address has been assigned.

**USB storage connected**

```json
{
  "type": "usb_storage_connected",
  "vendor_id": 1921,
  "product_id": 21891,
  "manufacturer": "SanDisk",
  "serial": "4C531234567890A",
  "host": "workstation-01",
  "timestamp": "2026-04-30T21:00:00Z"
}
```

`manufacturer` and `serial` are `null` if the device did not expose string descriptors. `vendor_id` and `product_id` are integers (decimal).

---

## Architecture

```
roguedetect/
├── src/
│   ├── main.rs                  # CLI, async runtime, event broadcast, notifier dispatch
│   ├── config.rs                # YAML config parsing
│   ├── events.rs                # DetectionEvent types shared across modules
│   ├── oui.rs                   # MAC vendor lookup (OUI prefix table)
│   ├── detectors/
│   │   ├── network.rs           # DHCP snooping, MAC matching, OUI lookup
│   │   └── usb.rs               # USB polling, device classification
│   └── notifiers/
│       ├── slack.rs             # Slack blocks format
│       ├── teams.rs             # Teams Adaptive Cards
│       └── webhook.rs           # Generic JSON POST
├── config.yaml.example
├── scripts/install.sh
└── .github/workflows/release.yml
```

The two detectors run in separate threads. Each emits events onto a broadcast channel. The async dispatcher receives events and fans them out to all configured notifiers concurrently, one tokio task per notifier per event.

The network detector is synchronous (pcap is a blocking API) and runs in a dedicated blocking thread. The USB detector polls every two seconds in a dedicated blocking thread. Neither blocks the other.

---

## Requirements

### Linux

```bash
apt install libpcap-dev libusb-1.0-0-dev
```

On Linux, packet capture requires either running as root or setting the capability on the binary:

```bash
sudo setcap cap_net_raw+ep $(which roguedetect)
```

### macOS

```bash
brew install libusb
```

libpcap is built in. Packet capture requires running as root.

### Windows

Two one-time dependencies:

1. **npcap**: download and install from `npcap.com`. During installation, enable **"Install Npcap in WinPcap API-compatible Mode"**.
2. **npcap SDK**: download the SDK zip from the same page and extract it to `C:\npcap-sdk`.

The Cargo config in the repository already points to `C:\npcap-sdk\Lib\x64` for the linker. If you extract to a different path, update `.cargo\config.toml` accordingly.

Packet capture on Windows requires running as Administrator.

---

## Installation

### Pre-built binaries

Download the binary for your platform from the [Releases](https://github.com/bogdanticu88/RogueDetect/releases) page.

| Platform | File |
|----------|------|
| Linux x86\_64 (static) | `roguedetect-linux-x86_64` |
| Linux ARM64 (static) | `roguedetect-linux-arm64` |
| macOS x86\_64 | `roguedetect-macos-x86_64` |
| macOS ARM64 (Apple Silicon) | `roguedetect-macos-arm64` |
| Windows x86\_64 | `roguedetect-windows-x86_64.exe` |

Linux binaries are statically linked (musl) and have no runtime dependencies beyond libpcap.

SHA-256 checksums for each binary are published in the release notes. Verify before running:

```bash
sha256sum -c roguedetect-linux-x86_64.sha256
```

### Install script (Linux / macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/bogdanticu88/RogueDetect/main/scripts/install.sh | sh
```

If you prefer to audit the script before running it, download it first:

```bash
curl -fsSL https://raw.githubusercontent.com/bogdanticu88/RogueDetect/main/scripts/install.sh -o install.sh
# review install.sh
sh install.sh
```

### Build from source

Requires Rust 1.70 or later.

```bash
git clone https://github.com/bogdanticu88/RogueDetect
cd RogueDetect
cargo build --release
```

The binary is placed at `target/release/roguedetect`.

---

## Configuration

Copy the example config and edit it:

```bash
cp config.yaml.example config.yaml
```

```yaml
network:
  interface: auto           # or a specific interface name, use --list-interfaces to see options
  approved_macs:
    - "00:11:22:33:44:55"   # printer
    - "AA:BB:CC:DD:EE:FF"   # VoIP phone

usb:
  enabled: true
  approved_vendors:         # HID vendor IDs to suppress (keyboards, mice)
    - 0x046d                # Logitech
    - 0x05ac                # Apple
    - 0x045e                # Microsoft
    - 0x04f2                # Chicony

notifiers:
  - type: slack
    webhook: "https://hooks.slack.com/services/..."

  - type: teams
    webhook: "https://prod-xx.westus.logic.azure.com/workflows/..."

  - type: webhook
    url: "https://your-siem.internal/events"
    headers:
      Authorization: "Bearer your-token"

log:
  level: info               # debug | info | warn | error
  format: text              # text | json
```

Setting `format: json` in the log section produces structured JSON logs suitable for forwarding to a log aggregator.

**Protect your config file.** It contains webhook URLs which act as credentials. Restrict read access to the user running RogueDetect:

```bash
chmod 600 config.yaml
```

---

## Running

List available network interfaces:

```bash
roguedetect --list-interfaces
```

Start with a config file:

```bash
# Linux / macOS (requires root or cap_net_raw)
sudo roguedetect --config config.yaml

# Windows (run as Administrator)
roguedetect.exe --config config.yaml
```

On startup, RogueDetect logs the active interface and confirms both detectors have started. From that point, any unknown wired device or USB storage insertion produces a log line and fires all configured notifiers.

**Test your notifier configuration** before going live:

```bash
roguedetect --config config.yaml --dry-run
```

This sends one synthetic network event and one synthetic USB event to every configured notifier and reports success or failure for each. No detectors are started and no real traffic is captured.

---

## Running as a service

### Linux (systemd)

A unit file is included in `scripts/roguedetect.service`. To install it:

```bash
# Create a dedicated user
sudo useradd --system --no-create-home roguedetect

# Copy binary and config
sudo cp roguedetect /usr/local/bin/
sudo mkdir -p /etc/roguedetect
sudo cp config.yaml /etc/roguedetect/config.yaml
sudo chmod 600 /etc/roguedetect/config.yaml
sudo chown roguedetect:roguedetect /etc/roguedetect/config.yaml

# Grant packet capture capability so the service does not run as root
sudo setcap cap_net_raw+ep /usr/local/bin/roguedetect

# Install and start the service
sudo cp scripts/roguedetect.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now roguedetect
sudo systemctl status roguedetect
```

### Windows (service)

Use the built-in `sc` command to register roguedetect as a Windows service running as a dedicated low-privilege account. The account needs to be in the local Administrators group for npcap packet capture, or npcap can be configured to allow non-admin capture in its installer options.

```cmd
sc create RogueDetect binPath= "C:\roguedetect\roguedetect.exe --config C:\roguedetect\config.yaml" start= auto
sc start RogueDetect
```

---

## Platform notes

**MAC randomization**: modern devices randomize their MAC address on Wi-Fi by default. RogueDetect monitors DHCP traffic on wired interfaces, where MAC randomization is less common. For wireless monitoring, approved MAC lists are less reliable and the tool is better suited to wired-only environments.

**VLAN support**: untagged Ethernet and single-tag 802.1Q (0x8100) frames are supported. Double-tagged QinQ (0x88a8) frames are not currently parsed and will be skipped.

**USB blocking**: RogueDetect detects and alerts; it does not block USB devices. Enforcement (preventing a device from mounting) requires OS-level policy such as Windows Defender Device Control or udev rules on Linux.

---

## Roadmap

### v0.2

**Windows USB hotplug**: the current USB detector uses polling (every 2 seconds). Windows supports hotplug events via WMI; switching to event-driven detection would reduce latency from up to 2 seconds to near-instant.

**Full IEEE OUI database**: the current vendor lookup covers a curated list of common prefixes. Embedding the full IEEE OUI database (~40,000 entries) would give accurate vendor names for all MAC addresses.

**QinQ (802.1ad) support**: double-tagged VLAN frames used in carrier and large enterprise environments are currently skipped.

---

### v0.3

**Web dashboard**: a lightweight local web UI showing the live device inventory, alert history, and approved device management. No cloud required, runs on the same host as the detector.

**SIEM output formats**: native CEF and LEEF output for direct ingestion by Splunk, QRadar, and ArcSight without needing a custom webhook handler.

**Device persistence**: store device history in a local SQLite database so you can query what connected, when, and from which interface over time.

---

## License

MIT. See LICENSE.
