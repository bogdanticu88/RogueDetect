# Changelog

All notable changes to this project will be documented here.

## [0.1.0] - 2026-04-30

### Added

- Passive DHCP snooping to detect unknown devices on wired networks
- MAC address allowlist with OUI vendor resolution
- USB storage device detection via polling (2-second interval)
- HID device suppression for approved vendor IDs
- Slack notifier (Block Kit format)
- Microsoft Teams notifier (Adaptive Card, Workflow webhook API)
- Generic JSON webhook notifier with custom headers
- Concurrent notifier dispatch with automatic one-time retry
- Structured JSON log output option
- `--list-interfaces` flag
- `--dry-run` flag for testing notifier configuration
- Cross-platform support: Linux (x86\_64, ARM64 static musl), macOS (x86\_64, Apple Silicon), Windows (x86\_64)
