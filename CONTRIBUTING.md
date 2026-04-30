# Contributing

## Before you start

Check the open issues to avoid duplicating work. For significant changes, open an issue first to discuss the approach.

## Development setup

```bash
git clone https://github.com/bogdanticu88/RogueDetect
cd RogueDetect
cargo build
cargo test
```

**Linux / macOS**: requires `libpcap` and `libusb` installed (see README Requirements).

**Windows**: requires npcap and the npcap SDK at `C:\npcap-sdk` (see README Requirements).

## Running the linter

```bash
cargo clippy -- -D warnings
cargo fmt --check
```

## Running tests

```bash
cargo test
```

Tests that require hardware (live USB or network) are not included in the automated suite. The test suite covers config parsing, MAC normalisation, DHCP packet parsing, and OUI lookups.

## Submitting a pull request

1. Fork the repo and create a branch off `main`.
2. Make your changes. Add tests for any new logic.
3. Run `cargo test` and `cargo clippy -- -D warnings` and ensure both pass cleanly.
4. Open a PR against `main` with a clear description of what changes and why.

## What is welcome

- Bug fixes
- Additional OUI entries
- Additional notifier backends
- Improved DHCP parsing (QinQ support, option coverage)
- Windows USB hotplug via WMI
- Test coverage improvements

## What to discuss first

- Changes to the config schema (backwards compatibility matters)
- New external dependencies
- Anything that requires root/kernel privileges beyond what is already used
