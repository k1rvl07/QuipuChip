# QuipuChip

QuipuChip is an offline, air-gapped-friendly password manager that runs entirely on an ESP32-S3. It exposes a local HTTPS web interface over USB-NCM and keeps your vault encrypted on the device's flash with no external dependencies or cloud sync.

## Features

- **Fully offline** — All data and cryptography stay on the device
- **Web UI over USB-NCM** — Connect via USB and access `https://192.168.7.1/` in your browser
- **Strong encryption** — Vault encrypted with your master password and optional key file
- **Master password generation** — On-device 38-character passphrase from a curated wordlist
- **Key file support** — Use a key file alone or together with a master password. Can be generated on-device or supplied
- **TOTP** — Store TOTP secrets per entry with live codes, configurable digits/period
- **Import/Export** — Protected JSON export/import and KeePass `.kdbx` import/export
- **Rekey** — Change master password and/or key file independently without losing entries
- **Device reset** — Reset from the lock screen if the master password is lost (destroys vault)
- **Self-signed TLS** — On-device CA/leaf certificates with an easy install page
- **Brute-force protection** — Lockout after failed unlock attempts
- **Session-based auth** — Token auth for the web UI

## Hardware

- **MCU:** ESP32-S3 (tested with ESP32-S3-DevKitC-1 class boards)
- **Connection:** USB (appears as `303a:4001 QuipuChip NCM`)
- **Network:** USB-NCM provides `192.168.7.50/24` to host, device is `192.168.7.1`

## Project structure

```text
QuipuChip/
├── core/       # pm-core — no_std portable core (vault, crypto, auth, TOTP, PKI)
├── firmware/   # ESP32-S3 firmware (esp-hal, embassy, picoserve, USB-NCM)
├── data/       # Embedded web UI (HTML/CSS/JS) served by the device
├── scripts/    # Build/test/helper scripts
├── tests/      # Integration tests
└── partitions.csv
```

## Building

### Prerequisites

- [Rust](https://rustup.rs/) with `xtensa` target support via [`espup`](https://github.com/esp-rs/espup)
- [`espflash`](https://github.com/esp-rs/espflash) for flashing
- [`cargo`](https://doc.rust-lang.org/cargo/)

### Core tests

Run the portable core tests on host:

```bash
cargo test -p pm-core
```

### Firmware build

```bash
cd firmware
cargo build --release
```

The binary will be produced at:

```text
target/xtensa-esp32s3-none-elf/release/firmware
```

### Flash

```bash
espflash flash --monitor target/xtensa-esp32s3-none-elf/release/firmware
```

## Usage

1. **Connect** — Plug the ESP32-S3 into your computer via USB
2. **Install CA** — Open `http://192.168.7.1/install.html` and follow instructions to trust the `QuipuChip CA` certificate
3. **Open UI** — Go to `https://192.168.7.1/`
4. **Setup** — On first boot create a vault. You'll be shown the master password **once** — save it securely
5. **Use** — Add entries, generate/manage TOTP codes, import from KeePass, or export your vault

## Security notes

- **No cloud** — Everything runs locally on the device
- **Keys don't leave** — Master password, key file, and decrypted data stay on-device
- **One-time secrets** — Master password and generated key files are shown/downloaded once
- **Physical access matters** — If someone gains physical access and knows/guesses the master password they can access the unlocked vault
- **eFuse/secure boot** — By default Flash Encryption and Secure Boot are not enabled. See [`AGENTS.md`](AGENTS.md) for strict rules around irreversible operations
- **CA changes** — Erasing the `tls` partition regenerates the CA and requires re-trusting

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.
