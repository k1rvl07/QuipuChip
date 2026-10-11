use std::time::Duration;

use esp_idf_svc::sys;

mod auth_worker;
mod freertos;
mod http;
mod net_bridge;
mod platform;
mod static_cell;
mod usb;
mod web;

fn main() -> anyhow::Result<()> {
    sys::link_patches();
    platform::log::init();

    log::info!("PassManager (Rust) booting on ESP32-S3");
    log::info!("pm-core version: {}", pm_core::version());
    log_psram();

    let mac6 = platform::device::reversed_mac6();
    match &mac6 {
        Some(m) => log::info!(
            "device mac6 {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m[0],
            m[1],
            m[2],
            m[3],
            m[4],
            m[5]
        ),
        None => log::warn!("efuse MAC unreadable, vault disabled"),
    }

    smoke_psram_allocation();

    // Mount the web partition first: static assets are independent of the
    // vault, and a missing image is not fatal.
    match web::mount() {
        Ok(()) => {}
        Err(e) => log::warn!("web mount failed: {e}"),
    }

    // The auth worker owns the vault and runs PBKDF2 off the server task; it
    // must be up before HTTP so the first /api/auth/state request sees the
    // provisioned flag read from flash.
    if let Err(e) = auth_worker::install() {
        log::error!("auth worker install failed: {e:#}");
    }

    // USB first: it lifts the OTG domain, brings up the PHY and starts the
    // TinyUSB task. The bridge then installs the esp_netif driver; it needs the
    // NCM MAC (same usb_mac6() source) and the USB task already pumping TX.
    if usb::install() {
        log::info!("usb ready, installing net bridge");
        if net_bridge::install() {
            log::info!("net bridge up 192.168.7.1");
        } else {
            log::error!("net bridge install failed");
        }
    } else {
        log::error!("usb install failed");
    }

    if let Err(e) = http::install() {
        log::error!("http install failed: {e:#}");
    }

    loop {
        std::thread::sleep(Duration::from_secs(5));
        log::info!("alive");
    }
}

fn log_psram() {
    let total = platform::psram::spiram_total();
    let free = platform::psram::spiram_free();
    let largest = platform::psram::spiram_largest();
    log::info!(
        "psram total {} MB free {} MB largest {} KB",
        total >> 20,
        free >> 20,
        largest >> 10
    );
}

/// Confirms a ~1 MiB allocation lands in external RAM. The entries working set
/// is this size, and it must not come out of the scarce internal heap.
fn smoke_psram_allocation() {
    let mut big = vec![0u8; 1 << 20];
    let last = big.len() - 1;
    big[0] = 0xA5;
    big[last] = 0x5A;
    let external = platform::psram::is_external(big.as_ptr());
    log::info!("1 MiB allocation in PSRAM: {}", external as u8);
}
