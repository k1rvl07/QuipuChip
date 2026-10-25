//! QuipuChip firmware — pure-Rust (esp-hal + embassy) boot path.
//!
//! Brings up the heap (internal DRAM + PSRAM), mounts the `vault` partition
//! through `esp-storage`, restores the vault's provisioned state, then starts
//! the USB-NCM / embassy-net / picoserve stack that serves the static SPA and
//! the auth + entries HTTP API.

#![no_std]
#![no_main]
#![feature(impl_trait_in_assoc_type)]

extern crate alloc;

use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use embassy_executor::{Spawner, task};
use embassy_net::{Ipv4Cidr, Runner, Stack, StackResources, StaticConfigV4};
use embassy_time::{Duration, Timer};
use embassy_usb::{
    Builder, UsbDevice,
    class::cdc_ncm::{
        CdcNcmClass, State as CdcNcmState,
        embassy_net::{Device, Runner as NcmRunner, State as NetState},
    },
};
use esp_backtrace as _;
use esp_bootloader_esp_idf::partitions;
use esp_hal::{
    system::Stack as CpuStack,
    timer::timg::TimerGroup,
    usb::otg::{
        Usb,
        embassy_usb_device::{Config, Driver as UsbDriver},
    },
};
use esp_storage::FlashStorage;
use picoserve::AppBuilder as AppBuilderTrait;
use static_cell::{ConstStaticCell, StaticCell};

mod authsvc;
mod device;
mod http;
mod hw;
mod mem;
mod selftest;
mod storage;
mod tls;
mod web;

use pm_core::pki::TlsMaterial;
use pm_core::vault::Vault;
use storage::VaultStorage;

use authsvc::WorkerAuth;
use hw::{EspClock, EspRng};

static WEBSERVER: StaticCell<picoserve::Router<AppRouter>> = StaticCell::new();
/// Plaintext HTTP server: only the certificate-install page and the CA
/// endpoints are reachable here, never the SPA or the API.
static INSTALL_SERVER: StaticCell<picoserve::Router<InstallRouter>> = StaticCell::new();
static SERVER_CONFIG: picoserve::Config =
    picoserve::Config::const_default().keep_connection_alive();

static CDC_NCM_STATE: StaticCell<CdcNcmState<'_>> = StaticCell::new();
static NET_STATE: StaticCell<NetState<{ ETHERNET_MTU }, 4, 4>> = StaticCell::new();
static RESOURCES: StaticCell<StackResources<NET_SOCKETS>> = StaticCell::new();

static EP_OUT_BUFFER: StaticCell<[u8; 1024]> = StaticCell::new();
static CONFIG_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
static BOS_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
static CONTROL_BUF: StaticCell<[u8; 64]> = StaticCell::new();

/// One HTTP connection per task (`picoserve` serves at most one connection per
/// `listen_and_serve`), one task per session allowed by `config::kHttpMaxSessions`.
const WEB_TASK_POOL_SIZE: usize = http::MAX_SESSIONS;
/// Connection sockets plus the DHCP server's UDP socket and the spare slot
/// `embassy-net` reserves for DNS.
// The plaintext and TLS task pools, the DHCP server socket, and two spare.
const NET_SOCKETS: usize = WEB_TASK_POOL_SIZE + tls::TLS_TASK_POOL_SIZE + 4;
const ETHERNET_MTU: usize = 1514;
const HTTP_PORT: u16 = 80;
const GW_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 7, 1);
/// Second-core stack for the auth worker. The KDF and the vault journal scan
/// need far more than the tiny default an embassy task gets.
const AUTH_WORKER_STACK: usize = 24 * 1024;
/// Idle wake-up interval for the auth worker's session-expiry tick
/// (`config::kAuthIdleCheckMs`).
const AUTH_TICK_MS: u64 = 1000;

static AUTH_STACK: ConstStaticCell<CpuStack<AUTH_WORKER_STACK>> =
    ConstStaticCell::new(CpuStack::new());

esp_bootloader_esp_idf::esp_app_desc!();

#[esp_hal::main]
#[allow(
    clippy::unwrap_used,
    reason = "boot-time spawn failures are fatal; panicking resets the device"
)]
async fn main(spawner: Spawner) -> ! {
    esp_println::logger::init_logger_from_env();
    log::info!("[pm] boot v{}", pm_core::config::FIRMWARE_VERSION);

    let peripherals = esp_hal::init(esp_hal::Config::default());

    mem::init(peripherals.PSRAM);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);

    let mac6 = device::reversed_mac6();
    match mac6 {
        Some(mac) => log::info!("device factor from MAC {mac:02x?}"),
        None => log::error!("device factor: eFuse MAC unreadable"),
    }

    // Open the vault partition directly (no filesystem) and restore state, and
    // load (or mint) the TLS material from the `tls` partition. Both are
    // resolved here because the flash peripheral is handed over exactly once.
    let flash = FlashStorage::new(peripherals.FLASH).multicore_auto_park();
    let mac = mac6.unwrap_or([0u8; 6]);
    let (mut vault, tls_config) = match open_partitions(flash) {
        Ok((store, material)) => {
            let base = store.base();
            let size = store.size();
            let mut vault = Vault::new(store, mac);
            vault.initialize();
            let snap = vault.snapshot();
            log::info!("vault: base={base:#x} size={size}");
            log::info!(
                "vault: state={}({}) provisioned={} entries={}",
                snap.state.as_str(),
                snap.state as u32,
                vault.provisioned(),
                vault.count()
            );
            let tls_config = material.as_ref().and_then(|m| {
                tls::build_config(m)
                    .inspect_err(|e| log::error!("tls: configuration failed: {e}"))
                    .ok()
            });
            (vault, tls_config)
        }
        Err(e) => {
            // The vault partition is required by `partitions.csv`; without it
            // there is nothing to serve, and a half-started stack that hangs on
            // the first auth request would be worse than refusing to boot.
            log::error!("vault: not available: {e}");
            loop {
                core::future::pending::<()>().await;
            }
        }
    };

    // Stage 4a/5 selftest gates rewrite the whole vault partition. They run
    // only when the `selftest` feature is compiled in (destructive) or the BOOT
    // button (GPIO0) is held across the sample window; in the latter case `run`
    // still refuses to touch a provisioned partition.
    if cfg!(feature = "selftest") || selftest::requested(peripherals.GPIO0) {
        log::warn!("stage 4a: selftest enabled, vault partition will be erased");
        selftest::run(&mut vault, cfg!(feature = "selftest"));
    } else {
        log::info!("selftest: not requested, vault left untouched");
    }

    let mut auth = WorkerAuth::new(EspRng::new(), EspClock);
    auth.initialize(&vault);

    // The auth worker runs on the second core so a ~2.9 s PBKDF2 cannot stall
    // the core-0 executor driving USB, the network and HTTP.
    esp_rtos::start_second_core(
        peripherals.CPU_CTRL,
        peripherals.FROM_CPU_INTR1,
        AUTH_STACK.take(),
        move || {
            static AUTH_EXECUTOR: StaticCell<esp_rtos::embassy::Executor> = StaticCell::new();
            let executor = AUTH_EXECUTOR.init(esp_rtos::embassy::Executor::new());
            executor.run(|spawner| {
                spawner.spawn(authsvc::worker(auth, vault).unwrap());
            });
        },
    );

    // On-board USB-OTG (full speed). DP => GPIO20, DM => GPIO19 on ESP32-S3.
    let usb = Usb::new_fs(peripherals.USB_FS, peripherals.GPIO20, peripherals.GPIO19);
    log::info!("usb: otg full-speed initialized");

    let driver = UsbDriver::new(usb, EP_OUT_BUFFER.init([0u8; 1024]), Config::default());

    // Device/config descriptor identity mirrors the original USB reference
    // (`PM_USB_BCD_*`, string table, remote-wakeup attribute), so the host sees
    // the same USB identity.
    let mut config = embassy_usb::Config::new(0x303A, 0x4001);
    config.bcd_usb = embassy_usb::UsbVersion::Two;
    config.device_release = 0x0100;
    config.supports_remote_wakeup = true;
    config.manufacturer = Some("QuipuChip");
    config.product = Some("QuipuChip NCM");
    config.serial_number = Some("");

    let mut usb_builder = Builder::new(
        driver,
        config,
        CONFIG_DESCRIPTOR.init([0; 256]),
        BOS_DESCRIPTOR.init([0; 256]),
        &mut [],
        CONTROL_BUF.init([0; 64]),
    );

    // MAC the host "thinks" its USB-ethernet adapter has (must not have the
    // locally-administered bit set for Android; Linux does not care).
    let host_mac_addr = [0x8A, 0x88, 0x88, 0x88, 0x88, 0x88];
    // Our device NCM MAC — matches the current firmware identity.
    let our_mac_addr = device::usb_mac6();

    let usb_cdc_ncm = CdcNcmClass::new(
        &mut usb_builder,
        CDC_NCM_STATE.init_with(CdcNcmState::new),
        host_mac_addr,
        64,
    );

    let (runner, device) = usb_cdc_ncm.into_embassy_net_device::<{ ETHERNET_MTU }, 4, 4>(
        NET_STATE.init_with(NetState::new),
        our_mac_addr,
    );

    spawner.spawn(usb_task(usb_builder.build()).unwrap());
    spawner.spawn(usb_ncm_task(runner).unwrap());

    let net_config = embassy_net::Config::ipv4_static(StaticConfigV4 {
        address: Ipv4Cidr::new(GW_IP, 24),
        gateway: Some(GW_IP),
        dns_servers: Default::default(),
    });
    let (stack, runner) = embassy_net::new(
        device,
        net_config,
        RESOURCES.init_with(StackResources::new),
        0x1234_5678,
    );
    spawner.spawn(net_task(runner).unwrap());
    spawner.spawn(run_dhcp(stack).unwrap());

    let webserver = WEBSERVER.init_with(|| AppBuilder::<false>.build_app());
    let install_server = INSTALL_SERVER.init_with(|| AppBuilder::<true>.build_app());
    for task_id in 0..WEB_TASK_POOL_SIZE {
        spawner.spawn(install_task(task_id, install_server, stack).unwrap());
    }
    spawner.spawn(auth_tick_task().unwrap());
    match tls_config {
        Some(config) => {
            for _ in 0..tls::TLS_TASK_POOL_SIZE {
                spawner.spawn(tls::tls_task(webserver, stack, config.clone()).unwrap());
            }
        }
        None => log::warn!("tls: no certificate material; HTTPS server disabled"),
    }
    log::info!("[pm] boot complete; entering idle");

    core::future::pending().await
}

/// Reads the partition table, wraps the `vault` partition as a
/// [`pm_core::vault::Storage`] and loads (or mints) the certificate material
/// from the `tls` partition.
///
/// The flash peripheral is handed over exactly once, so both partitions are
/// resolved here; the vault only takes ownership once the `tls` region has been
/// read or rewritten.
fn open_partitions(
    flash: FlashStorage<'static>,
) -> Result<(VaultStorage, Option<TlsMaterial>), &'static str> {
    let mut flash = flash;
    let mut table_buf = alloc::vec![0u8; partitions::PARTITION_TABLE_MAX_LEN];

    let (vault_base, vault_size, tls_region) = {
        let table = partitions::read_partition_table(&mut flash, &mut table_buf)
            .map_err(|_| "partition table unreadable")?;
        let vault = table
            .iter()
            .find(|e| e.label_as_str() == "vault")
            .ok_or("no `vault` partition")?;
        let tls = table
            .iter()
            .find(|e| e.label_as_str() == "tls")
            .map(|e| (e.offset(), e.len() as usize));
        (vault.offset(), vault.len() as usize, tls)
    };

    let material = if let Some((base, size)) = tls_region {
        match tls::load_or_generate(&mut flash, base, size) {
            Ok(material) => Some(material),
            Err(e) => {
                log::error!("tls: {e}; HTTPS server will be disabled");
                None
            }
        }
    } else {
        log::warn!("tls: no `tls` partition; HTTPS server will be disabled");
        None
    };

    Ok((VaultStorage::new(flash, vault_base, vault_size), material))
}

#[task]
async fn net_task(mut runner: Runner<'static, Device<'static, ETHERNET_MTU>>) -> ! {
    runner.run().await
}

/// Drives session-expiry/lockout bookkeeping in the auth worker. The worker
/// itself wakes only for commands, so period time must come from the outside.
#[task]
async fn auth_tick_task() -> ! {
    loop {
        authsvc::tick();
        Timer::after(Duration::from_millis(AUTH_TICK_MS)).await;
    }
}

#[task]
async fn usb_task(mut device: UsbDevice<'static, UsbDriver<'static>>) -> ! {
    device.run().await
}

#[task]
async fn usb_ncm_task(class: NcmRunner<'static, UsbDriver<'static>, ETHERNET_MTU>) -> ! {
    class.run().await;
}

#[task]
#[allow(
    clippy::unwrap_used,
    reason = "DHCP socket bind is boot-time; a failure is fatal"
)]
async fn run_dhcp(stack: Stack<'static>) {
    use edge_dhcp::{
        io::{self, DEFAULT_SERVER_PORT},
        server::{Server, ServerOptions},
    };
    use edge_nal::UdpBind;
    use edge_nal_embassy::{Udp, UdpBuffers};

    let ip = GW_IP;

    let mut buf = [0u8; 1500];
    let mut gw_buf = [Ipv4Addr::UNSPECIFIED];

    let buffers = UdpBuffers::<3, 1024, 1024, 10>::new();
    let unbound_socket = Udp::new(stack, &buffers);
    let mut bound_socket = unbound_socket
        .bind(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            DEFAULT_SERVER_PORT,
        )))
        .await
        .unwrap();

    loop {
        _ = io::server::run(
            &mut Server::<_, 64>::new_with_et(ip),
            &ServerOptions::new(ip, Some(&mut gw_buf)),
            &mut bound_socket,
            &mut buf,
        )
        .await
        .inspect_err(|e| log::warn!("DHCP server error: {e:?}"));
        Timer::after(Duration::from_millis(500)).await;
    }
}

#[task(pool_size = WEB_TASK_POOL_SIZE)]
async fn install_task(
    task_id: usize,
    app: &'static picoserve::Router<InstallRouter>,
    stack: Stack<'static>,
) -> ! {
    let mut tcp_rx_buffer = [0; 1024];
    let mut tcp_tx_buffer = [0; 1024];
    let mut http_buffer = [0; 2048];

    picoserve::Server::new(app, &SERVER_CONFIG, &mut http_buffer)
        .listen_and_serve(
            task_id,
            stack,
            HTTP_PORT,
            &mut tcp_rx_buffer,
            &mut tcp_tx_buffer,
        )
        .await
        .into_never()
}

/// Zero-sized picoserve app builder used to define [`AppRouter`] and
/// [`InstallRouter`]. The const parameter selects the HTTP variant: `false` is
/// the full SPA + API served over HTTPS, `true` only exposes the certificate
/// install page and the CA endpoints over plain HTTP.
pub struct AppBuilder<const INSTALL: bool>;

/// Router type of the full HTTPS application.
pub type AppRouter = <AppBuilder<false> as AppBuilderTrait>::PathRouter;

/// Router type of the certificate-install HTTP application.
pub type InstallRouter = <AppBuilder<true> as AppBuilderTrait>::PathRouter;

impl AppBuilderTrait for AppBuilder<false> {
    type PathRouter = impl picoserve::routing::PathRouter;

    fn build_app(self) -> picoserve::Router<Self::PathRouter> {
        picoserve::Router::from_service(http::Dispatcher::<false>)
    }
}

impl AppBuilderTrait for AppBuilder<true> {
    type PathRouter = impl picoserve::routing::PathRouter;

    fn build_app(self) -> picoserve::Router<Self::PathRouter> {
        picoserve::Router::from_service(http::Dispatcher::<true>)
    }
}
