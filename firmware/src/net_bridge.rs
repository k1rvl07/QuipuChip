//! Ethernet-over-USB bridge: an esp_netif driver fed by the TinyUSB NCM stack.
//!
//! The C++ reference kept every piece of bridge state in `static` globals and
//! mutated them from the lwIP/TinyUSB callbacks. Here the same state lives in
//! atomics and one `StaticCell`, and the only `unsafe` left is the thin
//! boundary where a raw esp_netif handle is turned back into our `Device`.

use core::ffi::{c_void, CStr};
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicU32, Ordering};
use std::sync::Mutex;

use esp_idf_svc::sys;
use sys::esp_err_t;

use crate::freertos::Queue;
use crate::platform;
use crate::static_cell::StaticCell;

/// Ethernet MTU (1500) plus framing headroom. Matches `net_bridge.cpp::kFrameBuf`.
const FRAME_BUF: usize = 1600;

/// Depth of the lwIP -> TinyUSB TX queue. Matches `kTxQueueLen`.
const TX_QUEUE_LEN: u32 = 16;

const SERVER_IP: &CStr = c"192.168.7.1";
const NETMASK: &CStr = c"255.255.255.0";
const IF_KEY: &CStr = c"NCM_DEF";
const IF_DESC: &CStr = c"ncm";

/// An outgoing Ethernet frame owned by the bridge between lwIP and TinyUSB.
#[repr(C)]
struct TxItem {
    data: *mut u8,
    len: usize,
}

/// The handle esp_netif hands back to our driver callbacks.
///
/// `base` must be the first field: esp_netif calls `post_attach` by jumping to
/// the function pointer at offset 0 of the handle, so anything else in front of
/// it would be interpreted as code.
#[repr(C)]
struct Device {
    base: sys::esp_netif_driver_base_t,
    tx_queue: sys::QueueHandle_t,
}

/// Bridge counters, published as one snapshot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    pub rx_frames: u32,
    pub tx_frames: u32,
    pub rx_bytes: u32,
    pub tx_bytes: u32,
    pub tx_dropped: u32,
}

// The driver handle. Its address is published to esp_netif and must stay put
// for the lifetime of the program, hence a static rather than a box. It is
// written during the single-threaded install() and read from the driver
// callbacks afterwards.
static DEVICE: StaticCell<Device> = StaticCell::new(Device {
    base: sys::esp_netif_driver_base_t {
        post_attach: Some(post_attach_c),
        netif: core::ptr::null_mut(),
    },
    tx_queue: core::ptr::null_mut(),
});

/// The attached netif, published by `post_attach_c` and consumed by `on_frame`/`ip`.
static NETIF: AtomicPtr<sys::esp_netif_t> = AtomicPtr::new(core::ptr::null_mut());

/// Stable home for the inherent config's `ip_info`; esp_netif keeps the pointer.
static IP_INFO: StaticCell<sys::esp_netif_ip_info_t> = StaticCell::new(sys::esp_netif_ip_info_t {
    ip: sys::esp_ip4_addr_t { addr: 0 },
    netmask: sys::esp_ip4_addr_t { addr: 0 },
    gw: sys::esp_ip4_addr_t { addr: 0 },
});

static RX_FRAMES: AtomicU32 = AtomicU32::new(0);
static TX_FRAMES: AtomicU32 = AtomicU32::new(0);
static RX_BYTES: AtomicU32 = AtomicU32::new(0);
static TX_BYTES: AtomicU32 = AtomicU32::new(0);
static TX_DROPPED: AtomicU32 = AtomicU32::new(0);
static DHCP_STARTED: AtomicBool = AtomicBool::new(false);
static NETIF_UP: AtomicBool = AtomicBool::new(false);

/// Where install() stopped, and the esp_err_t it saw. Kept for the periodic
/// status line, because install()'s own errors happen before the USB task logs.
static STEP: Mutex<&'static str> = Mutex::new("none");
static LAST_ERR: AtomicI32 = AtomicI32::new(sys::ESP_OK);

/// Address of the driver handle as an opaque esp_netif handle.
fn device_ptr() -> *mut Device {
    DEVICE.get()
}

fn set_step(step: &'static str) {
    *STEP.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = step;
}

fn fail(step: &'static str, err: esp_err_t) {
    set_step(step);
    LAST_ERR.store(err, Ordering::Relaxed);
    log::error!("netif: failed at {} err {}", step, err);
}

/// Allocates a frame buffer from PSRAM, where the entry working set belongs.
fn alloc_frame(len: usize) -> *mut u8 {
    unsafe { sys::heap_caps_malloc(len, sys::MALLOC_CAP_SPIRAM | sys::MALLOC_CAP_8BIT) }.cast()
}
fn free_frame(ptr: *mut u8) {
    unsafe { sys::heap_caps_free(ptr.cast()) };
}

/// lwIP -> USB. Runs on the TCP/IP task, so it must never block.
extern "C" fn transmit_c(h: *mut c_void, buffer: *mut c_void, len: usize) -> esp_err_t {
    if h.is_null() || buffer.is_null() || len == 0 || len > FRAME_BUF {
        TX_DROPPED.fetch_add(1, Ordering::Relaxed);
        return sys::ESP_OK;
    }

    // Bound to a single frame sized by the caller; lwIP reuses its buffer as
    // soon as we return, so the copy has to survive until TinyUSB drains it.
    let queue = Queue::from_handle(unsafe { (*h.cast::<Device>()).tx_queue });
    if queue.is_null() {
        TX_DROPPED.fetch_add(1, Ordering::Relaxed);
        return sys::ESP_OK;
    }

    let copy = alloc_frame(len);
    if copy.is_null() {
        TX_DROPPED.fetch_add(1, Ordering::Relaxed);
        return sys::ESP_OK;
    }
    unsafe { core::ptr::copy_nonoverlapping(buffer.cast::<u8>(), copy, len) };

    let item = TxItem { data: copy, len };
    // No wait: the TCP/IP task must not stall behind a busy USB. A dropped
    // frame is cheaper than a blocked stack; TCP will retransmit.
    if !queue.send(&item) {
        free_frame(copy);
        TX_DROPPED.fetch_add(1, Ordering::Relaxed);
        return sys::ESP_OK;
    }
    crate::usb::wake();
    sys::ESP_OK
}

extern "C" fn free_rx_buffer_c(_h: *mut c_void, buffer: *mut c_void) {
    if !buffer.is_null() {
        unsafe { sys::heap_caps_free(buffer) };
    }
}

/// Called by esp_netif_attach via the function pointer at offset 0 of our handle.
extern "C" fn post_attach_c(
    netif: *mut sys::esp_netif_t,
    h: sys::esp_netif_iodriver_handle,
) -> esp_err_t {
    if h.is_null() {
        return sys::ESP_FAIL;
    }
    unsafe { (*h.cast::<Device>()).base.netif = netif };
    NETIF.store(netif, Ordering::Release);
    log::info!("netif: attached ncm");
    sys::ESP_OK
}

/// USB -> lwIP. `data` points at TinyUSB's receive buffer, so it is copied
/// before handing the frame to esp_netif, which frees it via `free_rx_buffer_c`.
pub fn on_frame(data: &[u8]) -> bool {
    RX_FRAMES.fetch_add(1, Ordering::Relaxed);
    RX_BYTES.fetch_add(data.len() as u32, Ordering::Relaxed);

    let netif = NETIF.load(Ordering::Acquire);
    if netif.is_null() {
        return false;
    }
    if data.len() > FRAME_BUF {
        TX_DROPPED.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    let copy = alloc_frame(data.len());
    if copy.is_null() {
        TX_DROPPED.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), copy, data.len()) };
    let rc = unsafe {
        sys::esp_netif_receive(
            netif,
            copy.cast::<c_void>(),
            data.len(),
            core::ptr::null_mut(),
        )
    };
    rc == sys::ESP_OK
}

/// Drains queued frames into TinyUSB. Runs on the USB task only, because
/// `tud_network_xmit` touches DCD state owned by that task.
pub fn pump() {
    let queue = Queue::from_handle(unsafe { (*device_ptr()).tx_queue });
    if queue.is_null() {
        return;
    }

    let mut item = TxItem {
        data: core::ptr::null_mut(),
        len: 0,
    };
    loop {
        // Peek, not receive: the NCM transfer block is finite and when it is
        // full the frame has to wait rather than vanish. It became available
        // from lwIP exactly once; there is no way to fetch it again.
        if !queue.peek(&mut item) {
            return;
        }
        if item.data.is_null() || item.len == 0 {
            let _ = queue.receive(&mut item);
            free_frame(item.data);
            continue;
        }
        if !unsafe { sys::pm_tinyusb::tud_network_can_xmit(item.len as u16) } {
            return;
        }
        if !queue.receive(&mut item) {
            return;
        }
        unsafe { sys::pm_tinyusb::tud_network_xmit(item.data.cast(), item.len as u16) };
        free_frame(item.data);
        TX_FRAMES.fetch_add(1, Ordering::Relaxed);
        TX_BYTES.fetch_add(item.len as u32, Ordering::Relaxed);
    }
}

pub fn stats() -> Stats {
    Stats {
        rx_frames: RX_FRAMES.load(Ordering::Relaxed),
        tx_frames: TX_FRAMES.load(Ordering::Relaxed),
        rx_bytes: RX_BYTES.load(Ordering::Relaxed),
        tx_bytes: TX_BYTES.load(Ordering::Relaxed),
        tx_dropped: TX_DROPPED.load(Ordering::Relaxed),
    }
}

pub fn dhcp_started() -> bool {
    DHCP_STARTED.load(Ordering::Relaxed)
}

pub fn netif_up() -> bool {
    NETIF_UP.load(Ordering::Relaxed)
}

pub fn last_step() -> &'static str {
    *STEP.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub fn last_error() -> esp_err_t {
    LAST_ERR.load(Ordering::Relaxed)
}

/// Splits a network-order IPv4 address into octets. On the little-endian
/// Xtensa core the low byte is the first octet (as in `net_bridge.cpp`).
fn ip4_to_octets(addr: u32) -> [u8; 4] {
    [
        (addr & 0xFF) as u8,
        ((addr >> 8) & 0xFF) as u8,
        ((addr >> 16) & 0xFF) as u8,
        ((addr >> 24) & 0xFF) as u8,
    ]
}

/// Reads the address currently on the interface. `None` before attach.
pub fn ip() -> Option<[u8; 4]> {
    let netif = NETIF.load(Ordering::Acquire);
    if netif.is_null() {
        return None;
    }
    let mut now = sys::esp_netif_ip_info_t::default();
    if unsafe { sys::esp_netif_get_ip_info(netif, &mut now) } != sys::ESP_OK {
        return None;
    }
    Some(ip4_to_octets(now.ip.addr))
}

/// Number of frames waiting for the USB task, or `u32::MAX` before install.
pub fn tx_queue_waiting() -> u32 {
    let queue = Queue::from_handle(unsafe { (*device_ptr()).tx_queue });
    if queue.is_null() {
        return u32::MAX;
    }
    queue.waiting()
}

fn str_to_ip4(s: &CStr, dst: *mut sys::esp_ip4_addr_t) -> esp_err_t {
    unsafe { sys::esp_netif_str_to_ip4(s.as_ptr(), dst) }
}

/// Brings up the esp_netif driver and its DHCP server. Must run after
/// `usb::install()`, which has already started pumping the TinyUSB task.
pub fn install() -> bool {
    let mac = platform::device::usb_mac6();

    let queue = match Queue::create(TX_QUEUE_LEN, core::mem::size_of::<TxItem>()) {
        Some(q) => q,
        None => {
            fail("tx_queue", sys::ESP_ERR_NO_MEM);
            return false;
        }
    };
    unsafe { (*device_ptr()).tx_queue = queue.as_raw() };

    let ip_info = IP_INFO.get();
    // SAFETY: `ip_info` is the static's own address; the three fields are disjoint.
    let ip_ptr = unsafe { core::ptr::addr_of_mut!((*ip_info).ip) };
    let gw_ptr = unsafe { core::ptr::addr_of_mut!((*ip_info).gw) };
    let mask_ptr = unsafe { core::ptr::addr_of_mut!((*ip_info).netmask) };
    if str_to_ip4(SERVER_IP, ip_ptr) != sys::ESP_OK
        || str_to_ip4(SERVER_IP, gw_ptr) != sys::ESP_OK
        || str_to_ip4(NETMASK, mask_ptr) != sys::ESP_OK
    {
        fail("parse_ip", sys::ESP_ERR_INVALID_ARG);
        return false;
    }

    let mut base_cfg = sys::esp_netif_inherent_config_t {
        // AUTOUP: bring the interface up on attach. DHCP_SERVER: the host gets
        // the address, not us. GARP: announce our MAC on bring-up.
        flags: sys::esp_netif_flags_ESP_NETIF_FLAG_AUTOUP
            | sys::esp_netif_flags_ESP_NETIF_DHCP_SERVER
            | sys::esp_netif_flags_ESP_NETIF_FLAG_GARP,
        ..Default::default()
    };
    base_cfg.mac.copy_from_slice(&mac);
    // The pointer must outlive esp_netif_new(): the DHCP server reads its
    // address from here, so it points at the static, not a local.
    base_cfg.ip_info = ip_info;
    base_cfg.if_key = IF_KEY.as_ptr();
    base_cfg.if_desc = IF_DESC.as_ptr();
    base_cfg.route_prio = 20;
    base_cfg.bridge_info = core::ptr::null_mut();

    // esp_netif_init() is idempotent; INVALID_STATE means the Arduino core
    // already did it, which is not an error here.
    let err = unsafe { sys::esp_netif_init() };
    if err != sys::ESP_OK && err != sys::ESP_ERR_INVALID_STATE {
        fail("netif_init", err);
        return false;
    }

    let drv_cfg = sys::esp_netif_driver_ifconfig_t {
        handle: device_ptr().cast(),
        transmit: Some(transmit_c),
        driver_free_rx_buffer: Some(free_rx_buffer_c),
        ..Default::default()
    };

    let netif_cfg = sys::esp_netif_config_t {
        base: core::ptr::addr_of!(base_cfg),
        driver: core::ptr::addr_of!(drv_cfg),
        stack: unsafe { sys::_g_esp_netif_netstack_default_eth },
    };
    let netif = unsafe { sys::esp_netif_new(core::ptr::addr_of!(netif_cfg)) };
    if netif.is_null() {
        fail("netif_new", sys::ESP_FAIL);
        return false;
    }
    NETIF.store(netif, Ordering::Release);

    let err = unsafe { sys::esp_netif_set_driver_config(netif, core::ptr::addr_of!(drv_cfg)) };
    if err != sys::ESP_OK {
        fail("driver_cfg", err);
        return false;
    }

    let err = unsafe { sys::esp_netif_attach(netif, device_ptr().cast()) };
    if err != sys::ESP_OK {
        fail("attach", err);
        return false;
    }

    // ESP_NETIF_FLAG_AUTOUP only takes effect inside action_start(), which the
    // core normally triggers on an IO-driver start event. We have no such
    // driver, so the call is made directly. It also starts the DHCP server,
    // which is why the explicit dhcps_start below may report ALREADY_STARTED.
    unsafe {
        sys::esp_netif_action_start(
            netif.cast(),
            core::ptr::null(),
            sys::ESP_EVENT_ANY_ID,
            core::ptr::null_mut(),
        )
    };

    let err = unsafe { sys::esp_netif_dhcps_start(netif) };
    if err != sys::ESP_OK && err != sys::ESP_ERR_ESP_NETIF_DHCP_ALREADY_STARTED {
        fail("dhcps", err);
        return false;
    }
    DHCP_STARTED.store(true, Ordering::Relaxed);
    set_step("ok");
    LAST_ERR.store(sys::ESP_OK, Ordering::Relaxed);

    // Read the address back: the base config's ip_info could have been ignored,
    // in which case "up 192.168.7.1" would be a lie.
    let mut got = sys::esp_netif_ip_info_t::default();
    if unsafe { sys::esp_netif_get_ip_info(netif, &mut got) } == sys::ESP_OK {
        unsafe { *IP_INFO.get() = got };
    }
    NETIF_UP.store(
        unsafe { sys::esp_netif_is_netif_up(netif) },
        Ordering::Relaxed,
    );

    let addr = ip4_to_octets(unsafe { (*IP_INFO.get()).ip.addr });
    log::info!(
        "netif: ncm lwip_up {}",
        NETIF_UP.load(Ordering::Relaxed) as u8
    );
    log::info!(
        "netif: ncm up {}.{}.{}.{} dhcp on mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        addr[0],
        addr[1],
        addr[2],
        addr[3],
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5]
    );
    true
}
