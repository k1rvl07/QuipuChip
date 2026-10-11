use core::ffi::{c_char, c_void, CStr};
use core::sync::atomic::{AtomicPtr, Ordering};
use std::ptr;

use esp_idf_svc::sys;

use crate::freertos::{ms_to_ticks, PD_TRUE, TSK_NO_AFFINITY};
use crate::{net_bridge, platform};

pub const MAC_LEN: usize = 6;

/// USB identity, mirroring `config::kUsbVid` / `config::kUsbPid`. The C bridge
/// carries the authoritative descriptor values; these are only for the boot log.
pub const USB_VID: u16 = 0x303A;
pub const USB_PID: u16 = 0x4001;

/// Byte size of the usb device task stack. ESP-IDF measures xTaskCreate stack
/// depth in bytes (`StackType_t` is a byte here), so this mirrors
/// `config::kUsbTaskStackWords` from the reference one-for-one.
const USB_TASK_STACK_BYTES: u32 = 8192;

/// Handle of the TinyUSB task, published by `install()` and consumed by
/// `wake()`. Null until the task exists.
static USB_TASK: AtomicPtr<sys::tskTaskControlBlock> = AtomicPtr::new(ptr::null_mut());

/// Provided to the C bridge as `pm_usb_log`; routes descriptor/mount chatter
/// through the Rust logger so it lands in the same UART stream.
#[no_mangle]
pub extern "C" fn pm_usb_log(msg: *const c_char) {
    unsafe {
        if msg.is_null() {
            return;
        }
        if let Ok(s) = CStr::from_ptr(msg).to_str() {
            log::info!("{}", s);
        }
    }
}

/// Provided to the C bridge as `pm_net_on_frame`. Copied by net_bridge, so the
/// borrow of TinyUSB's receive buffer is not retained past this call.
#[no_mangle]
pub extern "C" fn pm_net_on_frame(src: *const u8, size: u16) -> bool {
    net_bridge::on_frame(unsafe { core::slice::from_raw_parts(src, size as usize) })
}

fn reversed_mac_bytes() -> [u8; MAC_LEN] {
    platform::device::usb_mac6()
}

/// Wake the USB task when lwIP queues a frame for the host.
pub fn wake() {
    let task = USB_TASK.load(Ordering::Relaxed);
    if task.is_null() {
        return;
    }
    unsafe {
        sys::xTaskGenericNotify(task, 0, 0, sys::eNotifyAction_eIncrement, ptr::null_mut());
    }
}

extern "C" fn usb_task(_arg: *mut c_void) {
    let mut next_log = unsafe { sys::xTaskGetTickCount() };
    const LOG_PERIOD_TICKS: sys::TickType_t = sys::configTICK_RATE_HZ; // 1 s

    loop {
        // Frames lwIP handed to the bridge are pushed to the host here:
        // tud_network_xmit() touches DCD state owned solely by this task.
        net_bridge::pump();

        // Non-blocking drain of the TinyUSB event queue. Waiting is our own
        // job: ulTaskGenericNotifyTake below wakes on a frame from lwIP
        // (usb::wake()) or on the 10 ms ceiling.
        unsafe { sys::pm_tinyusb::tud_task_ext(0, false) };

        unsafe {
            sys::ulTaskGenericNotifyTake(0, PD_TRUE, ms_to_ticks(10));
        }

        let now = unsafe { sys::xTaskGetTickCount() };
        if (now.wrapping_sub(next_log) as i32) < 0 {
            continue;
        }
        next_log = now.wrapping_add(LOG_PERIOD_TICKS);
        log_status();
    }
}

fn log_status() {
    let s = net_bridge::stats();
    let ip = net_bridge::ip().unwrap_or([0, 0, 0, 0]);
    let q = net_bridge::tx_queue_waiting();
    let ps = platform::psram::spiram_free();
    let ih = platform::psram::dram_free();
    log::info!(
        "ncm rx {} f/{} B tx {} f/{} B drop {} | link {} dhcp {} up {} step {}/{} ip {}.{}.{}.{} | q {} ps {} ih {}",
        s.rx_frames,
        s.rx_bytes,
        s.tx_frames,
        s.tx_bytes,
        s.tx_dropped,
        unsafe { sys::pm_tinyusb::pm_usb_link() } as u8,
        net_bridge::dhcp_started() as u8,
        net_bridge::netif_up() as u8,
        net_bridge::last_step(),
        net_bridge::last_error(),
        ip[0],
        ip[1],
        ip[2],
        ip[3],
        q,
        ps,
        ih
    );
}

pub fn install() -> bool {
    use sys::pm_tinyusb as pm_tusb;

    let mac = reversed_mac_bytes();
    unsafe {
        pm_tusb::pm_usb_set_mac(mac.as_ptr());
        pm_tusb::pm_usb_release_domain();
    }

    let mut phy_handle: pm_tusb::usb_phy_handle_t = ptr::null_mut();
    // Zeroed config is the documented default: controller = OTG, target = INT,
    // mode = default (device), speed = auto. Matches the reference
    // tinyusb_driver_install(external_phy = false) path.
    let phy_config =
        unsafe { core::mem::MaybeUninit::<pm_tusb::usb_phy_config_t>::zeroed().assume_init() };
    let rc_new =
        unsafe { pm_tusb::usb_new_phy(&phy_config as *const _, &mut phy_handle as *mut _) };
    if rc_new != sys::ESP_OK {
        log::error!("usb: usb_new_phy failed {}", rc_new);
        return false;
    }

    // Force the OTG session/ID control signals the internal PHY does not drive
    // (the reference configure_pins() step). Without this the controller never
    // pulls D+ up and the host sees no device.
    unsafe { pm_tusb::pm_usb_route_pins() };

    if !unsafe { pm_tusb::tusb_init() } {
        log::error!("usb: tusb_init returned false");
        return false;
    }

    let name = b"usb_dev\0";
    let mut task: sys::TaskHandle_t = ptr::null_mut();
    let created = unsafe {
        sys::xTaskCreatePinnedToCore(
            Some(usb_task),
            name.as_ptr() as *const c_char,
            USB_TASK_STACK_BYTES,
            ptr::null_mut(),
            sys::configMAX_PRIORITIES - 1,
            &mut task,
            TSK_NO_AFFINITY,
        )
    };
    if created != PD_TRUE {
        log::error!("usb: task create failed");
        return false;
    }
    USB_TASK.store(task, Ordering::Release);

    log::info!(
        "usb: ncm {:04x}:{:04x} mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} stk {}",
        USB_VID,
        USB_PID,
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5],
        USB_TASK_STACK_BYTES
    );
    true
}
