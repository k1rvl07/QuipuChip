//! Thin, safe wrappers over the FreeRTOS primitives the firmware uses.
//!
//! FreeRTOS ships most of its entry points as C macros, so bindgen emits only
//! the `x*Generic*` forms. The constants bindgen cannot see are pinned here and
//! the raw calls are confined to a few methods, so the rest of the firmware
//! never spells out a queue handle by hand.

use esp_idf_svc::sys;

/// `pdTRUE`.
pub const PD_TRUE: sys::BaseType_t = 1;

/// `queueSEND_TO_BACK`.
const QUEUE_SEND_TO_BACK: sys::BaseType_t = 0;

/// `queueQUEUE_TYPE_BASE`.
const QUEUE_TYPE_BASE: u8 = 0;

/// `tskNO_AFFINITY`.
pub const TSK_NO_AFFINITY: sys::BaseType_t = 0x7FFF_FFFF;

/// `pdMS_TO_TICKS` at the tick rate this kernel is built with.
pub const fn ms_to_ticks(ms: u32) -> sys::TickType_t {
    ms * sys::configTICK_RATE_HZ / 1000
}

/// A non-blocking FreeRTOS queue of fixed-size items.
///
/// The handle is a plain pointer; the queue itself lives in the kernel. `Send`
/// and `Sync` are hand-rolled because FreeRTOS queues are safe to share across
/// tasks — that is their whole purpose — even though the raw pointer type is
/// not marked as such.
#[derive(Clone, Copy)]
pub struct Queue {
    handle: sys::QueueHandle_t,
}

// SAFETY: the FreeRTOS queue API is internally synchronised; concurrent `send`
// and `receive` from different tasks are explicitly supported.
unsafe impl Send for Queue {}
unsafe impl Sync for Queue {}

impl Queue {
    /// Wraps an already-created handle.
    pub const fn from_handle(handle: sys::QueueHandle_t) -> Self {
        Self { handle }
    }

    /// Creates a queue of `len` items of `item_size` bytes.
    pub fn create(len: u32, item_size: usize) -> Option<Self> {
        let handle = unsafe {
            sys::xQueueGenericCreate(
                len as sys::UBaseType_t,
                item_size as sys::UBaseType_t,
                QUEUE_TYPE_BASE,
            )
        };
        (!handle.is_null()).then_some(Self { handle })
    }

    /// The underlying FreeRTOS handle, for storing in FFI-owned state.
    pub const fn as_raw(&self) -> sys::QueueHandle_t {
        self.handle
    }

    pub fn is_null(&self) -> bool {
        self.handle.is_null()
    }

    /// Non-blocking send. Returns `false` when the queue is full.
    pub fn send<T>(&self, item: &T) -> bool {
        unsafe {
            sys::xQueueGenericSend(
                self.handle,
                item as *const T as *const core::ffi::c_void,
                0,
                QUEUE_SEND_TO_BACK,
            ) == PD_TRUE
        }
    }

    /// Non-blocking copy of the head without removing it.
    pub fn peek<T>(&self, out: &mut T) -> bool {
        unsafe {
            sys::xQueuePeek(self.handle, out as *mut T as *mut core::ffi::c_void, 0) == PD_TRUE
        }
    }

    /// Non-blocking removal of the head.
    pub fn receive<T>(&self, out: &mut T) -> bool {
        unsafe {
            sys::xQueueReceive(self.handle, out as *mut T as *mut core::ffi::c_void, 0) == PD_TRUE
        }
    }

    /// Number of items currently queued.
    pub fn waiting(&self) -> u32 {
        unsafe { sys::uxQueueMessagesWaiting(self.handle) }
    }
}
