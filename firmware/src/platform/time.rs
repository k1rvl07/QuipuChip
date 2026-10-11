//! Wall/monotonic clock. `now_ms()` mirrors the C++ `millis()`: milliseconds
//! since boot, wrapping as `u32` after ~49.7 days (the auth lockout logic is
//! built to tolerate that wrap).

use esp_idf_svc::sys;
use pm_core::auth::Clock;

/// Milliseconds since boot, truncated to `u32` like `millis()`.
pub fn now_ms() -> u32 {
    (unsafe { sys::esp_timer_get_time() } / 1000) as u32
}

/// `pm-core::auth::Clock` backed by the hardware timer.
#[allow(dead_code)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u32 {
        now_ms()
    }
}
