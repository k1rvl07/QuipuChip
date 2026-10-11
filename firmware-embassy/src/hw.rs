//! Board adapters for the portable `pm-core` traits: a hardware RNG and a
//! monotonic clock.

use esp_hal::rng::Rng;
use pm_core::auth::Clock;
use pm_core::rand::RandomSource;

/// `esp_fill_random` equivalent, wrapping esp-hal's true RNG.
pub struct EspRng(Rng);

impl EspRng {
    pub fn new() -> Self {
        Self(Rng::new())
    }
}

impl RandomSource for EspRng {
    fn fill(&mut self, buf: &mut [u8]) {
        self.0.read(buf);
    }
}

/// Milliseconds since boot, from the embassy timer. Wrapping is expected and
/// handled by the sign-aware arithmetic in `pm-core::auth`.
pub struct EspClock;

impl Clock for EspClock {
    fn now_ms(&self) -> u32 {
        now_ms()
    }
}

/// Milliseconds since boot, from the embassy timer.
pub fn now_ms() -> u32 {
    embassy_time::Instant::now().as_millis() as u32
}
