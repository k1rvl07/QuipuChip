//! Board-specific services for the Rust firmware: flash storage, PSRAM, time
//! and logging. Everything here talks to ESP-IDF; the portable logic lives in
//! `pm-core`.

pub mod device;
pub mod log;
pub mod psram;
pub mod storage;
pub mod time;
