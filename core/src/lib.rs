//! Portable core for the PassManager firmware.
//!
//! Everything here must build and be testable on the host, without any ESP-IDF
//! or hardware dependency. Board-specific code lives in the `pm-firmware` crate.
//!
//! The formats implemented here are byte-compatible with the C++ reference in
//! `src/` and `include/`: the on-flash vault (PMV1) and the export container
//! (PMX1), plus the crypto and password/totp primitives.
//!
//! The crate is `no_std` on device and needs only `alloc`; host builds compile
//! it with `std` (see `cfg_attr` below) so the test harness keeps working.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod auth;
pub mod config;
pub mod crypto;
pub mod device;
pub mod entry;
pub mod export;
pub mod password;
pub mod rand;
pub mod totp;
pub mod vault;
pub mod wordlist;

/// Returns the current firmware version string reported over the API.
pub const fn version() -> &'static str {
    config::FIRMWARE_VERSION
}

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_defined() {
        assert!(!super::version().is_empty());
    }

    #[test]
    fn wordlist_shape_and_terminators() {
        use crate::wordlist::{word, WORDS, WORD_BYTES, WORD_COUNT, WORD_STRIDE};
        assert_eq!(WORD_COUNT, 4096);
        assert_eq!(WORD_BYTES, 5);
        assert_eq!(WORD_STRIDE, 6);
        assert_eq!(WORDS.len(), WORD_COUNT * WORD_STRIDE);
        for i in 0..WORD_COUNT {
            let w = word(i);
            assert_eq!(w.len(), WORD_BYTES);
            assert!(w.iter().all(|b| b.is_ascii_lowercase()));
            assert_eq!(WORDS[i * WORD_STRIDE + WORD_BYTES], 0);
        }
    }
}
