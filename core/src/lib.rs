//! Portable core for the PassManager firmware.
//!
//! Everything here must build and be testable on the host, without any ESP-IDF
//! or hardware dependency. Board-specific code lives in the `firmware-embassy`
//! crate.
//!
//! The formats implemented here are byte-compatible with the C++ reference that
//! preceded this port: the on-flash vault (PMV1) and the export container
//! (PMX1), plus the crypto and password/totp primitives. That C++ implementation
//! was removed from the tree and is recoverable only from git history.
//!
//! The crate is `no_std` on device and needs only `alloc`; host builds compile
//! it with `std` (see `cfg_attr` below) so the test harness keeps working.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod auth;
pub mod base64;
pub mod config;
pub mod crypto;
pub mod device;
pub mod entry;
pub mod export;
pub mod hex;
pub mod password;
pub mod rand;
pub mod totp;
pub mod types;
pub mod vault;
pub mod wordlist;

#[cfg(any(test, feature = "test-utils"))]
pub mod testutil;

/// Returns the current firmware version string reported over the API.
#[must_use]
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
        use crate::wordlist::{WORD_BYTES, WORD_COUNT, WORD_STRIDE, WORDS, word};
        assert_eq!(WORD_COUNT, 4096);
        assert_eq!(WORD_BYTES, 5);
        assert_eq!(WORD_STRIDE, 6);
        assert_eq!(WORDS.len(), WORD_COUNT * WORD_STRIDE);
        for i in 0..WORD_COUNT {
            let w = word(i);
            assert_eq!(w.len(), WORD_BYTES);
            assert!(w.iter().all(u8::is_ascii_lowercase));
            assert_eq!(WORDS[i * WORD_STRIDE + WORD_BYTES], 0);
        }
    }
}
