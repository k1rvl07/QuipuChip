//! Master-password generation, ported from `auth.cpp`
//! (`randomWordIndex` / `randomDigit` / `generatePassword`).
//!
//! Layout: six dictionary words of 5 letters joined by `-`, then a final `-`
//! and two decimal digits, e.g. `abcde-fghij-...-vwxyz-42` (38 chars).
//!
//! The word index is `u32_le >> 20`: 4096 = 2^12, so the top 12 bits are a
//! uniform index and **no** rejection is needed (adding `% 4096` would bias the
//! distribution). Digits *do* reject: `256 % 10 != 0`, so values `250..=255` are
//! dropped, with a hard attempt cap so a degenerate source cannot hang.

use alloc::string::String;

use crate::config::{
    MASTER_DIGITS, MASTER_PASSWORD_CHARS, MASTER_WORD_BYTES, MASTER_WORDS, MAX_DIGIT_ATTEMPTS,
};
use crate::rand::RandomSource;
use crate::wordlist::word;

/// Uniform word index in `0..4096` from four random bytes (little-endian).
pub fn random_word_index(src: &mut impl RandomSource) -> usize {
    let mut b = [0u8; 4];
    src.fill(&mut b);
    let v = u32::from_le_bytes(b);
    (v >> 20) as usize
}

/// Uniform digit `0..=9`. After `MAX_DIGIT_ATTEMPTS` rejections, falls back to
/// the last rejected byte (biased, but an explicit refusal to spin forever).
pub fn next_digit(src: &mut impl RandomSource) -> u8 {
    let mut b = [0u8; 1];
    let mut last = 0u8;
    for _ in 0..MAX_DIGIT_ATTEMPTS {
        src.fill(&mut b);
        last = b[0];
        if last < 250 {
            return last % 10;
        }
    }
    last % 10
}

/// Builds a master password. The length is fixed by construction, so the C++
/// "layout broke" guard becomes a debug assertion here.
pub fn generate_password(src: &mut impl RandomSource) -> [u8; MASTER_PASSWORD_CHARS] {
    let mut out = [0u8; MASTER_PASSWORD_CHARS];
    let mut n = 0usize;
    for w in 0..MASTER_WORDS {
        if w != 0 {
            out[n] = b'-';
            n += 1;
        }
        let idx = random_word_index(src);
        out[n..n + MASTER_WORD_BYTES].copy_from_slice(word(idx));
        n += MASTER_WORD_BYTES;
    }
    out[n] = b'-';
    n += 1;
    for _ in 0..MASTER_DIGITS {
        out[n] = b'0' + next_digit(src);
        n += 1;
    }
    debug_assert_eq!(n, MASTER_PASSWORD_CHARS);
    out
}

/// Convenience wrapper returning the password as a `String`.
pub fn generate_password_string(src: &mut impl RandomSource) -> String {
    let bytes = generate_password(src);
    String::from_utf8(bytes.to_vec()).expect("password is ASCII by construction")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rand::CycleSource;
    use crate::wordlist::word;

    #[test]
    fn word_index_is_top_12_bits_of_little_endian_u32() {
        // (1<<20)|3 -> bytes 03 00 10 00 in little-endian -> index 1.
        let mut s = CycleSource::new(&[0x03, 0x00, 0x10, 0x00]);
        assert_eq!(random_word_index(&mut s), 1);
        // (2<<20)|3 -> bytes 03 00 20 00 -> index 2.
        let mut s = CycleSource::new(&[0x03, 0x00, 0x20, 0x00]);
        assert_eq!(random_word_index(&mut s), 2);
        // Boundaries of the 12-bit field (top 12 bits).
        let hi = (4095u32 << 20).to_le_bytes();
        let mut s = CycleSource::new(&hi);
        assert_eq!(random_word_index(&mut s), 4095);
        let zero = 0u32.to_le_bytes();
        let mut s = CycleSource::new(&zero);
        assert_eq!(random_word_index(&mut s), 0);
    }

    #[test]
    fn digit_rejects_high_bytes_and_caps_attempts() {
        // 0..=249 accepted as-is.
        let mut s = CycleSource::new(&[249]);
        assert_eq!(next_digit(&mut s), 9);
        let mut s = CycleSource::new(&[200]);
        assert_eq!(next_digit(&mut s), 0);
        // All-0xFF never passes; the cap turns it into the biased fallback
        // (255 % 10 == 5) instead of an infinite loop.
        let mut s = CycleSource::new(&[0xFF]);
        assert_eq!(next_digit(&mut s), 5);
    }

    #[test]
    fn password_layout_is_38_chars_with_expected_hyphens() {
        let mut s = CycleSource::new(&[0xFF]);
        let pw = generate_password(&mut s);
        assert_eq!(pw.len(), MASTER_PASSWORD_CHARS);
        assert_eq!(pw.len(), 38);
        let text = core::str::from_utf8(&pw).unwrap();
        let parts: Vec<&str> = text.split('-').collect();
        assert_eq!(parts.len(), MASTER_WORDS + 1);
        // Six words of 5 letters, each equal to word(4095), then "55".
        for w in &parts[..MASTER_WORDS] {
            assert_eq!(*w, core::str::from_utf8(word(4095)).unwrap());
        }
        assert_eq!(parts[MASTER_WORDS], "55");
    }
}
