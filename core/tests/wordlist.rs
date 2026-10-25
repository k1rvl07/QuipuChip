//! Contract tests for the generated master wordlist.
//!
//! `core/src/wordlist.rs` is owned by `scripts/wordlist.py`: the generator
//! writes it and `--check` compares it byte for byte. Anything added to that
//! file by hand would break that gate, so the tests live here instead.

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use pm_core::wordlist::{WORD_BYTES, WORD_COUNT, WORD_STRIDE, WORDS, word};

/// Every word of the table.
fn all_words() -> Vec<&'static [u8]> {
    (0..WORD_COUNT).map(word).collect()
}

/// Reads a Python tuple of string literals out of the generator source.
///
/// The block lists live in `scripts/wordlist.py`; parsing them here means the
/// runtime table is checked against the *same* policy the generator uses,
/// instead of against a copy that could drift.
///
/// Returns `Err` instead of panicking: the restriction lints are waived inside
/// `#[test]` functions, but not in a helper they call.
fn python_tuple(name: &str) -> Result<Vec<String>, String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../scripts/wordlist.py");
    let source =
        fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let start = source
        .find(&format!("{name} = ("))
        .ok_or_else(|| format!("{name} not found in {}", path.display()))?;
    let body = &source[start..];
    let end = body
        .find(')')
        .ok_or_else(|| format!("{name} is not closed in {}", path.display()))?;
    Ok(body[..end]
        .split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect())
}

#[test]
fn table_shape_is_exact() {
    assert_eq!(WORD_COUNT, 4096);
    assert_eq!(WORD_BYTES, 5);
    assert_eq!(WORD_STRIDE, 6);
    assert_eq!(WORDS.len(), WORD_COUNT * WORD_STRIDE);
}

#[test]
fn every_word_is_five_lowercase_letters() {
    for (i, w) in all_words().iter().enumerate() {
        assert_eq!(w.len(), WORD_BYTES, "word {i} has the wrong length");
        assert!(
            w.iter().all(u8::is_ascii_lowercase),
            "word {i} ({:?}) is not lowercase ASCII",
            String::from_utf8_lossy(w)
        );
    }
}

#[test]
fn every_word_is_nul_terminated_in_the_table() {
    // The terminator is what makes a word's index independent of its
    // position; a missing one would run two words together.
    for i in 0..WORD_COUNT {
        assert_eq!(
            WORDS[i * WORD_STRIDE + WORD_BYTES],
            0,
            "word {i} is not NUL-terminated"
        );
    }
}

#[test]
fn words_are_unique() {
    // A duplicate would silently halve the entropy of a word slot while the
    // table still claimed 12 bits per word.
    let mut seen: HashSet<&[u8]> = HashSet::new();
    for w in all_words() {
        assert!(
            seen.insert(w),
            "duplicate word {:?}",
            String::from_utf8_lossy(w)
        );
    }
    assert_eq!(seen.len(), WORD_COUNT);
}

#[test]
fn no_word_contains_a_blocked_substring() {
    let blocked = python_tuple("BLOCK_SUBSTRINGS").unwrap();
    assert!(blocked.len() > 20, "block list looks truncated");
    for w in all_words() {
        let text = String::from_utf8_lossy(w);
        for bad in &blocked {
            assert!(
                !text.contains(bad.as_str()),
                "word {text:?} contains the blocked substring {bad:?}"
            );
        }
    }
}

#[test]
fn no_word_is_explicitly_excluded() {
    let excluded = python_tuple("WORD_EXCLUDE").unwrap();
    assert!(!excluded.is_empty(), "exclusion list is empty");
    for w in all_words() {
        let text = String::from_utf8_lossy(w);
        for bad in &excluded {
            assert_ne!(&text, bad, "excluded word {bad:?} is in the table");
        }
    }
}

#[test]
fn no_word_hints_at_account_access() {
    // The generator refuses words that tell an attacker which account the
    // passphrase belongs to. Guarded separately so a future regeneration
    // cannot reintroduce them through a different spelling.
    for w in all_words() {
        let text = String::from_utf8_lossy(w);
        for bad in ["root", "sudo", "admin", "login", "guest", "super", "master"] {
            assert!(
                !text.contains(bad),
                "word {text:?} contains the access word {bad:?}"
            );
        }
    }
}

#[test]
fn word_accessor_matches_the_table() {
    for i in 0..WORD_COUNT {
        let expected = &WORDS[i * WORD_STRIDE..i * WORD_STRIDE + WORD_BYTES];
        assert_eq!(word(i), expected);
    }
    assert_eq!(word(0), b"there");
}

#[test]
#[should_panic(expected = "range end index")]
fn word_accessor_rejects_an_out_of_range_index() {
    // Documented behaviour: the index is trusted, and an out-of-range one
    // panics rather than silently returning a neighbouring word.
    let _ = word(WORD_COUNT);
}
