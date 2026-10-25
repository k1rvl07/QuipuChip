//! Shared status and snapshot types for the PMV1 vault and the auth FSM.
//!
//! These mirror the C++ reference's `vault::VaultError`, `vault::State`,
//! `vault::Stats` and `vault::Snapshot`. Discriminants are stable for logging.

/// Status code returned by the vault operations.
///
/// Explicitly `#[repr(u8)]` because the discriminant is logged numerically
/// (`State::Locked as u32` in the firmware boot path); the default `isize`
/// representation would leave the value unspecified.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultError {
    /// No error.
    None = 0,
    /// The vault partition was not found on flash.
    NotFound = 1,
    /// The vault has not been provisioned yet.
    BootStrap = 2,
    /// The supplied password did not unlock the vault.
    WrongPassword = 3,
    /// Header authentication failed or the on-flash layout is inconsistent.
    Tampered = 4,
    /// The live-byte budget would be exceeded.
    Budget = 5,
    /// The journal has no room for the record.
    NoSpace = 6,
    /// An entry could not be serialized.
    Serial = 7,
    /// A cryptographic operation failed.
    Crypto = 8,
    /// A flash I/O operation failed.
    Io = 9,
    /// The entry-count limit was reached.
    TooManyEntries = 10,
    /// An entry exceeds the per-entry size limit.
    EntryTooLong = 11,
}

impl VaultError {
    /// Human-readable text, also the wire wording used in error logs.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            VaultError::None => "ok",
            VaultError::NotFound => "partition not found",
            VaultError::BootStrap => "not provisioned yet",
            VaultError::WrongPassword => "wrong password",
            VaultError::Tampered => "tampered",
            VaultError::Budget => "live byte budget exceeded",
            VaultError::NoSpace => "no space in vault",
            VaultError::Serial => "serialization failed",
            VaultError::Crypto => "crypto failed",
            VaultError::Io => "flash io failed",
            VaultError::TooManyEntries => "entry count limit",
            VaultError::EntryTooLong => "entry too long",
        }
    }
}

impl core::fmt::Display for VaultError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str((*self).as_str())
    }
}

impl core::error::Error for VaultError {}

/// Provisioning/unlock state of the vault. `#[repr(u8)]` for the same reason as
/// [`VaultError`].
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// No vault has been provisioned.
    Unprovisioned = 0,
    /// A vault exists but is currently locked.
    Locked = 1,
    /// The vault is unlocked and usable.
    Unlocked = 2,
}

impl State {
    /// Human-readable text, also the wire wording used in logs.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            State::Unprovisioned => "unprovisioned",
            State::Locked => "locked",
            State::Unlocked => "unlocked",
        }
    }
}

impl core::fmt::Display for State {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str((*self).as_str())
    }
}

/// Counters describing the live contents of a vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stats {
    /// Number of live entries.
    pub entry_count: u32,
    /// Sum of live payload bytes (per-record overhead excluded).
    pub live_bytes: usize,
    /// Journal bytes consumed in the active region.
    pub used_bytes: usize,
    /// Key generation counter, bumped on rekey.
    pub generation: u32,
    /// Whether the journal has been compacted at least once.
    pub compacted_once: bool,
}

/// Immutable point-in-time view of a vault's state and counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    /// Provisioning/unlock state at capture time.
    pub state: State,
    /// Number of live entries.
    pub entry_count: u32,
    /// Key generation counter.
    pub generation: u32,
    /// Sum of live payload bytes.
    pub live_bytes: usize,
}

impl Default for Snapshot {
    fn default() -> Self {
        Snapshot {
            state: State::Unprovisioned,
            entry_count: 0,
            generation: 0,
            live_bytes: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec::Vec;

    /// Every variant, in declaration order. The numeric discriminants are a
    /// logging contract with the C++ reference, so they are pinned here.
    const ALL_ERRORS: [VaultError; 12] = [
        VaultError::None,
        VaultError::NotFound,
        VaultError::BootStrap,
        VaultError::WrongPassword,
        VaultError::Tampered,
        VaultError::Budget,
        VaultError::NoSpace,
        VaultError::Serial,
        VaultError::Crypto,
        VaultError::Io,
        VaultError::TooManyEntries,
        VaultError::EntryTooLong,
    ];

    #[test]
    fn error_discriminants_are_stable() {
        // The firmware logs `state as u32`; a reordering would silently change
        // what an operator sees in the log.
        let expected = [
            (VaultError::None, 0u8),
            (VaultError::NotFound, 1),
            (VaultError::BootStrap, 2),
            (VaultError::WrongPassword, 3),
            (VaultError::Tampered, 4),
            (VaultError::Budget, 5),
            (VaultError::NoSpace, 6),
            (VaultError::Serial, 7),
            (VaultError::Crypto, 8),
            (VaultError::Io, 9),
            (VaultError::TooManyEntries, 10),
            (VaultError::EntryTooLong, 11),
        ];
        for (err, code) in expected {
            assert_eq!(err as u8, code, "discriminant of {err:?}");
        }
    }

    #[test]
    fn error_strings_match_the_reference_wording() {
        // These strings are the wire wording the C++ reference used. They are
        // part of the contract, not decoration.
        let expected = [
            (VaultError::None, "ok"),
            (VaultError::NotFound, "partition not found"),
            (VaultError::BootStrap, "not provisioned yet"),
            (VaultError::WrongPassword, "wrong password"),
            (VaultError::Tampered, "tampered"),
            (VaultError::Budget, "live byte budget exceeded"),
            (VaultError::NoSpace, "no space in vault"),
            (VaultError::Serial, "serialization failed"),
            (VaultError::Crypto, "crypto failed"),
            (VaultError::Io, "flash io failed"),
            (VaultError::TooManyEntries, "entry count limit"),
            (VaultError::EntryTooLong, "entry too long"),
        ];
        for (err, text) in expected {
            assert_eq!(err.as_str(), text, "as_str of {err:?}");
            assert_eq!(err.to_string(), text, "Display of {err:?}");
        }
    }

    #[test]
    fn every_error_variant_has_a_distinct_string() {
        let mut seen: Vec<&str> = Vec::new();
        for err in ALL_ERRORS {
            let text = err.as_str();
            assert!(!text.is_empty(), "{err:?} has an empty string");
            assert!(!seen.contains(&text), "duplicate error text: {text}");
            seen.push(text);
        }
        assert_eq!(seen.len(), ALL_ERRORS.len());
    }

    #[test]
    fn errors_implement_the_error_trait() {
        fn as_dyn(err: &dyn core::error::Error) -> String {
            err.to_string()
        }
        for err in ALL_ERRORS {
            assert_eq!(as_dyn(&err), err.as_str());
        }
    }

    #[test]
    fn state_discriminants_and_strings() {
        assert_eq!(State::Unprovisioned as u8, 0);
        assert_eq!(State::Locked as u8, 1);
        assert_eq!(State::Unlocked as u8, 2);

        assert_eq!(State::Unprovisioned.as_str(), "unprovisioned");
        assert_eq!(State::Locked.as_str(), "locked");
        assert_eq!(State::Unlocked.as_str(), "unlocked");

        assert_eq!(State::Unprovisioned.to_string(), "unprovisioned");
        assert_eq!(State::Locked.to_string(), "locked");
        assert_eq!(State::Unlocked.to_string(), "unlocked");
    }

    #[test]
    fn stats_default_is_empty() {
        let s = Stats::default();
        assert_eq!(s.entry_count, 0);
        assert_eq!(s.live_bytes, 0);
        assert_eq!(s.used_bytes, 0);
        assert_eq!(s.generation, 0);
        assert!(!s.compacted_once);
    }

    #[test]
    fn snapshot_default_is_unprovisioned() {
        let s = Snapshot::default();
        assert_eq!(s.state, State::Unprovisioned);
        assert_eq!(s.entry_count, 0);
        assert_eq!(s.generation, 0);
        assert_eq!(s.live_bytes, 0);
    }
}
