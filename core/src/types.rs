//! Shared status and snapshot types for the PMV1 vault and the auth FSM.
//!
//! These mirror the C++ reference's `vault::VaultError`, `vault::State`,
//! `vault::Stats` and `vault::Snapshot`. Discriminants are stable for logging.

/// Status code returned by the vault operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultError {
    None = 0,
    NotFound = 1,
    BootStrap = 2,
    WrongPassword = 3,
    Tampered = 4,
    Budget = 5,
    NoSpace = 6,
    Serial = 7,
    Crypto = 8,
    Io = 9,
    TooManyEntries = 10,
    EntryTooLong = 11,
}

impl VaultError {
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

/// Provisioning/unlock state of the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Unprovisioned = 0,
    Locked = 1,
    Unlocked = 2,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Unprovisioned => "unprovisioned",
            State::Locked => "locked",
            State::Unlocked => "unlocked",
        }
    }
}

/// Counters describing the live contents of a vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stats {
    pub entry_count: u32,
    pub live_bytes: usize,
    pub used_bytes: usize,
    pub generation: u32,
    pub compacted_once: bool,
}

/// Immutable point-in-time view of a vault's state and counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    pub state: State,
    pub entry_count: u32,
    pub generation: u32,
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
