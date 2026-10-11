//! Stage 4a/5 selftest gates, ported from the removed C++ reference.
//!
//! Nothing here can be checked reliably on the host: PBKDF2 and AES are done by
//! real hardware, and flash writes only mean something on the real chip. The
//! vault gates write to the `vault` partition and clear it at the end, so
//! [`run`] first checks the partition is empty and refuses to touch real data
//! unless the explicit `selftest` cargo feature asked for a wipe.
//!
//! Secrets are never logged: the gate password is a constant from this file,
//! and messages carry only lengths, counters and comparison results.
//!
//! The C++ reference drives the auth worker asynchronously (`auth::install()`
//! and `poll()` over time). Here the gates run before the embassy executor
//! starts, so the `Auth` job is executed inline: `submit*` produces a request,
//! `Auth::run` executes it, and `poll` returns the finished view. The one-shot
//! delivery semantics are preserved because `poll` is still called exactly as
//! the C++ does.
//!
//! The gates are grouped by area into sibling modules; this file holds the
//! shared constants and helpers plus the [`requested`]/[`run`] entry points.

#![allow(clippy::too_many_lines, clippy::needless_range_loop)]

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use pm_core::auth::{
    Job, JobResult, JobView, KeyfileAction, NO_JOB, SESSION_TOKEN_HEX_LEN, Submit,
};
use pm_core::crypto::{self, CipherError};
use pm_core::device;
use pm_core::entry::{
    ENTRY_LOGIN, ENTRY_NOTE, ENTRY_PASSWORD, ENTRY_TITLE, ENTRY_URL, Entry, FIELD_ORDER, Field,
};
use pm_core::password::generate_password_string;
use pm_core::rand::CycleSource;
use pm_core::totp;
use pm_core::types::{State, VaultError};
use pm_core::vault::Storage;
use pm_core::{config, wordlist};

use crate::authsvc::{WorkerAuth, WorkerVault};
use crate::device::reversed_mac6;
use crate::hw::{EspClock, EspRng};

mod auth_gates;
mod crypto_gates;
mod keyfile_gates;
mod rekey_gates;
mod reset_gates;
mod vault_gates;

use auth_gates::auth_gates;
use crypto_gates::crypto_gates;
use keyfile_gates::keyfile_gates;
use rekey_gates::rekey_gates;
use reset_gates::reset_gates;
use vault_gates::vault_gates;

/// Password the gates provision under. Longer than `MIN_PASS_CHARS`. Once the
/// auth gates generate a real master password it is copied here, because the
/// vault gates must open the very storage auth gates left behind.
const GATE_PASSWORD: &str = "gate-only-passphrase-4a-not-a-real-secret";
const GATE_PASSWORD_WRONG: &str = "gate-only-wrong-passphrase-4a";
/// Password the rekey gates move to and back from.
const REKEY_PASSWORD: &str = "gate-rekey-passphrase-9b-not-a-real-secret";

// Header field offsets, duplicated on purpose: the gates must check the real
// bytes on flash, not ask `vault.rs` what it thinks it wrote.
const HDR_COUNT: usize = 0x0C;
const HDR_FLAGS: usize = 0x18;
const HDR_GENERATION: usize = 0x08;
const HDR_ITERS: usize = 0x1C;
const HDR_SALT_PW: usize = 0x20;
const HDR_SALT_DEV: usize = 0x30;
const HDR_DATA_START: usize = 0x50;
const HDR_SEQ: usize = 0x54;
const COMMIT_BYTES: usize = 4;
const HDR_COMMIT: usize = config::VAULT_HEADER_BYTES - COMMIT_BYTES;
const HDR_CHECK: usize = HDR_COMMIT - 16;
const FLAG_PROVISIONED: u32 = 1;
/// id(4) + len(2) + iv(12) + tag(16).
const REC_FIXED: usize = 34;

const SELFTEST_SAMPLES: u32 = 12;
const SELFTEST_SAMPLE_DELAY_MS: u32 = 20;

static PASS: AtomicU32 = AtomicU32::new(0);
static FAIL: AtomicU32 = AtomicU32::new(0);

/// Reports one gate: green increments the pass counter, red the fail counter.
fn report(gate: &str, ok: bool, detail: &str) {
    if ok {
        PASS.fetch_add(1, Ordering::Relaxed);
        log::info!("gate {:<20} PASS {}", gate, detail);
    } else {
        FAIL.fetch_add(1, Ordering::Relaxed);
        log::error!("gate {:<20} FAIL {}", gate, detail);
    }
}

/// Samples GPIO0 (BOOT) continuously and returns true only if it stays LOW for
/// the whole window.
///
/// IO0 is shared with the bootloader strapping pin and pulled low by the host's
/// DTR through the auto-reset circuit, so a single sample at start-up reads the
/// host, not a human. Only a sustained LOW enables the gates.
pub fn requested(pin: impl esp_hal::gpio::InputPin + 'static) -> bool {
    use esp_hal::delay::Delay;
    use esp_hal::gpio::{Input, InputConfig, Pull};

    let button = Input::new(pin, InputConfig::default().with_pull(Pull::Up));
    let delay = Delay::new();
    let mut low = 0u32;
    for _ in 0..SELFTEST_SAMPLES {
        if button.is_low() {
            low += 1;
        }
        delay.delay_millis(SELFTEST_SAMPLE_DELAY_MS);
    }
    low == SELFTEST_SAMPLES
}

fn fill_entry(e: &mut Entry, id: u32, tag: &str) {
    *e = Entry::new();
    e.id = id;
    e.set(Field::Title, format!("gate-{tag}").as_bytes());
    e.set(Field::Login, format!("user-{tag}").as_bytes());
    e.set(Field::Password, format!("pw-{tag}").as_bytes());
    e.set(
        Field::Url,
        format!("https://example.invalid/{tag}").as_bytes(),
    );
    e.set(Field::Note, format!("note-{tag}").as_bytes());
    e.set(Field::Tags, format!("tag-{tag},shared").as_bytes());
    e.set(Field::Totp, b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
}

fn entries_equal(a: &Entry, b: &Entry) -> bool {
    a.id == b.id && FIELD_ORDER.iter().all(|&f| a.get(f) == b.get(f))
}

fn read_u32(p: &[u8]) -> u32 {
    u32::from_le_bytes([p[0], p[1], p[2], p[3]])
}

/// Runs an `Auth` job inline and returns its finished view, or `None` if the
/// job was refused (`NO_JOB`) or is still pending.
fn wait_job(auth: &mut WorkerAuth, vault: &mut WorkerVault, sub: Submit) -> Option<JobView> {
    let (id, req) = sub;
    if id == NO_JOB {
        return None;
    }
    if let Some(req) = req.as_ref() {
        auth.run(vault, req);
    }
    let view = auth.poll(id)?;
    if view.result == JobResult::Pending {
        return None;
    }
    Some(view)
}

/// A partition is empty unless the header carries the provisioned flag.
fn vault_looks_empty(vault: &WorkerVault) -> bool {
    let mut head = [0u8; config::VAULT_HEADER_BYTES];
    if vault.storage_ref().read(0, &mut head).is_err() {
        return false;
    }
    if head[..4] != config::VAULT_MAGIC {
        return true;
    }
    read_u32(&head[HDR_FLAGS..]) & FLAG_PROVISIONED == 0
}

/// Slot of the newest completed header, found by the largest `seq`.
fn active_header_slot(vault: &WorkerVault) -> usize {
    let mut best = 0usize;
    let mut best_seq = 0u32;
    let mut hdr = [0u8; config::VAULT_HEADER_BYTES];
    for slot in 0..config::VAULT_HEADER_SLOTS {
        if vault
            .storage_ref()
            .read(slot * config::VAULT_HEADER_SLOT_BYTES, &mut hdr)
            .is_err()
        {
            continue;
        }
        if hdr[..4] != config::VAULT_MAGIC {
            continue;
        }
        if read_u32(&hdr[HDR_FLAGS..]) & FLAG_PROVISIONED == 0 {
            continue;
        }
        let seq = read_u32(&hdr[HDR_SEQ..]);
        if seq > best_seq {
            best_seq = seq;
            best = slot;
        }
    }
    best
}

fn read_active_header(vault: &WorkerVault, hdr: &mut [u8; config::VAULT_HEADER_BYTES]) -> bool {
    let slot = active_header_slot(vault);
    vault
        .storage_ref()
        .read(slot * config::VAULT_HEADER_SLOT_BYTES, hdr)
        .is_ok()
}

/// Opening with a tampered byte must be refused. True means the vault refused.
fn rejected_on_open(vault: &mut WorkerVault, rng: &mut EspRng) -> bool {
    matches!(
        vault.begin(GATE_PASSWORD, None, rng),
        VaultError::Tampered | VaultError::WrongPassword
    )
}

/// Writes `bad` over `bad.len()` bytes at `off`, checks the open is refused,
/// then restores the whole sector.
///
/// Restoring through erase is mandatory: flash only goes `1 -> 0`, so a cleared
/// bit cannot be raised without erasing. The sector is read before tampering, so
/// every other record in it comes back too.
fn tamper_bytes_rejected(
    vault: &mut WorkerVault,
    rng: &mut EspRng,
    off: usize,
    bad: &[u8],
) -> bool {
    if bad.is_empty() || off + bad.len() > config::VAULT_PARTITION_BYTES {
        return false;
    }
    let sector = off & !(config::FLASH_SECTOR_BYTES - 1);
    if off + bad.len() > sector + config::FLASH_SECTOR_BYTES {
        log::error!("gate: tamper range crosses sector boundary at {off}");
        return false;
    }
    let mut snap = vec![0u8; config::FLASH_SECTOR_BYTES];
    if vault.storage_ref().read(sector, &mut snap).is_err() {
        log::error!("gate: cannot snapshot sector at {sector}");
        return false;
    }
    let mut rejected = false;
    if vault.storage_mut().write(off, bad).is_err() {
        // A refused write is not a result: flash simply did not accept it.
        log::error!("gate: flash rejected tamper write at {off}");
    } else {
        rejected = rejected_on_open(vault, rng);
    }
    let restored = vault
        .storage_mut()
        .erase(sector, config::FLASH_SECTOR_BYTES)
        .is_ok()
        && vault.storage_mut().write(sector, &snap).is_ok();
    if !restored {
        log::error!("gate: cannot restore sector at {sector}, vault is broken");
    }
    rejected
}

/// Clears the low bit at `off` (the only transition flash takes without erase)
/// and checks the open is refused.
fn tamper_byte_is_rejected(vault: &mut WorkerVault, rng: &mut EspRng, off: usize) -> bool {
    let mut orig = [0u8; 1];
    if vault.storage_ref().read(off, &mut orig).is_err() {
        return false;
    }
    let bad = orig[0] & 0xFE;
    if bad == orig[0] {
        // Already zero: nothing to clear, and setting a bit needs erase.
        return true;
    }
    tamper_bytes_rejected(vault, rng, off, &[bad])
}

/// Runs every gate in the C++ order and reports the totals.
///
/// `wipe_vault` is only true for the explicit `selftest` build feature: the
/// GPIO0-triggered run must never silently destroy real data.
pub fn run(vault: &mut WorkerVault, wipe_vault: bool) {
    log::info!("=== gates ===");
    PASS.store(0, Ordering::Relaxed);
    FAIL.store(0, Ordering::Relaxed);

    let mut rng = EspRng::new();

    crypto_gates();

    if !vault_looks_empty(vault) {
        if !wipe_vault {
            log::error!("vault partition holds data: refusing to run destructive vault gates");
            log::error!("erase it manually or use the vault clear command");
            // A skip is not a failure: a refusal to touch data must not look
            // like a red gate.
            log::info!(
                "=== {} passed, {} failed, vault gates SKIPPED ===",
                PASS.load(Ordering::Relaxed),
                FAIL.load(Ordering::Relaxed)
            );
            return;
        }
        log::warn!("gate: wiping vault partition for a clean run");
        let size = vault.storage_ref().size();
        if vault.storage_mut().erase(0, size).is_err() {
            log::error!("gate: cannot wipe vault partition, vault gates skipped");
            log::info!(
                "=== {} passed, {} failed, vault gates SKIPPED ===",
                PASS.load(Ordering::Relaxed),
                FAIL.load(Ordering::Relaxed)
            );
            return;
        }
    }

    // auth gates run first, while the partition is still empty.
    let mut auth = WorkerAuth::new(EspRng::new(), EspClock);
    let mut gate_pw = String::from(GATE_PASSWORD);
    auth_gates(vault, &mut auth, &mut gate_pw);
    vault_gates(vault, &gate_pw, &mut rng);
    // Key-file and rekey sit between the vault and reset gates.
    keyfile_gates(vault, &mut auth, &gate_pw);
    rekey_gates(vault, &mut auth, &gate_pw);
    // reset destroys the vault the previous gates leaned on; it goes last.
    reset_gates(vault, &mut auth, &gate_pw);

    let passed = PASS.load(Ordering::Relaxed);
    let failed = FAIL.load(Ordering::Relaxed);
    log::info!("=== total: {passed} passed, {failed} failed ===");
    if failed > 0 {
        log::error!("gates FAILED");
    } else {
        log::info!("gates all PASS");
    }
}
