//! Stage 4a/5 selftest gates, ported from `src/selftest.cpp`.
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
    ENTRY_LOGIN, ENTRY_NOTE, ENTRY_PASSWORD, ENTRY_TITLE, ENTRY_URL, Entry, Field, State,
    VaultError,
};
use pm_core::password::generate_password_string;
use pm_core::rand::CycleSource;
use pm_core::totp;
use pm_core::vault::Storage;
use pm_core::{config, wordlist};

use crate::authsvc::{WorkerAuth, WorkerVault};
use crate::device::reversed_mac6;
use crate::hw::{EspClock, EspRng};

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

fn hex_to_bytes(hex: &str, out: &mut [u8]) -> bool {
    let b = hex.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_nibble(b[i * 2]);
        let lo = hex_nibble(b[i * 2 + 1]);
        match (hi, lo) {
            (Some(hi), Some(lo)) => *slot = (hi << 4) | lo,
            _ => return false,
        }
    }
    true
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
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

const ALL_FIELDS: [Field; 7] = [
    Field::Title,
    Field::Login,
    Field::Password,
    Field::Url,
    Field::Note,
    Field::Tags,
    Field::Totp,
];

fn entries_equal(a: &Entry, b: &Entry) -> bool {
    a.id == b.id && ALL_FIELDS.iter().all(|&f| a.get(f) == b.get(f))
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

// ── Crypto gates ────────────────────────────────────────────────────────────

fn crypto_gates() {
    // PBKDF2 against RFC 7914 vectors.
    const VECTORS: &[(&str, &str, u32, &str)] = &[
        (
            "password",
            "salt",
            1,
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
        ),
        (
            "password",
            "salt",
            2,
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
        ),
        (
            "password",
            "salt",
            4096,
            "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
        ),
        (
            "passwordPASSWORDpassword",
            "saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
            "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1",
        ),
        (
            "passwd",
            "salt",
            1,
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc",
        ),
    ];
    let mut ok_count = 0u32;
    for (pass, salt, iters, expect) in VECTORS {
        let mut want = [0u8; 32];
        if !hex_to_bytes(expect, &mut want) {
            continue;
        }
        if crypto::pbkdf2_hmac_sha256(pass.as_bytes(), salt.as_bytes(), *iters)
            .map(|got| crypto::ct_equal(&got, &want))
            .unwrap_or(false)
        {
            ok_count += 1;
        }
    }
    report(
        "crypto-kdf",
        ok_count as usize == VECTORS.len(),
        &format!("{}/{} vectors (RFC 7914)", ok_count, VECTORS.len()),
    );

    // AES-256-GCM round-trip, then tag/AAD/ciphertext flips must fail.
    {
        let key: [u8; 32] = core::array::from_fn(|i| (i + 1) as u8);
        let iv: [u8; 12] = [0xAA, 0xBB, 0xCC, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let aad: [u8; 8] = [b'h', b'd', b'r', b'v', b'1', 0, 0, 0];
        let msg = b"gate-plaintext-check-0123456789";
        let mut buf = msg.to_vec();
        let mut ok = false;
        if let Ok(tag) = crypto::aes_gcm_encrypt(&key, &iv, &aad, &mut buf) {
            ok = buf.len() == msg.len();
            if ok {
                let mut back = buf.clone();
                ok = crypto::aes_gcm_decrypt(&key, &iv, &aad, &mut back, &tag).is_ok()
                    && back == msg;
                if ok {
                    let mut bad_aad = aad;
                    bad_aad[0] ^= 0x01;
                    ok = crypto::aes_gcm_decrypt(&key, &iv, &bad_aad, &mut back, &tag)
                        == Err(CipherError::AuthFail);
                }
                if ok {
                    let mut ct = buf.clone();
                    ct[0] ^= 0x01;
                    ok = crypto::aes_gcm_decrypt(&key, &iv, &aad, &mut ct, &tag)
                        == Err(CipherError::AuthFail);
                }
                if ok {
                    let mut t = tag;
                    t[0] ^= 0x01;
                    ok = crypto::aes_gcm_decrypt(&key, &iv, &aad, &mut back, &t)
                        == Err(CipherError::AuthFail);
                }
            }
        }
        crypto::wipe(&mut buf);
        report("crypto-aes-gcm", ok, "roundtrip + ct/aad/tag flip rejected");
    }

    // ct_equal must tell two buffers apart.
    {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 5];
        report(
            "crypto-cteq",
            !crypto::ct_equal(&a, &b) && crypto::ct_equal(&a, &a),
            "",
        );
    }

    // Device factor must be deterministic and salt-dependent.
    {
        let mut s1 = [0u8; 16];
        s1[0] = 1;
        let mut s2 = [0u8; 16];
        s2[0] = 2;
        let ok = match reversed_mac6() {
            Some(mac) => match (
                device::factor(&mac, &s1),
                device::factor(&mac, &s1),
                device::factor(&mac, &s2),
            ) {
                (Ok(f1), Ok(f2), Ok(f3)) => {
                    crypto::ct_equal(&f1, &f2) && !crypto::ct_equal(&f1, &f3)
                }
                _ => false,
            },
            None => false,
        };
        report("device-factor", ok, "stable, salt-dependent");
    }

    // TOTP against RFC 6238 (SHA-1). T = 20000000000 does not fit a u32, and
    // device time is 32-bit.
    {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        const VECTORS: &[(u32, &str)] = &[
            (59, "287082"),
            (1111111109, "081804"),
            (1111111111, "050471"),
            (1234567890, "005924"),
            (2000000000, "279037"),
        ];
        let mut ok_count = 0u32;
        for (t, expect) in VECTORS {
            if totp::code(secret, *t as u64)
                .map(|code| code == *expect)
                .unwrap_or(false)
            {
                ok_count += 1;
            }
        }
        let rejects = !totp::valid_secret("abc")
            && !totp::valid_secret("ABCDEFGH1IJKLMNOP")
            && !totp::valid_secret("")
            && totp::code("too-short", 59).is_err();
        report(
            "crypto-totp-rfc6238",
            ok_count == 5 && rejects,
            &format!("{}/5 vectors, invalid rejected: {}", ok_count, rejects),
        );
    }
}

// ── Vault gates ─────────────────────────────────────────────────────────────

fn vault_gates(vault: &mut WorkerVault, gate_pw: &str, rng: &mut EspRng) {
    let rc = vault.begin(gate_pw, None, rng);
    if rc == VaultError::Tampered || rc == VaultError::WrongPassword {
        report(
            "vault-open",
            false,
            "leftover data in vault partition, refusing to write",
        );
        return;
    }
    report("vault-provision", rc == VaultError::Ok, rc.to_str());
    if rc != VaultError::Ok {
        return;
    }

    let mut scratch = Entry::new();
    fill_entry(&mut scratch, 0, "alpha");
    let id = match vault.add(&scratch) {
        Ok(id) => {
            report("vault-add", id != 0, "");
            id
        }
        Err(e) => {
            report("vault-add", false, e.to_str());
            return;
        }
    };
    scratch.id = id;

    match vault.load(8) {
        Ok(got) => report(
            "vault-load",
            got.len() == 1 && entries_equal(&got[0], &scratch),
            "",
        ),
        Err(e) => report("vault-load", false, e.to_str()),
    }

    // Reopen so data is read from flash, not memory.
    let rc = vault.begin(gate_pw, None, rng);
    report("vault-reopen", rc == VaultError::Ok, rc.to_str());
    match vault.load(8) {
        Ok(got) => report(
            "vault-load-reboot",
            rc == VaultError::Ok && got.len() == 1 && entries_equal(&got[0], &scratch),
            rc.to_str(),
        ),
        Err(e) => report("vault-load-reboot", false, e.to_str()),
    }

    // Update: same id, content changes, count stays.
    fill_entry(&mut scratch, id, "alpha-v2");
    let _ = vault.add(&scratch);
    match vault.load(8) {
        Ok(got) => report(
            "vault-update",
            got.len() == 1 && entries_equal(&got[0], &scratch),
            "in-place, count stable",
        ),
        Err(e) => report("vault-update", false, e.to_str()),
    }

    let _ = vault.remove(id);
    match vault.load(8) {
        Ok(got) => report("vault-remove", got.is_empty(), ""),
        Err(e) => report("vault-remove", false, e.to_str()),
    }

    // Removal must survive a reboot.
    let _ = vault.begin(gate_pw, None, rng);
    match vault.load(8) {
        Ok(got) => report("vault-remove-persist", got.is_empty(), ""),
        Err(e) => report("vault-remove-persist", false, e.to_str()),
    }

    // Max-size record accepted and read back intact.
    {
        let mut big = Entry::new();
        fill_entry(&mut big, 0, "max");
        big.set(Field::Title, &[b't'; ENTRY_TITLE - 1]);
        big.set(Field::Login, &[b'l'; ENTRY_LOGIN - 1]);
        big.set(Field::Password, &[b'p'; ENTRY_PASSWORD - 1]);
        big.set(Field::Url, &[b'u'; ENTRY_URL - 1]);
        big.set(Field::Note, &[b'n'; ENTRY_NOTE - 1]);
        let before = vault.count();
        let (add_ok, max_id, found) = match vault.add(&big) {
            Ok(max_id) => {
                big.id = max_id;
                let found = matches!(
                    vault.load(2),
                    Ok(back) if back.iter().any(|b| b.id == max_id && entries_equal(b, &big))
                );
                (true, max_id, found)
            }
            Err(_) => (false, 0, false),
        };
        let detail = format!(
            "max record roundtrip {}",
            if found { "ok" } else { "broken" }
        );
        report(
            "gate5-max-entry",
            add_ok && found && vault.count() == before + 1,
            &detail,
        );
        let _ = vault.remove(max_id);
    }

    // Count limit: add to the ceiling and check the refusal.
    {
        let mut added = 0u32;
        let mut add_rc = VaultError::Ok;
        let mut t = Entry::new();
        let mut i = 0u32;
        while i < config::MAX_ENTRIES + 8 && add_rc == VaultError::Ok {
            fill_entry(&mut t, 0, "cap");
            add_rc = match vault.add(&t) {
                Ok(_) => {
                    added += 1;
                    VaultError::Ok
                }
                Err(e) => e,
            };
            i += 1;
        }
        let detail = format!("{} added, stopped with {}", added, add_rc.to_str());
        let ok = vault.count() <= config::MAX_ENTRIES
            && matches!(
                add_rc,
                VaultError::TooManyEntries | VaultError::Budget | VaultError::NoSpace
            );
        report("gate5-count-cap", ok, &detail);
    }

    log::info!("gate: clearing vault before wear gates");
    let rc = vault.clear(gate_pw, None, rng);
    report("gate-reset", rc == VaultError::Ok, rc.to_str());
    if rc != VaultError::Ok {
        return;
    }

    // Wear: 480 saves, verifying after EACH write so a break at #480 is not
    // confused with a break at #1.
    {
        const WEAR_ITERATIONS: u32 = 480;
        let mut checked = 0u32;
        let mut bad = VaultError::Ok;
        let mut t = Entry::new();
        for i in 0..WEAR_ITERATIONS {
            fill_entry(&mut t, 0, "wear");
            // The iteration number is appended after fillEntry, otherwise
            // fillEntry would overwrite the note and neighbouring records would
            // not differ.
            let note = format!("wear-{i:03}-{}", "w".repeat(500));
            t.set(Field::Note, note.as_bytes());
            if let Err(e) = vault.add(&t) {
                bad = e;
                break;
            }
            let tail = match vault.load(4) {
                Ok(v) => v,
                Err(e) => {
                    bad = e;
                    break;
                }
            };
            if tail.is_empty() {
                bad = VaultError::Tampered;
                break;
            }
            if tail[tail.len() - 1].get(Field::Password) != t.get(Field::Password) {
                bad = VaultError::Tampered;
                break;
            }
            checked += 1;
        }
        let detail = format!(
            "{}/{} verified after each write{}",
            checked,
            WEAR_ITERATIONS,
            if bad == VaultError::Ok {
                ""
            } else {
                ", stopped early"
            }
        );
        report(
            "gate6-wear",
            bad == VaultError::Ok && checked == WEAR_ITERATIONS,
            &detail,
        );
    }

    // Index and region rebuilt by compaction must survive a reboot.
    {
        let expected = vault.count();
        let rc = vault.begin(gate_pw, None, rng);
        const PROBE: u32 = 16;
        let (load_rc, an) = match vault.load(PROBE as usize) {
            Ok(v) => (VaultError::Ok, v.len() as u32),
            Err(e) => (e, 0),
        };
        let after_open = vault.count();
        let detail = format!(
            "count {} -> {}, {} loaded, data intact",
            expected, after_open, an
        );
        report(
            "gate6-reboot",
            rc == VaultError::Ok
                && load_rc == VaultError::Ok
                && after_open == expected
                && an == expected.min(PROBE)
                && expected > 0,
            &detail,
        );
    }

    let st = vault.stats();
    log::info!(
        "gate: gen {} entries {} live {} B used {} B compacted {}",
        st.generation,
        st.entry_count,
        st.live_bytes,
        st.used_bytes,
        st.compacted_once as u8
    );
    report(
        "gate7-compact",
        st.compacted_once,
        "compaction triggered by log growth",
    );

    // Wrong password must not change a single partition byte, nor drop the
    // device into Unprovisioned.
    {
        let mut ok = false;
        let st_before = vault.snapshot();
        let mut bad_pw_rc = VaultError::NotFound;
        let mut st_after = st_before;
        let mut prov_after = false;
        let mut snap: Vec<u8> = Vec::new();
        if snap
            .try_reserve_exact(config::VAULT_PARTITION_BYTES)
            .is_ok()
        {
            snap.resize(config::VAULT_PARTITION_BYTES, 0);
            if vault.storage_ref().read(0, &mut snap).is_ok() {
                bad_pw_rc = vault.begin(GATE_PASSWORD_WRONG, None, rng);
                st_after = vault.snapshot();
                ok = bad_pw_rc == VaultError::WrongPassword;
                prov_after = vault.provisioned();
                if ok {
                    ok = st_before.state == State::Unlocked
                        && st_after.state == State::Locked
                        && prov_after;
                }
                if ok {
                    let mut page = [0u8; 256];
                    let mut off = 0usize;
                    while off < config::VAULT_PARTITION_BYTES {
                        let chunk = core::cmp::min(256, config::VAULT_PARTITION_BYTES - off);
                        if vault.storage_ref().read(off, &mut page[..chunk]).is_err()
                            || page[..chunk] != snap[off..off + chunk]
                        {
                            ok = false;
                            break;
                        }
                        off += 256;
                    }
                }
            }
        }
        let detail = format!(
            "wrong={} state {}->{} prov={} ok={}",
            bad_pw_rc.to_str(),
            st_before.state.to_str(),
            st_after.state.to_str(),
            prov_after as u8,
            ok as u8
        );
        report("gate2-wrongpw", ok, &detail);
    }

    // Header corruption. generation/iters/saltPw/saltDev/check are in the AAD.
    {
        if vault.begin(gate_pw, None, rng) != VaultError::Ok {
            report(
                "gate3-tamper-hdr",
                false,
                "cannot open vault for tamper test",
            );
        } else {
            let offsets = [
                HDR_GENERATION,
                HDR_ITERS,
                HDR_SALT_PW,
                HDR_SALT_DEV,
                HDR_CHECK,
            ];
            let base = active_header_slot(vault) * config::VAULT_HEADER_SLOT_BYTES;
            let mut rejected = 0u32;
            let mut accepted = 0u32;
            for off in offsets {
                if tamper_byte_is_rejected(vault, rng, base + off) {
                    rejected += 1;
                } else {
                    accepted += 1;
                }
            }
            let detail = format!("{}/{} header bytes rejected", rejected, offsets.len());
            report("gate3-tamper-hdr", rejected > 0 && accepted == 0, &detail);
        }
    }

    // A torn header write must fall back to the spare slot, not refuse.
    {
        let mut ok = false;
        let mut detail = String::from("no active slot");
        if vault.begin(gate_pw, None, rng) == VaultError::Ok {
            let slot = active_header_slot(vault);
            let sector = slot * config::VAULT_HEADER_SLOT_BYTES;
            let count_before = vault.count();
            let mut snap = vec![0u8; config::FLASH_SECTOR_BYTES];
            let read_ok = vault.storage_ref().read(sector, &mut snap).is_ok();
            let erase_ok = vault
                .storage_mut()
                .erase(sector, config::FLASH_SECTOR_BYTES)
                .is_ok();
            if read_ok && erase_ok {
                // Write everything through the tag but not the commit marker:
                // exactly what a power loss leaves behind.
                let write_ok = vault
                    .storage_mut()
                    .write(sector, &snap[..HDR_COMMIT])
                    .is_ok();
                if write_ok {
                    let r = vault.begin(gate_pw, None, rng);
                    let count_after = vault.count();
                    let count_ok = count_after == count_before || count_after + 1 == count_before;
                    ok = r == VaultError::Ok && vault.initialized() && count_ok;
                    detail = format!("fell back, entries {count_before} -> {count_after}");
                }
                if vault
                    .storage_mut()
                    .erase(sector, config::FLASH_SECTOR_BYTES)
                    .is_ok()
                {
                    let _ = vault.storage_mut().write(sector, &snap);
                }
            }
        }
        report("gate3b-torn-hdr", ok, &detail);
    }

    // dataStart corruption: the field is not in the AAD, but it bounds the
    // active region, so a value off either boundary must be rejected.
    {
        let mut ok = false;
        if vault.begin(gate_pw, None, rng) == VaultError::Ok {
            let ds_off =
                active_header_slot(vault) * config::VAULT_HEADER_SLOT_BYTES + HDR_DATA_START;
            ok = tamper_bytes_rejected(vault, rng, ds_off, &[0, 0, 0, 0]);
        }
        report("gate4-tamper-ds", ok, "dataStart out of range rejected");
    }

    // Record ciphertext corruption.
    {
        let mut ok = false;
        let mut data_start = 0u32;
        let open_rc = vault.begin(gate_pw, None, rng);
        let detail: String;
        if open_rc == VaultError::Ok {
            let mut hdr = [0u8; config::VAULT_HEADER_BYTES];
            if read_active_header(vault, &mut hdr) {
                data_start = read_u32(&hdr[HDR_DATA_START..]);
                if data_start as usize == config::VAULT_REGION0_OFFSET
                    || data_start as usize
                        == config::VAULT_REGION0_OFFSET + config::VAULT_REGION_BYTES
                {
                    ok = tamper_byte_is_rejected(vault, rng, data_start as usize + REC_FIXED);
                }
            }
            detail = format!(
                "open {} dataStart {} rejected {}",
                open_rc.to_str(),
                data_start,
                ok as u8
            );
        } else {
            detail = format!("open {}", open_rc.to_str());
        }
        report("gate8-tamper-ct", ok, &detail);
    }

    // Header counter corruption: counters are not in the AAD, so they are
    // guarded by re-counting the log.
    {
        let mut ok = false;
        if vault.begin(gate_pw, None, rng) == VaultError::Ok {
            let cnt_off = active_header_slot(vault) * config::VAULT_HEADER_SLOT_BYTES + HDR_COUNT;
            let mut raw = [0u8; 4];
            if vault.storage_ref().read(cnt_off, &mut raw).is_ok() {
                let bytes = [0u8, raw[1], raw[2], raw[3]];
                ok = tamper_bytes_rejected(vault, rng, cnt_off, &bytes);
            }
        }
        report("gate9-tamper-count", ok, "entryCount mismatch rejected");
    }

    // GCM tag of the first record: last tag byte is dataStart + REC_FIXED - 1.
    {
        let mut ok = false;
        let mut data_start = 0u32;
        let open_rc = vault.begin(gate_pw, None, rng);
        let detail: String;
        if open_rc == VaultError::Ok {
            let mut hdr = [0u8; config::VAULT_HEADER_BYTES];
            if read_active_header(vault, &mut hdr) {
                data_start = read_u32(&hdr[HDR_DATA_START..]);
                if data_start as usize == config::VAULT_REGION0_OFFSET
                    || data_start as usize
                        == config::VAULT_REGION0_OFFSET + config::VAULT_REGION_BYTES
                {
                    ok = tamper_byte_is_rejected(vault, rng, data_start as usize + REC_FIXED - 1);
                }
            }
            detail = format!(
                "open {} dataStart {} rejected {}",
                open_rc.to_str(),
                data_start,
                ok as u8
            );
        } else {
            detail = format!("open {}", open_rc.to_str());
        }
        report("gate10-tamper-tag", ok, &detail);
    }

    // Session surface: close(), get(), provisioned(), snapshot(), reset().
    {
        let open = vault.begin(gate_pw, None, rng);
        let mut e = Entry::new();
        e.set(Field::Title, b"session-probe");
        e.set(Field::Password, b"pw-probe-distinctive-4a");
        e.set(Field::Note, b"note-probe");
        let before = if open == VaultError::Ok {
            vault.count()
        } else {
            0
        };
        let (add_rc, id) = match vault.add(&e) {
            Ok(id) => (VaultError::Ok, id),
            Err(er) => (er, 0),
        };

        vault.close();
        let closed = !vault.initialized() && vault.count() == 0;
        let snap_locked = vault.snapshot().state == State::Locked;
        vault.close();
        vault.close();
        let close_idempotent = !vault.initialized() && vault.count() == 0;

        let reopen = vault.begin(gate_pw, None, rng);
        let survived = reopen == VaultError::Ok && vault.count() == before + 1;
        let s_open = vault.snapshot();
        let snap_unlocked = s_open.state == State::Unlocked && s_open.entry_count == before + 1;

        let get_ok = match vault.get(id) {
            Ok(got) => {
                got.id == id
                    && got.get(Field::Title) == e.get(Field::Title)
                    && got.get(Field::Password) == e.get(Field::Password)
                    && got.get(Field::Note) == e.get(Field::Note)
            }
            Err(_) => false,
        };
        let miss_ok = vault.get(id.wrapping_add(100000)) == Err(VaultError::NotFound);
        let prov_yes = vault.provisioned();
        let detail = format!(
            "open {} add {} id {} | close {}/{} snap {}/{} | get {} miss {} | {}",
            open.to_str(),
            add_rc.to_str(),
            id,
            closed as u8,
            close_idempotent as u8,
            snap_locked as u8,
            snap_unlocked as u8,
            get_ok as u8,
            miss_ok as u8,
            prov_yes as u8
        );
        report(
            "gate11-session",
            open == VaultError::Ok
                && add_rc == VaultError::Ok
                && closed
                && close_idempotent
                && snap_locked
                && snap_unlocked
                && survived
                && get_ok
                && miss_ok
                && prov_yes,
            &detail,
        );

        // reset() works without password and session; afterwards the device
        // reads Unprovisioned.
        vault.close();
        let rst = vault.reset();
        let s_reset = vault.snapshot();
        let reset_ok = rst == VaultError::Ok
            && !vault.provisioned()
            && s_reset.state == State::Unprovisioned
            && !vault.initialized();
        let prov_after_reset = vault.provisioned();
        report(
            "gate12-reset",
            reset_ok && !prov_after_reset,
            "destroyed without password",
        );

        let re_prov = vault.begin(gate_pw, None, rng);
        report(
            "gate13-reprovision",
            re_prov == VaultError::Ok,
            re_prov.to_str(),
        );
    }

    {
        let r = vault.begin(gate_pw, None, rng);
        report("vault-reopen", r == VaultError::Ok, r.to_str());
    }
    let _ = vault.clear(gate_pw, None, rng);
    log::info!("gate: vault cleared after tests");
}

// ── Auth gates ──────────────────────────────────────────────────────────────

fn auth_gates(vault: &mut WorkerVault, auth: &mut WorkerAuth, gate_pw: &mut String) {
    log::info!("=== stage 5 auth gates ===");

    if !vault_looks_empty(vault) {
        log::error!("vault partition holds data: refusing to run stage 5 auth gates");
        log::error!("they provision storage from scratch and cannot run on existing data");
        return;
    }

    auth.initialize(vault);
    report("gateA0-install", true, "auth worker up");

    // Format: 6 words of 5 letters joined by '-', then '-' and 2 digits.
    {
        let pw = auth.generate_master_password();
        let bytes = pw.as_bytes();
        let mut ok = bytes.len() == config::MASTER_PASSWORD_CHARS;
        let mut pos = 0usize;
        if ok {
            for w in 0..config::MASTER_WORDS {
                if w != 0 {
                    ok = bytes[pos] == b'-';
                    pos += 1;
                }
                for _ in 0..config::MASTER_WORD_BYTES {
                    if ok {
                        let c = bytes[pos];
                        ok = c.is_ascii_lowercase();
                    }
                    pos += 1;
                }
            }
            if ok {
                ok = bytes[pos] == b'-';
                pos += 1;
            }
            for _ in 0..config::MASTER_DIGITS {
                if ok {
                    ok = bytes[pos].is_ascii_digit();
                }
                pos += 1;
            }
            ok = ok && pos == config::MASTER_PASSWORD_CHARS;
        }
        let detail = format!(
            "{} chars, format {}",
            bytes.len(),
            if ok { "ok" } else { "BROKEN" }
        );
        report("gateA-password-format", ok, &detail);
    }

    // Every word must be a dictionary word, not just five letters.
    {
        let pw = auth.generate_master_password();
        let bytes = pw.as_bytes();
        let mut ok = true;
        let mut hits = 0u32;
        for w in 0..config::MASTER_WORDS {
            if !ok {
                break;
            }
            let off = w * wordlist::WORD_STRIDE;
            let mut found = false;
            for i in 0..wordlist::WORD_COUNT {
                if wordlist::word(i) == &bytes[off..off + wordlist::WORD_BYTES] {
                    found = true;
                    hits += 1;
                    break;
                }
            }
            ok = found;
        }
        let detail = format!(
            "{}/{} words found in dictionary",
            hits,
            config::MASTER_WORDS
        );
        report("gateA2-words-in-dict", ok, &detail);
    }

    // Word-index bias, checked deterministically.
    {
        const SRC_LEN: usize = 4 * config::MASTER_WORDS + config::MASTER_DIGITS;
        let mut hi = [0xFFu8; SRC_LEN];
        let mut lo = [0x00u8; SRC_LEN];
        let mut tail = [0x00u8; SRC_LEN];
        let mut tail2 = [0x00u8; SRC_LEN];
        tail[0] = 0x03;
        tail[1] = 0x00;
        tail[2] = 0x10;
        tail[3] = 0x00; // (1<<20)|3 -> index 1
        tail2[0] = 0x03;
        tail2[1] = 0x00;
        tail2[2] = 0x20;
        tail2[3] = 0x00; // (2<<20)|3 -> index 2
        hi[SRC_LEN - 2] = 5;
        hi[SRC_LEN - 1] = 6;
        lo[SRC_LEN - 2] = 5;
        lo[SRC_LEN - 1] = 6;
        tail[SRC_LEN - 2] = 5;
        tail[SRC_LEN - 1] = 6;
        tail2[SRC_LEN - 2] = 5;
        tail2[SRC_LEN - 1] = 6;

        let hi_ok = generate_password_string(&mut CycleSource::new(&hi))
            .as_bytes()
            .starts_with(wordlist::word(wordlist::WORD_COUNT - 1));
        let lo_ok = generate_password_string(&mut CycleSource::new(&lo))
            .as_bytes()
            .starts_with(wordlist::word(0));
        let tail_ok = generate_password_string(&mut CycleSource::new(&tail))
            .as_bytes()
            .starts_with(wordlist::word(1));
        let tail2_ok = generate_password_string(&mut CycleSource::new(&tail2))
            .as_bytes()
            .starts_with(wordlist::word(2));

        let detail = format!(
            "max {} min {} shift1e6->1 {} shift2e6->2 {}",
            hi_ok as u8, lo_ok as u8, tail_ok as u8, tail2_ok as u8
        );
        report(
            "gateA3-word-bias",
            hi_ok && lo_ok && tail_ok && tail2_ok,
            &detail,
        );
    }

    // Digit rejection: 251 must be dropped, not turned into 1.
    {
        const SRC_LEN: usize = 4 * config::MASTER_WORDS + config::MASTER_DIGITS;
        let mut digits = [0x00u8; SRC_LEN];
        digits[SRC_LEN - 2] = 251; // must be rejected
        digits[SRC_LEN - 1] = 7;
        digits[0] = 6; // second digit wraps to byte 0
        let pw = generate_password_string(&mut CycleSource::new(&digits));
        let b = pw.as_bytes();
        let d1 = b[config::MASTER_PASSWORD_CHARS - 2] == b'7';
        let d2 = b[config::MASTER_PASSWORD_CHARS - 1] == b'6';
        let detail = format!(
            "251 rejected, got '{}{}' (want '76')",
            b[config::MASTER_PASSWORD_CHARS - 2] as char,
            b[config::MASTER_PASSWORD_CHARS - 1] as char
        );
        report("gateA4-digit-bias", d1 && d2, &detail);
    }

    // Real provisioning: the password is delivered exactly once.
    let good = {
        let (job, req) = auth.submit_provision(&[]);
        let mut ok = job != NO_JOB;
        if let Some(req) = req.as_ref() {
            auth.run(vault, req);
        }
        let (res, good) = match auth.poll(job) {
            Some(v) => (v.result, String::from_utf8_lossy(&v.password).into_owned()),
            None => (JobResult::Error, String::new()),
        };
        ok = ok && res == JobResult::Ok;
        let n = if ok { good.len() } else { 0 };
        ok = ok && n == config::MASTER_PASSWORD_CHARS;

        let second_ok = auth
            .poll(job)
            .map(|v| v.password.is_empty())
            .unwrap_or(false);
        let detail = format!(
            "result {} len {}, second poll empty {}",
            res.as_str(),
            n,
            second_ok as u8
        );
        report("gateB-provision-once", ok && second_ok, &detail);

        let again = auth.submit_provision(&[]);
        let refused = again.0 == NO_JOB && vault.provisioned();
        report(
            "gateB2-no-reprovision",
            refused,
            if refused {
                "refused, vault intact"
            } else {
                "ACCEPTED"
            },
        );
        good
    };

    // The vault is now under `good`; vault gates open it with the same password.
    *gate_pw = good.clone();

    {
        auth.lock(vault);
        let sub = auth.submit_unlock(&good, &[]);
        let view = wait_job(auth, vault, sub);
        let (ujob_ok, ures) = match view {
            Some(v) => (true, v.result),
            None => (false, JobResult::Error),
        };
        let unlocked = ujob_ok && ures == JobResult::Ok;
        report("gateC-unlock", unlocked, ures.as_str());

        // Session token: valid accepted, altered rejected, locked dead.
        let tok = auth.session_token_hex();
        let have_tok = tok.is_some();
        let ok_tok = tok
            .as_deref()
            .map(|t| auth.session_valid(t))
            .unwrap_or(false);
        let bad = tok
            .as_deref()
            .map(|t| {
                let first = if t.starts_with('a') { "b" } else { "a" };
                format!("{first}{}", &t[1..])
            })
            .unwrap_or_default();
        let bad_tok = !(have_tok && auth.session_valid(&bad));
        let not_hex = "z".repeat(SESSION_TOKEN_HEX_LEN);
        let not_hex_rejected = !auth.session_valid(&not_hex);
        report(
            "gateC2-token",
            ok_tok && bad_tok && not_hex_rejected,
            "valid/bad-char/non-hex checked",
        );

        auth.lock(vault);
        let dead_after_lock =
            !auth.session_valid(tok.as_deref().unwrap_or("")) && auth.session_token_hex().is_none();
        report(
            "gateC3-lock",
            dead_after_lock,
            if dead_after_lock {
                "token dead"
            } else {
                "TOKEN SURVIVED"
            },
        );

        // Wrong password: fail count grows, provisioned stays, state Locked.
        let before = auth.state().fail_count;
        let sub = auth.submit_unlock(GATE_PASSWORD_WRONG, &[]);
        let view = wait_job(auth, vault, sub);
        let (wjob_ok, wres) = match view {
            Some(v) => (true, v.result),
            None => (false, JobResult::Error),
        };
        let st = auth.state();
        let wrong_ok = wjob_ok
            && wres == JobResult::WrongPassword
            && st.fail_count == before + 1
            && st.provisioned
            && !st.unlocked;
        let detail = format!(
            "result {} fails {}->{} prov {}",
            wres.as_str(),
            before,
            st.fail_count,
            st.provisioned as u8
        );
        report("gateD-wrongpw", wrong_ok, &detail);

        // Lockout: after AUTH_MAX_FAIL failures the correct password is refused.
        while auth.state().lockout_ms_left == 0 && auth.state().fail_count < config::AUTH_MAX_FAIL {
            let sub = auth.submit_unlock(GATE_PASSWORD_WRONG, &[]);
            let _ = wait_job(auth, vault, sub);
        }
        let locked_job = auth.submit_unlock(&good, &[]);
        let lockout_held = locked_job.0 == NO_JOB && auth.state().lockout_ms_left > 0;
        report(
            "gateD2-lockout",
            lockout_held,
            if lockout_held {
                "correct password refused while locked out"
            } else {
                "LOCKOUT NOT HELD"
            },
        );

        // Length errors: empty and oversized are rejected on input.
        auth.clear_lockout();
        let empty_rejected = auth.submit_unlock("", &[]).0 == NO_JOB;
        let too_long = "x".repeat(config::MAX_PASS_CHARS + 1);
        let long_rejected = auth.submit_unlock(&too_long, &[]).0 == NO_JOB;
        report(
            "gateE-input-limits",
            empty_rejected && long_rejected,
            "empty and oversized rejected",
        );

        // Idle expiry: zero TTL closes the session.
        let sub = auth.submit_unlock(&good, &[]);
        let view = wait_job(auth, vault, sub);
        let was_open = view.map(|v| v.result == JobResult::Ok).unwrap_or(false);
        auth.expire_idle_session(vault, 0);
        let idle_closed = was_open && !auth.state().unlocked;
        report(
            "gateF-idle-lock",
            idle_closed,
            if idle_closed {
                "closed on idle"
            } else {
                "STILL OPEN"
            },
        );

        // Job secrets are delivered exactly once.
        {
            let sub = auth.submit_unlock(&good, &[]);
            let (sjob, req) = sub;
            if let Some(req) = req.as_ref() {
                auth.run(vault, req);
            }
            let sv1 = auth.poll(sjob);
            let sv2 = auth.poll(sjob);
            let second_empty =
                sjob != NO_JOB && sv2.map(|v| v.session_token.is_empty()).unwrap_or(false);
            let tok_usable = match &sv1 {
                Some(v) => {
                    v.result == JobResult::Ok
                        && !v.session_token.is_empty()
                        && auth.session_valid(core::str::from_utf8(&v.session_token).unwrap_or(""))
                }
                None => false,
            };
            report(
                "gateE2-one-shot-token",
                second_empty && tok_usable,
                if second_empty && tok_usable {
                    "delivered once, usable"
                } else {
                    "STILL REDELIVERED"
                },
            );
            auth.lock(vault);
        }

        let end_state = !auth.state().unlocked && vault.provisioned();
        report("gateG-final-state", end_state, "locked, still provisioned");
    }
}

// ── Key-file gates ──────────────────────────────────────────────────────────

fn keyfile_gates(vault: &mut WorkerVault, auth: &mut WorkerAuth, gate_pw: &str) {
    log::info!("=== keyfile gates ===");

    let file_a: [u8; 32] = core::array::from_fn(|i| i as u8);
    let file_b: [u8; 32] = core::array::from_fn(|i| (0x1f - i) as u8);
    let mut rng = EspRng::new();

    let probe_id = {
        let rc = vault.clear(gate_pw, Some(&file_a), &mut rng);
        let flag = vault.key_file_required();
        let mut e = Entry::new();
        fill_entry(&mut e, 0, "keyfile");
        let (add_rc, id) = if rc == VaultError::Ok {
            match vault.add(&e) {
                Ok(id) => (VaultError::Ok, id),
                Err(er) => (er, 0),
            }
        } else {
            (rc, 0)
        };
        let detail = format!(
            "clear {}, flag {}, entry {}",
            rc.to_str(),
            flag as u8,
            add_rc.to_str()
        );
        report(
            "gateK1-keyfile-provision",
            rc == VaultError::Ok && flag && add_rc == VaultError::Ok && id != 0,
            &detail,
        );
        if rc != VaultError::Ok {
            return;
        }
        id
    };

    // Unlock through the auth pipeline with the key file.
    {
        auth.lock(vault);
        let sub = auth.submit_unlock(gate_pw, &file_a);
        let view = wait_job(auth, vault, sub);
        let (polled, res) = match view {
            Some(v) => (true, v.result),
            None => (false, JobResult::Error),
        };
        let mut get_ok = false;
        if polled && res == JobResult::Ok {
            get_ok = vault
                .get(probe_id)
                .map(|got| got.get(Field::Title) == b"gate-keyfile")
                .unwrap_or(false);
        }
        let detail = format!(
            "unlock {}, entry {}",
            if polled { res.as_str() } else { "not polled" },
            if get_ok { "ok" } else { "lost" }
        );
        report(
            "gateK2-keyfile-unlock",
            polled && res == JobResult::Ok && get_ok && auth.state().unlocked,
            &detail,
        );
    }

    // Same password without the file must fail.
    auth.lock(vault);
    {
        let sub = auth.submit_unlock(gate_pw, &[]);
        let view = wait_job(auth, vault, sub);
        let (polled, res) = match view {
            Some(v) => (true, v.result),
            None => (false, JobResult::Error),
        };
        report(
            "gateK3-keyfile-no-file",
            polled && res == JobResult::WrongPassword && !auth.state().unlocked,
            if polled { res.as_str() } else { "not polled" },
        );
    }

    // A foreign file must fail the same way.
    {
        let sub = auth.submit_unlock(gate_pw, &file_b);
        let view = wait_job(auth, vault, sub);
        let (polled, res) = match view {
            Some(v) => (true, v.result),
            None => (false, JobResult::Error),
        };
        auth.clear_lockout();
        report(
            "gateK4-keyfile-wrong-file",
            polled && res == JobResult::WrongPassword && !auth.state().unlocked,
            if polled { res.as_str() } else { "not polled" },
        );
    }

    // Restore the vault without the file, needed by resetGates().
    {
        vault.close();
        let open_rc = vault.begin(gate_pw, Some(&file_a), &mut rng);
        let clear_rc = if open_rc == VaultError::Ok {
            vault.clear(gate_pw, None, &mut rng)
        } else {
            open_rc
        };
        let flag_gone = !vault.key_file_required();
        let prov = vault.provisioned();
        vault.close();
        let detail = format!(
            "open {}, clear {}, flag {}, prov {}",
            open_rc.to_str(),
            clear_rc.to_str(),
            flag_gone as u8,
            prov as u8
        );
        report(
            "gateK5-keyfile-restore",
            open_rc == VaultError::Ok && clear_rc == VaultError::Ok && flag_gone && prov,
            &detail,
        );
    }
}

// ── Rekey gates ─────────────────────────────────────────────────────────────

fn rekey_gates(vault: &mut WorkerVault, auth: &mut WorkerAuth, gate_pw: &str) {
    log::info!("=== rekey gates ===");

    let mut rng = EspRng::new();

    // R1: rekey on a closed vault must be Refused, not Error or Ok.
    vault.close();
    {
        let sub = auth.submit_rekey(gate_pw, Some(REKEY_PASSWORD), &[], &[], KeyfileAction::Keep);
        let view = wait_job(auth, vault, sub);
        let (polled, res, kind) = match view {
            Some(v) => (true, v.result, Some(v.kind)),
            None => (false, JobResult::Error, None),
        };
        report(
            "gateR1-rekey-refused-closed",
            polled && res == JobResult::Refused && kind == Some(Job::Rekey),
            if polled { res.as_str() } else { "not polled" },
        );
    }

    // R2: rekey through the pipeline on a live session; the session survives.
    {
        let sub = auth.submit_unlock(gate_pw, &[]);
        let view = wait_job(auth, vault, sub);
        let (unlocked, ures) = match view {
            Some(v) => (v.result == JobResult::Ok, v.result),
            None => (false, JobResult::Error),
        };

        // The record is added before the change: rekey must rewrap every live
        // record under the new key.
        let mut e = Entry::new();
        fill_entry(&mut e, 0, "rekey");
        let (add_rc, probe_id) = if unlocked {
            match vault.add(&e) {
                Ok(id) => (VaultError::Ok, id),
                Err(er) => (er, 0),
            }
        } else {
            (VaultError::BootStrap, 0)
        };

        let sub = auth.submit_rekey(gate_pw, Some(REKEY_PASSWORD), &[], &[], KeyfileAction::Keep);
        let view = wait_job(auth, vault, sub);
        let (polled, res) = match view {
            Some(v) => (true, v.result),
            None => (false, JobResult::Error),
        };
        let session_alive = auth.state().unlocked && auth.session_token_hex().is_some();
        let detail = format!(
            "unlock {}, add {}, rekey {}, session {}",
            if polled && unlocked {
                ures.as_str()
            } else {
                "fail"
            },
            add_rc.to_str(),
            if polled { res.as_str() } else { "not polled" },
            session_alive as u8
        );
        report(
            "gateR2-rekey-ok",
            unlocked
                && add_rc == VaultError::Ok
                && polled
                && res == JobResult::Ok
                && session_alive
                && probe_id != 0,
            &detail,
        );

        // R3 + R4: old password rejected, new one opens, record survives.
        vault.close();
        let old_rc = vault.begin(gate_pw, None, &mut rng);
        vault.close();
        let new_rc = vault.begin(REKEY_PASSWORD, None, &mut rng);
        let data_ok = if new_rc == VaultError::Ok {
            match vault.get(probe_id) {
                Ok(got) => {
                    got.get(Field::Title) == b"gate-rekey"
                        && got.get(Field::Tags) == b"tag-rekey,shared"
                }
                Err(_) => false,
            }
        } else {
            false
        };
        let detail34 = format!(
            "old {} new {} entry {}",
            old_rc.to_str(),
            new_rc.to_str(),
            data_ok as u8
        );
        report(
            "gateR3-rekey-old-pw-rejected",
            old_rc == VaultError::WrongPassword,
            &detail34,
        );
        report(
            "gateR4-rekey-data-survives",
            new_rc == VaultError::Ok && data_ok,
            &detail34,
        );

        // R5: restore the gate password directly through vault::rekey.
        let back_rc = if new_rc == VaultError::Ok {
            vault.rekey(gate_pw, None, &mut rng)
        } else {
            VaultError::BootStrap
        };
        let flag = vault.key_file_required();
        let prov = vault.provisioned();
        vault.close();
        let detail5 = format!(
            "back {}, flag {}, prov {}",
            back_rc.to_str(),
            flag as u8,
            prov as u8
        );
        report(
            "gateR5-rekey-restore",
            back_rc == VaultError::Ok && !flag && prov,
            &detail5,
        );
    }
}

// ── Reset gate ──────────────────────────────────────────────────────────────

fn reset_gates(vault: &mut WorkerVault, auth: &mut WorkerAuth, gate_pw: &str) {
    let sub = auth.submit_unlock(gate_pw, &[]);
    let view = wait_job(auth, vault, sub);
    let (ures, unlocked) = match view {
        Some(v) => (v.result, auth.state().unlocked),
        None => (JobResult::Error, false),
    };
    report(
        "gateH1-unlock-before-reset",
        ures == JobResult::Ok && unlocked,
        if ures == JobResult::Ok {
            "vault unlocked"
        } else {
            ures.as_str()
        },
    );
    if ures != JobResult::Ok {
        return;
    }

    // A doomed record: reset must take it away, verified from flash.
    {
        let mut e = Entry::new();
        e.set(Field::Title, b"doomed");
        e.set(Field::Login, b"doomed");
        e.set(Field::Password, b"doomed-secret");
        let rc = vault.add(&e);
        let detail = match &rc {
            Ok(_) => "ok",
            Err(er) => er.to_str(),
        };
        report("gateH2-entry-before-reset", rc.is_ok(), detail);
    }

    let session_was_open = auth.state().unlocked;
    report(
        "gateH2b-session-before-reset",
        session_was_open,
        if session_was_open { "open" } else { "closed" },
    );

    let sub = auth.submit_reset();
    let view = wait_job(auth, vault, sub);
    let (polled, res) = match view {
        Some(v) => (true, v.result),
        None => (false, JobResult::Error),
    };
    report(
        "gateH3-reset-ok",
        polled && res == JobResult::Ok && !vault.provisioned(),
        if polled { res.as_str() } else { "not polled" },
    );

    let after_reset = auth.state();
    let h4 = session_was_open
        && !after_reset.provisioned
        && !after_reset.unlocked
        && auth.session_token_hex().is_none();
    report("gateH4-session-closed", h4, "no session, no token");

    let sub = auth.submit_reset();
    let view = wait_job(auth, vault, sub);
    let (polled2, res2, kind2) = match view {
        Some(v) => (true, v.result, Some(v.kind)),
        None => (false, JobResult::Error, None),
    };
    report(
        "gateH5-reset-refused-when-empty",
        polled2 && res2 == JobResult::Refused && kind2 == Some(Job::Reset),
        if polled2 { res2.as_str() } else { "not polled" },
    );
}

// ── Entry point ─────────────────────────────────────────────────────────────

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
