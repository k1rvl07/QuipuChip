//! Vault lifecycle over the public API, with reboots simulated by handing a
//! fresh `Vault` the raw flash image.
//!
//! `MemStorage` is the in-memory stand-in for the SPI flash partition: writes
//! can only clear bits and erase restores `0xFF`. A reboot is therefore a new
//! `Vault` over the *same* bytes, which is exactly what the device does after a
//! reset.

#![cfg(feature = "test-utils")]
#![allow(clippy::unwrap_used)]

use pm_core::config::{
    MAX_ENTRIES, MAX_ENTRY_LEN, MIN_PASS_CHARS, PBKDF2_ITERS, VAULT_LIVE_BUDGET_BYTES,
};
use pm_core::entry::{Entry, Field};
use pm_core::rand::CycleSource;
use pm_core::testutil::{MemStorage, TEST_MAC, vault};
use pm_core::types::{State, VaultError};
use pm_core::vault::Vault;

const SALT_BYTES: &[u8] = b"integration-lifecycle-salt-material-0123456789";
const PW: &str = "correct horse battery staple";
const PW2: &str = "another correct battery staple";

fn rng() -> CycleSource<'static> {
    CycleSource::new(SALT_BYTES)
}

fn entry(title: &str, password: &str) -> Entry {
    let mut e = Entry::new();
    e.set(Field::Title, title.as_bytes());
    e.set(Field::Password, password.as_bytes());
    e
}

/// Reopens a vault over a byte copy of its flash image, as a reset would.
fn reboot(v: &Vault<MemStorage>, password: &str, key_file: Option<&[u8]>) -> Vault<MemStorage> {
    let image = v.storage_ref().to_bytes();
    let mut next = Vault::new(MemStorage::from_bytes(image), TEST_MAC);
    assert_eq!(next.begin(password, key_file, &mut rng()), VaultError::None);
    next
}

fn all_fields() -> Entry {
    let mut e = Entry::new();
    e.set(Field::Title, "Все поля / all fields".as_bytes());
    e.set(Field::Login, "user@example.com".as_bytes());
    e.set(Field::Password, "hunter2 with spaces".as_bytes());
    e.set(Field::Url, "https://example.com/login?a=1&b=2".as_bytes());
    e.set(Field::Note, "line one\nline two\ttabbed".as_bytes());
    e.set(Field::Tags, "work personal".as_bytes());
    e.set(Field::Totp, b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    e.set(Field::TotpDigits, b"8");
    e.set(Field::TotpPeriod, b"60");
    e
}

/// An entry whose serialized payload is exactly `ENTRY_PAYLOAD_MAX`: every
/// field is filled to its capacity.
fn max_size_entry() -> Entry {
    let mut e = Entry::new();
    for (field, byte) in [
        (Field::Title, b'T'),
        (Field::Login, b'L'),
        (Field::Password, b'P'),
        (Field::Url, b'U'),
        (Field::Note, b'N'),
        (Field::Tags, b'G'),
        (Field::Totp, b'A'),
        (Field::TotpDigits, b'8'),
        (Field::TotpPeriod, b'6'),
    ] {
        let cap = e.raw(field).len();
        e.set(field, &vec![byte; cap]);
    }
    e
}

fn fields_of(e: &Entry) -> Vec<Vec<u8>> {
    [
        Field::Title,
        Field::Login,
        Field::Password,
        Field::Url,
        Field::Note,
        Field::Tags,
        Field::Totp,
        Field::TotpDigits,
        Field::TotpPeriod,
    ]
    .iter()
    .map(|f| e.get(*f).to_vec())
    .collect()
}

#[test]
fn every_field_survives_a_reboot_byte_for_byte() {
    let mut v = vault();
    assert_eq!(v.begin(PW, None, &mut rng()), VaultError::None);
    let id = v.add(&all_fields()).unwrap();
    v.close();

    let v = reboot(&v, PW, None);
    let got = v.get(id).unwrap();
    assert_eq!(fields_of(&got), fields_of(&all_fields()));
}

#[test]
fn a_multi_step_lifecycle_survives_repeated_reboots() {
    let mut v = vault();
    assert_eq!(v.begin(PW, None, &mut rng()), VaultError::None);

    let a = v.add(&entry("Mail", "pw-a")).unwrap();
    let b = v.add(&entry("Bank", "pw-b")).unwrap();
    let c = v.add(&entry("Git", "pw-c")).unwrap();
    assert_eq!((a, b, c), (1, 2, 3));

    // Update id 2, remove id 1.
    let mut upd = v.get(b).unwrap();
    upd.set(Field::Password, b"pw-b-new");
    assert_eq!(v.add(&upd), Ok(b));
    assert_eq!(v.remove(a), VaultError::None);

    let mut v = reboot(&v, PW, None);
    assert_eq!(v.count(), 2);
    assert_eq!(v.get(b).unwrap().get(Field::Password), b"pw-b-new");
    assert_eq!(v.get(a), Err(VaultError::NotFound));
    assert_eq!(v.get(c).unwrap().get(Field::Title), b"Git");

    // A second reboot after another mutation must be just as clean.
    let d = v.add(&entry("After", "pw-d")).unwrap();
    assert_ne!(d, a, "a removed id must not be reused");
    v.close();
    let v = reboot(&v, PW, None);
    assert_eq!(v.count(), 3);
    assert_eq!(v.get(d).unwrap().get(Field::Title), b"After");
}

#[test]
fn ids_keep_increasing_across_reboots_and_are_never_reused() {
    let mut v = vault();
    assert_eq!(v.begin(PW, None, &mut rng()), VaultError::None);
    let first = v.add(&entry("one", "p")).unwrap();
    assert_eq!(v.remove(first), VaultError::None);
    let second = v.add(&entry("two", "p")).unwrap();
    assert!(second > first);

    let mut v = reboot(&v, PW, None);
    let third = v.add(&entry("three", "p")).unwrap();
    assert!(third > second, "next_id must persist across a reboot");
}

#[test]
fn load_honours_its_limit_and_returns_every_live_entry() {
    let mut v = vault();
    assert_eq!(v.begin(PW, None, &mut rng()), VaultError::None);
    for i in 0..5 {
        v.add(&entry(&format!("e{i}"), "p")).unwrap();
    }
    assert_eq!(v.load(MAX_ENTRIES as usize).unwrap().len(), 5);
    assert_eq!(v.load(3).unwrap().len(), 3);
    assert_eq!(v.load(0).unwrap().len(), 0);

    // Removing an entry makes it disappear from `load`, not just from `count`.
    assert_eq!(v.remove(3), VaultError::None);
    let titles: Vec<Vec<u8>> = v
        .load(MAX_ENTRIES as usize)
        .unwrap()
        .iter()
        .map(|e| e.get(Field::Title).to_vec())
        .collect();
    assert_eq!(titles.len(), 4);
    assert!(!titles.iter().any(|t| t == b"e2"));
}

#[test]
fn a_key_file_is_required_once_it_was_used() {
    let kf = b"raw key file material for the integration test";
    let mut v = vault();
    assert_eq!(v.begin(PW, Some(kf), &mut rng()), VaultError::None);
    assert!(v.key_file_required());
    v.add(&entry("Mail", "pw")).unwrap();

    // Without the file the password alone is not enough.
    let mut copy = Vault::new(MemStorage::from_bytes(v.storage_ref().to_bytes()), TEST_MAC);
    assert_eq!(copy.begin(PW, None, &mut rng()), VaultError::WrongPassword);
    // A different file is just as wrong as none.
    let mut copy = Vault::new(MemStorage::from_bytes(v.storage_ref().to_bytes()), TEST_MAC);
    assert_eq!(
        copy.begin(PW, Some(b"different key file"), &mut rng()),
        VaultError::WrongPassword
    );
    // The right pair opens it.
    let v = reboot(&v, PW, Some(kf));
    assert!(v.key_file_required());
    assert_eq!(v.count(), 1);
}

#[test]
fn rekey_switches_password_and_key_file_together() {
    let old_kf = b"old key file material";
    let new_kf = b"new key file material";
    let mut v = vault();
    assert_eq!(v.begin(PW, Some(old_kf), &mut rng()), VaultError::None);
    v.add(&entry("Mail", "pw")).unwrap();
    let generation_before = v.stats().generation;

    assert_eq!(v.rekey(PW2, Some(new_kf), &mut rng()), VaultError::None);
    assert!(
        v.stats().generation > generation_before,
        "rekey bumps generation"
    );
    // The current session stays open and reads the new key.
    assert_eq!(v.count(), 1);

    // The old pair is refused, the new pair opens the vault.
    let image = v.storage_ref().to_bytes();
    let mut stale = Vault::new(MemStorage::from_bytes(image.clone()), TEST_MAC);
    assert_eq!(
        stale.begin(PW, Some(old_kf), &mut rng()),
        VaultError::WrongPassword
    );
    let mut fresh = Vault::new(MemStorage::from_bytes(image), TEST_MAC);
    assert_eq!(fresh.begin(PW2, Some(new_kf), &mut rng()), VaultError::None);
    assert_eq!(fresh.count(), 1);
}

#[test]
fn rekey_can_drop_the_key_file() {
    let mut v = vault();
    assert_eq!(
        v.begin(PW, Some(b"key file to drop"), &mut rng()),
        VaultError::None
    );
    v.add(&entry("Mail", "pw")).unwrap();
    assert_eq!(v.rekey(PW, None, &mut rng()), VaultError::None);
    assert!(!v.key_file_required());

    let v = reboot(&v, PW, None);
    assert!(!v.key_file_required());
    assert_eq!(v.count(), 1);
}

#[test]
fn clear_reprovisions_and_keeps_only_the_new_entries() {
    let mut v = vault();
    assert_eq!(v.begin(PW, None, &mut rng()), VaultError::None);
    v.add(&entry("secret", "pw")).unwrap();

    assert_eq!(v.clear(PW2, None, &mut rng()), VaultError::None);
    assert_eq!(v.count(), 0);
    assert_eq!(v.get(1), Err(VaultError::NotFound));

    // The old password no longer opens the cleared vault.
    let image = v.storage_ref().to_bytes();
    let mut stale = Vault::new(MemStorage::from_bytes(image.clone()), TEST_MAC);
    assert_eq!(stale.begin(PW, None, &mut rng()), VaultError::WrongPassword);

    let mut fresh = Vault::new(MemStorage::from_bytes(image), TEST_MAC);
    assert_eq!(fresh.begin(PW2, None, &mut rng()), VaultError::None);
    assert_eq!(fresh.count(), 0);
    fresh.add(&entry("new", "pw")).unwrap();
    fresh.close();
    let fresh = reboot(&fresh, PW2, None);
    assert_eq!(fresh.count(), 1);
}

#[test]
fn a_wrong_password_never_destroys_or_reprovisions() {
    let mut v = vault();
    assert_eq!(v.begin(PW, None, &mut rng()), VaultError::None);
    v.add(&entry("Mail", "pw")).unwrap();
    v.close();
    assert_eq!(v.snapshot().state, State::Locked);

    assert_eq!(
        v.begin("wrong password", None, &mut rng()),
        VaultError::WrongPassword
    );
    assert!(v.provisioned());
    assert_eq!(v.count(), 0, "a failed begin leaves no entries visible");
    assert_eq!(v.snapshot().state, State::Locked);

    // The real password still works and the data is intact.
    assert_eq!(v.begin(PW, None, &mut rng()), VaultError::None);
    assert_eq!(v.count(), 1);
    assert_eq!(v.snapshot().state, State::Unlocked);
}

#[test]
fn password_length_bounds_are_enforced_by_begin() {
    let mut v = vault();
    let short = "x".repeat(MIN_PASS_CHARS - 1);
    assert_eq!(v.begin(&short, None, &mut rng()), VaultError::WrongPassword);
    assert!(!v.provisioned());
    // At the limit it is accepted (the reference uses [MIN, MAX)).
    let ok = "x".repeat(MIN_PASS_CHARS);
    assert_eq!(v.begin(&ok, None, &mut rng()), VaultError::None);
}

#[test]
fn reset_returns_the_partition_to_the_unprovisioned_state() {
    let mut v = vault();
    assert_eq!(v.begin(PW, None, &mut rng()), VaultError::None);
    v.add(&entry("Mail", "pw")).unwrap();
    assert_eq!(v.reset(), VaultError::None);
    assert!(!v.provisioned());
    assert_eq!(v.snapshot().state, State::Unprovisioned);
    assert_eq!(v.count(), 0);

    // A fresh provision works and starts from id 1.
    assert_eq!(v.begin(PW2, None, &mut rng()), VaultError::None);
    assert_eq!(v.add(&entry("New", "pw")), Ok(1));
}

#[test]
fn the_counters_stay_consistent_with_the_contents() {
    let mut v = vault();
    assert_eq!(v.begin(PW, None, &mut rng()), VaultError::None);
    for i in 0..10 {
        v.add(&entry(&format!("t{i}"), "password")).unwrap();
    }
    let st = v.stats();
    assert_eq!(st.entry_count, v.count());
    assert_eq!(st.entry_count, 10);
    assert!(st.used_bytes > 0);
    assert_eq!(st.generation, 1);
    assert_eq!(v.snapshot().entry_count, st.entry_count);
    assert_eq!(v.snapshot().live_bytes, st.live_bytes);

    let payload: usize = v
        .load(MAX_ENTRIES as usize)
        .unwrap()
        .iter()
        .map(|e| {
            let mut buf = vec![0u8; MAX_ENTRY_LEN];
            e.serialize(&mut buf).unwrap()
        })
        .sum();
    assert!(st.live_bytes >= payload, "live_bytes covers the payloads");
    assert!(st.live_bytes <= VAULT_LIVE_BUDGET_BYTES);
}

#[test]
fn the_journal_is_compacted_before_it_fills_the_region() {
    let mut v = vault();
    assert_eq!(v.begin(PW, None, &mut rng()), VaultError::None);
    // A record at the payload maximum: the journal fills in ~115 of these,
    // which is before the live-byte budget refuses the next one.
    let full = max_size_entry();
    for i in 0..250 {
        if let Err(err) = v.add(&full) {
            panic!("add #{i} failed unexpectedly: {err:?}");
        }
        if v.stats().compacted_once {
            break;
        }
    }
    let st = v.stats();
    assert!(
        st.compacted_once,
        "the journal must be compacted, not filled"
    );
    // Compaction keeps every live entry readable.
    let loaded = v.load(MAX_ENTRIES as usize).unwrap();
    assert_eq!(loaded.len() as u32, v.count());
}

#[test]
fn the_pbkdf2_iteration_default_is_the_reference_value() {
    // Not a performance assertion: a change here would silently change the
    // on-flash key derivation and make every existing vault unreadable.
    assert_eq!(PBKDF2_ITERS, 30_000);
}
