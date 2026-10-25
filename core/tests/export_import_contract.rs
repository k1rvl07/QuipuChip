//! PMX1 export/import contract: JSON shape, field order, limits, validation
//! and round-trip through the vault.

#![cfg(feature = "test-utils")]
#![allow(
    clippy::unwrap_used,
    clippy::format_push_string,
    clippy::items_after_statements
)]

use pm_core::config::IMPORT_BATCH_ENTRIES;
use pm_core::entry::{Entry, Field};
use pm_core::export::{ImportError, encode_entry, export_document, parse_import_bytes};
use pm_core::rand::CycleSource;
use pm_core::testutil::vault;
use pm_core::types::VaultError;

const SALT_BYTES: &[u8] = b"integration-export-salt-material-0123456789";

fn rng() -> CycleSource<'static> {
    CycleSource::new(SALT_BYTES)
}

fn entry(title: &str) -> Entry {
    let mut e = Entry::new();
    e.set(Field::Title, title.as_bytes());
    e.set(Field::Login, b"user");
    e.set(Field::Password, b"pass");
    e.set(Field::Url, b"https://ex");
    e.set(Field::Note, b"note");
    e.set(Field::Tags, b"tag");
    e.set(Field::Totp, b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    e
}

#[test]
fn pmx1_shape_matches_the_contract() {
    let e = entry("Mail");
    let doc = export_document(&[e]);
    let v: serde_json::Value = serde_json::from_str(&doc).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["format"], "PMX1");
    assert_eq!(v["version"], 1);
    assert_eq!(v["count"], 1);
    let arr = v["entries"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    let obj = arr[0].as_object().unwrap();
    assert!(!obj.contains_key("id"));
    // field order matches FIELD_KEYS
    let keys: Vec<String> = obj.keys().cloned().collect();
    assert_eq!(
        keys,
        vec![
            "login",
            "note",
            "password",
            "tags",
            "title",
            "totp",
            "totpDigits",
            "totpPeriod",
            "url"
        ]
    );
    assert_eq!(obj["totpDigits"], "");
    assert_eq!(obj["totpPeriod"], "");
}

#[test]
fn export_encode_includes_totp_params_when_present() {
    let mut e = entry("X");
    e.set(Field::TotpDigits, b"8");
    e.set(Field::TotpPeriod, b"60");
    let json = encode_entry(&e);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["totpDigits"], "8");
    assert_eq!(v["totpPeriod"], "60");
}

#[test]
fn import_rejects_wrong_format_version_and_batch_limits() {
    let bad_fmt = br#"{"format":"BAD","version":1,"entries":[{"title":"x"}]}"#;
    assert_eq!(
        parse_import_bytes(bad_fmt),
        Err(ImportError::FormatRequired)
    );
    let bad_ver = br#"{"format":"PMX1","version":2,"entries":[{"title":"x"}]}"#;
    assert_eq!(
        parse_import_bytes(bad_ver),
        Err(ImportError::VersionUnsupported)
    );
    let empty = br#"{"format":"PMX1","version":1,"entries":[]}"#;
    assert_eq!(parse_import_bytes(empty), Err(ImportError::NothingToImport));
    let no_arr = br#"{"format":"PMX1","version":1}"#;
    assert_eq!(
        parse_import_bytes(no_arr),
        Err(ImportError::EntriesRequired)
    );

    // batch too large
    let mut entries = String::new();
    for i in 0..=IMPORT_BATCH_ENTRIES {
        if i != 0 {
            entries.push(',');
        }
        use core::fmt::Write as _;
        let _ = write!(entries, "{{\"title\":\"{i}\"}}");
    }
    let big = format!("{{\"format\":\"PMX1\",\"version\":1,\"entries\":[{entries}]}}");
    assert_eq!(
        parse_import_bytes(big.as_bytes()),
        Err(ImportError::BatchTooLarge)
    );
}

#[test]
fn import_validates_each_field_and_totp() {
    // not object
    let s = br#"{"format":"PMX1","version":1,"entries":[1]}"#;
    assert_eq!(parse_import_bytes(s), Err(ImportError::EntryNotAnObject));
    // non-string
    let s = br#"{"format":"PMX1","version":1,"entries":[{"title":123}]}"#;
    assert_eq!(
        parse_import_bytes(s),
        Err(ImportError::FieldTooLongOrNotString)
    );
    // null is allowed
    let s = br#"{"format":"PMX1","version":1,"entries":[{"title":"x","login":null}]}"#;
    assert!(parse_import_bytes(s).is_ok());
    // invalid totp secret
    let s = br#"{"format":"PMX1","version":1,"entries":[{"title":"x","totp":"notbase32!!"}]}"#;
    assert_eq!(parse_import_bytes(s), Err(ImportError::TotpSecretInvalid));
    // bad digits/period
    let s = br#"{"format":"PMX1","version":1,"entries":[{"title":"x","totpDigits":"5"}]}"#;
    assert_eq!(parse_import_bytes(s), Err(ImportError::TotpParamsInvalid));
    let s = br#"{"format":"PMX1","version":1,"entries":[{"title":"x","totpPeriod":"9"}]}"#;
    assert_eq!(parse_import_bytes(s), Err(ImportError::TotpParamsInvalid));
}

#[test]
fn import_is_atomic_across_batch() {
    // first ok, second bad -> whole batch rejected
    let s = br#"{"format":"PMX1","version":1,"entries":[{"title":"ok"}, {"title":123}]}"#;
    assert_eq!(
        parse_import_bytes(s),
        Err(ImportError::FieldTooLongOrNotString)
    );
}

#[test]
fn import_round_trip_through_vault_with_new_ids() {
    let mut v = vault();
    assert_eq!(
        v.begin("correct horse battery staple", None, &mut rng()),
        VaultError::None
    );
    let doc = export_document(&[entry("A"), entry("B")]);
    let parsed = parse_import_bytes(doc.as_bytes()).unwrap();
    let mut ids = Vec::new();
    for e in parsed {
        ids.push(v.add(&e).unwrap());
    }
    assert_eq!(ids, vec![1, 2]);
    // re-import into same vault assigns new ids
    let doc = export_document(&[entry("C")]);
    let parsed = parse_import_bytes(doc.as_bytes()).unwrap();
    assert_eq!(v.add(&parsed[0]).unwrap(), 3);
}

#[test]
fn malformed_json_maps_to_format_required() {
    assert_eq!(
        parse_import_bytes(b"not json"),
        Err(ImportError::FormatRequired)
    );
    assert_eq!(parse_import_bytes(b"[]"), Err(ImportError::FormatRequired));
}
