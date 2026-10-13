//! End-to-end flow over the public API, driven by the in-memory storage.
//!
//! Gated on the `test-utils` feature so a plain `cargo test -p pm-core` still
//! builds; run the real thing with
//! `cargo test -p pm-core --features test-utils`.

#![cfg(feature = "test-utils")]

use pm_core::auth::{Auth, JobResult, ManualClock, NO_JOB, SESSION_TOKEN_HEX_LEN};
use pm_core::config::{MASTER_PASSWORD_CHARS, MAX_ENTRIES};
use pm_core::entry::{Entry, Field};
use pm_core::rand::CycleSource;
use pm_core::testutil::vault;
use pm_core::types::VaultError;

const SALT_BYTES: &[u8] = b"integration-salt-material-0123456789";

#[test]
fn provision_unlock_add_export_round_trip() {
    let mut a = Auth::new(CycleSource::new(SALT_BYTES), ManualClock::new(1_000));
    let mut v = vault();
    a.initialize(&v);

    let (id, req) = a.submit_provision(&[], false);
    assert_ne!(id, NO_JOB);
    a.run(&mut v, req.as_ref().unwrap());
    let view = a.poll(id).unwrap();
    assert_eq!(view.result, JobResult::Ok);
    let pw = String::from_utf8(view.password.clone()).unwrap();
    assert_eq!(pw.len(), MASTER_PASSWORD_CHARS);
    assert_eq!(view.session_token.len(), SESSION_TOKEN_HEX_LEN);
    assert!(v.provisioned());

    let mut e = Entry::new();
    e.set(Field::Title, b"example.com");
    e.set(Field::Login, b"alice");
    e.set(Field::Password, b"hunter2");
    let eid = v.add(&e).unwrap();

    let got = v.get(eid).unwrap();
    assert_eq!(got.get(Field::Title), b"example.com");
    assert_eq!(got.get_str(Field::Login).unwrap(), "alice");

    let all = v.load(MAX_ENTRIES as usize).unwrap();
    assert_eq!(all.len(), 1);
    let doc = pm_core::export::export_document(&all);
    let imported = pm_core::export::parse_import_bytes(doc.as_bytes()).unwrap();
    assert_eq!(imported.len(), 1);
    assert_eq!(imported[0].get(Field::Password), b"hunter2");

    a.lock(&mut v);
    assert!(!a.state().unlocked);
    let (uid, ureq) = a.submit_unlock(&pw, &[]);
    assert_ne!(uid, NO_JOB);
    a.run(&mut v, ureq.as_ref().unwrap());
    assert_eq!(a.poll(uid).unwrap().result, JobResult::Ok);
    assert!(a.state().unlocked);

    assert_eq!(v.remove(eid), VaultError::None);
    assert_eq!(v.count(), 0);
}
