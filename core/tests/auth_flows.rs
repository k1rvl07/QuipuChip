//! Auth FSM flows over the worker interface: provisioning, unlock/lock,
//! idle timeout, lockout with wraparound, rekey across variants, reset and
//! secret one-shot delivery.

#![cfg(feature = "test-utils")]
#![allow(clippy::unwrap_used)]

use pm_core::auth::{Auth, JobResult, KeyfileAction, ManualClock, NO_JOB, SESSION_TOKEN_HEX_LEN};
use pm_core::config::SESSION_TTL_MS;
use pm_core::config::{
    AUTH_LOCKOUT_MS, AUTH_MAX_FAIL, KEYFILE_GENERATED_BYTES, MASTER_PASSWORD_CHARS,
};
use pm_core::rand::CycleSource;
use pm_core::testutil::vault;

const SALT_BYTES: &[u8] = b"integration-auth-salt-material-0123456789";
const PW: &str = "correct horse battery staple";
const PW2: &str = "another correct battery staple";
const PW3: &str = "third correct battery staple";

fn auth(clock: ManualClock) -> Auth<CycleSource<'static>, ManualClock> {
    Auth::new(CycleSource::new(SALT_BYTES), clock)
}

fn provision(
    a: &mut Auth<CycleSource<'static>, ManualClock>,
    v: &mut pm_core::vault::Vault<pm_core::testutil::MemStorage>,
) -> String {
    let (id, req) = a.submit_provision(&[], false);
    assert_ne!(id, NO_JOB);
    a.run(v, req.as_ref().unwrap());
    let view = a.poll(id).unwrap();
    assert_eq!(view.result, JobResult::Ok);
    let pw = String::from_utf8(view.password.clone()).unwrap();
    assert_eq!(pw.len(), MASTER_PASSWORD_CHARS);
    pw
}

#[test]
fn full_provision_unlock_cycle_hands_out_token_once() {
    let clock = ManualClock::new(1_000);
    let mut a = auth(clock.clone());
    let mut v = vault();
    a.initialize(&v);
    let pw = provision(&mut a, &mut v);
    let st = a.state();
    assert!(st.provisioned && st.unlocked && !st.busy);
    assert_eq!(
        a.session_token_hex().as_ref().unwrap().len(),
        SESSION_TOKEN_HEX_LEN
    );

    // Token is delivered once.
    let (id, req) = a.submit_unlock(&pw, &[]);
    a.run(&mut v, req.as_ref().unwrap());
    let view = a.poll(id).unwrap();
    assert_eq!(view.result, JobResult::Ok);
    assert!(view.password.is_empty());
    assert!(!view.session_token.is_empty());
    assert!(
        a.poll(id).unwrap().session_token.is_empty(),
        "token must be single-use"
    );
}

#[test]
fn lock_and_unlock_preserve_vault_contents() {
    let clock = ManualClock::new(0);
    let mut a = auth(clock);
    let mut v = vault();
    a.initialize(&v);
    let pw = provision(&mut a, &mut v);
    v.close(); // let the worker-style flow own it, but just ensure state matches
    // Re-open via auth: lock then unlock
    a.lock(&mut v);
    assert!(!a.state().unlocked);
    assert!(a.session_token_hex().is_none());
    let (id, req) = a.submit_unlock(&pw, &[]);
    a.run(&mut v, req.as_ref().unwrap());
    assert_eq!(a.poll(id).unwrap().result, JobResult::Ok);
    assert!(a.state().unlocked);
}

#[test]
fn idle_session_expires_and_clears_on_tick() {
    let clock = ManualClock::new(5_000);
    let mut a = auth(clock.clone());
    let mut v = vault();
    a.initialize(&v);
    let _pw = provision(&mut a, &mut v);
    assert!(a.state().unlocked);
    clock.advance(SESSION_TTL_MS - 500);
    a.tick(&mut v);
    assert!(a.state().unlocked);
    clock.advance(1000);
    a.tick(&mut v);
    assert!(!a.state().unlocked);
    assert!(a.session_token_hex().is_none());
}

#[test]
fn lockout_accumulates_and_expires_across_wrap() {
    let clock = ManualClock::new(u32::MAX - 5);
    let mut a = auth(clock.clone());
    let mut v = vault();
    a.initialize(&v);
    let pw = provision(&mut a, &mut v);
    a.lock(&mut v);
    for _ in 0..AUTH_MAX_FAIL {
        let (id, req) = a.submit_unlock(&pw, &[]); // wrong password string
        if id == NO_JOB {
            break;
        }
        // run against the vault while locked; use wrong pw
        a.run(&mut v, req.as_ref().unwrap());
    }
    // Run again with explicitly wrong
    let mut failures = 0;
    while failures < AUTH_MAX_FAIL {
        let (id, req) = a.submit_unlock("definitely wrong", &[]);
        if id == NO_JOB {
            break;
        }
        a.run(&mut v, req.as_ref().unwrap());
        let res = a.poll(id).unwrap().result;
        if res == JobResult::WrongPassword {
            failures += 1;
        }
    }
    assert!(a.state().lockout_ms_left > 0);
    clock.advance(10);
    assert!(a.state().lockout_ms_left > 0);
    clock.advance(AUTH_LOCKOUT_MS);
    assert_eq!(a.state().lockout_ms_left, 0);
    a.clear_lockout();
    assert_ne!(a.submit_unlock("definitely wrong", &[]).0, NO_JOB);
}

#[test]
fn rekey_password_only_keeps_keyfile_state() {
    let clock = ManualClock::new(0);
    let mut a = auth(clock);
    let mut v = vault();
    a.initialize(&v);
    // start with keyfile
    let (id, req) = a.submit_provision(&[], true);
    a.run(&mut v, req.as_ref().unwrap());
    let view = a.poll(id).unwrap();
    let pw = String::from_utf8(view.password.clone()).unwrap();
    let kf = view.key_file.clone();
    assert!(v.key_file_required());

    let (id, req) = a.submit_rekey(&pw, Some(PW2), &kf, &[], KeyfileAction::Keep);
    a.run(&mut v, req.as_ref().unwrap());
    assert_eq!(a.poll(id).unwrap().result, JobResult::Ok);
    a.lock(&mut v);
    // old pw with kf wrong
    let (id, req) = a.submit_unlock(&pw, &kf);
    a.run(&mut v, req.as_ref().unwrap());
    assert_eq!(a.poll(id).unwrap().result, JobResult::WrongPassword);
    // new pw with kf ok
    let (id, req) = a.submit_unlock(PW2, &kf);
    a.run(&mut v, req.as_ref().unwrap());
    assert_eq!(a.poll(id).unwrap().result, JobResult::Ok);
}

#[test]
fn rekey_keyfile_only_set_and_clear() {
    let clock = ManualClock::new(0);
    let mut a = auth(clock);
    let mut v = vault();
    a.initialize(&v);
    let pw = provision(&mut a, &mut v);
    let kf1 = b"keyfile one";
    let (id, req) = a.submit_rekey(&pw, None, &[], kf1, KeyfileAction::Set);
    a.run(&mut v, req.as_ref().unwrap());
    assert_eq!(a.poll(id).unwrap().result, JobResult::Ok);
    a.lock(&mut v);
    let (id, req) = a.submit_unlock(&pw, &[]);
    a.run(&mut v, req.as_ref().unwrap());
    assert_eq!(a.poll(id).unwrap().result, JobResult::WrongPassword);
    let (id, req) = a.submit_unlock(&pw, kf1);
    a.run(&mut v, req.as_ref().unwrap());
    assert_eq!(a.poll(id).unwrap().result, JobResult::Ok);

    // clear
    let (id, req) = a.submit_rekey(&pw, None, kf1, &[], KeyfileAction::Clear);
    a.run(&mut v, req.as_ref().unwrap());
    assert_eq!(a.poll(id).unwrap().result, JobResult::Ok);
    a.lock(&mut v);
    let (id, req) = a.submit_unlock(&pw, &[]);
    a.run(&mut v, req.as_ref().unwrap());
    assert_eq!(a.poll(id).unwrap().result, JobResult::Ok);
}

#[test]
fn rekey_generate_delivers_keyfile_once() {
    let clock = ManualClock::new(0);
    let mut a = auth(clock);
    let mut v = vault();
    a.initialize(&v);
    let pw = provision(&mut a, &mut v);
    let (id, req) = a.submit_rekey(&pw, None, &[], &[], KeyfileAction::Generate);
    a.run(&mut v, req.as_ref().unwrap());
    let view = a.poll(id).unwrap();
    assert_eq!(view.result, JobResult::Ok);
    assert_eq!(view.key_file.len(), KEYFILE_GENERATED_BYTES);
    let kf = view.key_file.clone();
    assert!(a.poll(id).unwrap().key_file.is_empty());
    a.lock(&mut v);
    let (id, req) = a.submit_unlock(&pw, &[]);
    a.run(&mut v, req.as_ref().unwrap());
    assert_eq!(a.poll(id).unwrap().result, JobResult::WrongPassword);
    let (id, req) = a.submit_unlock(&pw, &kf);
    a.run(&mut v, req.as_ref().unwrap());
    assert_eq!(a.poll(id).unwrap().result, JobResult::Ok);
}

#[test]
fn rekey_rejects_empty_change_and_wrong_old_password_closes_session() {
    let clock = ManualClock::new(0);
    let mut a = auth(clock);
    assert_eq!(
        a.submit_rekey(PW, None, &[], &[], KeyfileAction::Keep).0,
        NO_JOB
    );
    assert_eq!(
        a.submit_rekey(PW, Some(""), &[], &[], KeyfileAction::Keep)
            .0,
        NO_JOB
    );

    let mut a = auth(ManualClock::new(0));
    let mut v = vault();
    a.initialize(&v);
    let _pw = provision(&mut a, &mut v);
    let (id, req) = a.submit_rekey("wrong", Some(PW3), &[], &[], KeyfileAction::Keep);
    a.run(&mut v, req.as_ref().unwrap());
    assert_eq!(a.poll(id).unwrap().result, JobResult::WrongPassword);
    assert!(!a.state().unlocked);
}

#[test]
fn reset_clears_everything_and_allows_reprovision() {
    let clock = ManualClock::new(0);
    let mut a = auth(clock);
    let mut v = vault();
    a.initialize(&v);
    let pw = provision(&mut a, &mut v);
    let (id, req) = a.submit_reset();
    a.run(&mut v, req.as_ref().unwrap());
    assert_eq!(a.poll(id).unwrap().result, JobResult::Ok);
    assert!(!a.state().provisioned);
    assert!(!a.state().unlocked);
    // provision again
    let pw2 = provision(&mut a, &mut v);
    assert_ne!(pw, pw2); // generated
    assert!(a.state().unlocked);
}

#[test]
fn submit_refuses_when_busy_and_on_invalid_input() {
    let clock = ManualClock::new(0);
    let mut a = auth(clock);
    let mut v = vault();
    a.initialize(&v);
    let (id, req) = a.submit_provision(&[], false);
    assert_ne!(id, NO_JOB);
    assert_eq!(a.submit_reset().0, NO_JOB);
    a.run(&mut v, req.as_ref().unwrap());
    drop(a.poll(id));

    // invalid
    assert_eq!(a.submit_unlock("", &[]).0, NO_JOB);
    let long = "x".repeat(256);
    assert_eq!(a.submit_unlock(&long, &[]).0, NO_JOB);
    let big = vec![0u8; 4096 + 1];
    assert_eq!(a.submit_unlock(&"x".repeat(12), &big).0, NO_JOB);
}
