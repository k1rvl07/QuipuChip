//! Reset gate: destroying the vault from a live session.

use super::*;

pub(super) fn reset_gates(vault: &mut WorkerVault, auth: &mut WorkerAuth, gate_pw: &str) {
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
            Err(er) => er.as_str(),
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
