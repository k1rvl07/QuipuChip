//! Auth gates: master-password generation and the session lifecycle.

use super::*;

pub(super) fn auth_gates(vault: &mut WorkerVault, auth: &mut WorkerAuth, gate_pw: &mut String) {
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
