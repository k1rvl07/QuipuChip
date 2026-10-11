//! Rekey gates: changing the master password and rewrapping records.

use super::*;

pub(super) fn rekey_gates(vault: &mut WorkerVault, auth: &mut WorkerAuth, gate_pw: &str) {
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
                Ok(id) => (VaultError::None, id),
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
            add_rc.as_str(),
            if polled { res.as_str() } else { "not polled" },
            session_alive as u8
        );
        report(
            "gateR2-rekey-ok",
            unlocked
                && add_rc == VaultError::None
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
        let data_ok = if new_rc == VaultError::None {
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
            old_rc.as_str(),
            new_rc.as_str(),
            data_ok as u8
        );
        report(
            "gateR3-rekey-old-pw-rejected",
            old_rc == VaultError::WrongPassword,
            &detail34,
        );
        report(
            "gateR4-rekey-data-survives",
            new_rc == VaultError::None && data_ok,
            &detail34,
        );

        // R5: restore the gate password directly through vault::rekey.
        let back_rc = if new_rc == VaultError::None {
            vault.rekey(gate_pw, None, &mut rng)
        } else {
            VaultError::BootStrap
        };
        let flag = vault.key_file_required();
        let prov = vault.provisioned();
        vault.close();
        let detail5 = format!(
            "back {}, flag {}, prov {}",
            back_rc.as_str(),
            flag as u8,
            prov as u8
        );
        report(
            "gateR5-rekey-restore",
            back_rc == VaultError::None && !flag && prov,
            &detail5,
        );
    }
}
