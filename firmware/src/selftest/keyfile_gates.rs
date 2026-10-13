//! Key-file gates: provisioning with a key file and unlock requirements.

use super::*;

pub(super) fn keyfile_gates(vault: &mut WorkerVault, auth: &mut WorkerAuth, gate_pw: &str) {
    log::info!("=== keyfile gates ===");

    let file_a: [u8; 32] = core::array::from_fn(|i| i as u8);
    let file_b: [u8; 32] = core::array::from_fn(|i| (0x1f - i) as u8);
    let mut rng = EspRng::new();

    let probe_id = {
        let rc = vault.clear(gate_pw, Some(&file_a), &mut rng);
        let flag = vault.key_file_required();
        let mut e = Entry::new();
        fill_entry(&mut e, 0, "keyfile");
        let (add_rc, id) = if rc == VaultError::None {
            match vault.add(&e) {
                Ok(id) => (VaultError::None, id),
                Err(er) => (er, 0),
            }
        } else {
            (rc, 0)
        };
        let detail = format!(
            "clear {}, flag {}, entry {}",
            rc.as_str(),
            flag as u8,
            add_rc.as_str()
        );
        report(
            "gateK1-keyfile-provision",
            rc == VaultError::None && flag && add_rc == VaultError::None && id != 0,
            &detail,
        );
        if rc != VaultError::None {
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
                .is_ok_and(|got| got.get(Field::Title) == b"gate-keyfile");
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
        let clear_rc = if open_rc == VaultError::None {
            vault.clear(gate_pw, None, &mut rng)
        } else {
            open_rc
        };
        let flag_gone = !vault.key_file_required();
        let prov = vault.provisioned();
        vault.close();
        let detail = format!(
            "open {}, clear {}, flag {}, prov {}",
            open_rc.as_str(),
            clear_rc.as_str(),
            flag_gone as u8,
            prov as u8
        );
        report(
            "gateK5-keyfile-restore",
            open_rc == VaultError::None && clear_rc == VaultError::None && flag_gone && prov,
            &detail,
        );
    }

    // K6: a rekey with KeyfileAction::Generate mints a 32-byte file on the
    // device, installs it at rekey time and delivers it through poll exactly
    // once. The delivered bytes must then open the vault; afterwards the vault
    // is restored to the provisioned, no-file state that rekeyGates() expects.
    {
        let sub = auth.submit_unlock(gate_pw, &[]);
        let unlocked = wait_job(auth, vault, sub).is_some_and(|v| v.result == JobResult::Ok);

        let (polled, res, mut kf) = if unlocked {
            let sub = auth.submit_rekey(gate_pw, None, &[], &[], KeyfileAction::Generate);
            match wait_job(auth, vault, sub) {
                Some(v) => (true, v.result, v.key_file.clone()),
                None => (false, JobResult::Error, Vec::new()),
            }
        } else {
            (false, JobResult::Error, Vec::new())
        };

        let len_ok = kf.len() == config::KEYFILE_GENERATED_BYTES;
        let requires = vault.key_file_required();

        // The delivered key file must be the one this vault actually uses.
        let mut reopens = false;
        if polled && res == JobResult::Ok && len_ok {
            auth.lock(vault);
            let sub = auth.submit_unlock(gate_pw, &kf);
            reopens = wait_job(auth, vault, sub).is_some_and(|v| v.result == JobResult::Ok);
        }
        auth.lock(vault);

        let detail = format!(
            "unlock {}, rekey {}, len {}, flag {}, reopen {}",
            unlocked as u8,
            if polled { res.as_str() } else { "not polled" },
            kf.len(),
            requires as u8,
            reopens as u8
        );
        report(
            "gateK6-keyfile-generate",
            unlocked && polled && res == JobResult::Ok && len_ok && requires && reopens,
            &detail,
        );

        // Restore: open with the generated file and clear it, so the vault is
        // provisioned without a key file again.
        if reopens {
            vault.close();
            let open_rc = vault.begin(gate_pw, Some(&kf), &mut rng);
            if open_rc == VaultError::None {
                vault.clear(gate_pw, None, &mut rng);
            }
            vault.close();
        }
        crypto::wipe(&mut kf);
    }

    // K7: a keyfile-only rekey (no new password) installs a supplied file and
    // keeps the existing password; the password alone then stops working.
    // K8: clearing the key file restores password-only unlock.
    {
        let unlocked = {
            let sub = auth.submit_unlock(gate_pw, &[]);
            wait_job(auth, vault, sub).is_some_and(|v| v.result == JobResult::Ok)
        };

        let (set_polled, set_res, set_flag) = if unlocked {
            let sub = auth.submit_rekey(gate_pw, None, &[], &file_a, KeyfileAction::Set);
            match wait_job(auth, vault, sub) {
                Some(v) => (true, v.result, vault.key_file_required()),
                None => (false, JobResult::Error, false),
            }
        } else {
            (false, JobResult::Error, false)
        };

        let mut no_file_ok = false;
        let mut with_file_ok = false;
        if set_polled && set_res == JobResult::Ok {
            auth.lock(vault);
            let sub = auth.submit_unlock(gate_pw, &[]);
            no_file_ok = wait_job(auth, vault, sub).is_some_and(|v| v.result == JobResult::Ok);
            auth.clear_lockout();

            let sub = auth.submit_unlock(gate_pw, &file_a);
            with_file_ok = wait_job(auth, vault, sub).is_some_and(|v| v.result == JobResult::Ok);
        }

        let set_detail = format!(
            "unlock {}, rekey {}, flag {}, nofile {}, withfile {}",
            unlocked as u8,
            if set_polled { set_res.as_str() } else { "not polled" },
            set_flag as u8,
            no_file_ok as u8,
            with_file_ok as u8
        );
        report(
            "gateK7-keyfile-only-set",
            unlocked
                && set_polled
                && set_res == JobResult::Ok
                && set_flag
                && !no_file_ok
                && with_file_ok,
            &set_detail,
        );

        let clear_res = if with_file_ok && auth.state().unlocked {
            let sub = auth.submit_rekey(gate_pw, None, &file_a, &[], KeyfileAction::Clear);
            wait_job(auth, vault, sub).map(|v| v.result)
        } else {
            None
        };
        let flag_gone = !vault.key_file_required();

        let mut reopen_ok = false;
        if clear_res == Some(JobResult::Ok) {
            auth.lock(vault);
            let sub = auth.submit_unlock(gate_pw, &[]);
            reopen_ok = wait_job(auth, vault, sub).is_some_and(|v| v.result == JobResult::Ok);
        }

        let clear_detail = format!(
            "clear {}, flag {}, reopen {}",
            match clear_res {
                Some(r) => r.as_str(),
                None => "not polled",
            },
            flag_gone as u8,
            reopen_ok as u8
        );
        report(
            "gateK8-keyfile-clear",
            clear_res == Some(JobResult::Ok) && flag_gone && reopen_ok,
            &clear_detail,
        );
    }
}
