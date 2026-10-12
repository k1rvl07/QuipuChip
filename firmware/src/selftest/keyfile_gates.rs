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
}
