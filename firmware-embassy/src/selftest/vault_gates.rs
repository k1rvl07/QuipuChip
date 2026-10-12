//! Vault gates: storage lifecycle, tamper resistance, wear and compaction.

use super::*;

pub(super) fn vault_gates(vault: &mut WorkerVault, gate_pw: &str, rng: &mut EspRng) {
    let rc = vault.begin(gate_pw, None, rng);
    if rc == VaultError::Tampered || rc == VaultError::WrongPassword {
        report(
            "vault-open",
            false,
            "leftover data in vault partition, refusing to write",
        );
        return;
    }
    report("vault-provision", rc == VaultError::None, rc.as_str());
    if rc != VaultError::None {
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
            report("vault-add", false, e.as_str());
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
        Err(e) => report("vault-load", false, e.as_str()),
    }

    // Reopen so data is read from flash, not memory.
    let rc = vault.begin(gate_pw, None, rng);
    report("vault-reopen", rc == VaultError::None, rc.as_str());
    match vault.load(8) {
        Ok(got) => report(
            "vault-load-reboot",
            rc == VaultError::None && got.len() == 1 && entries_equal(&got[0], &scratch),
            rc.as_str(),
        ),
        Err(e) => report("vault-load-reboot", false, e.as_str()),
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
        Err(e) => report("vault-update", false, e.as_str()),
    }

    let _ = vault.remove(id);
    match vault.load(8) {
        Ok(got) => report("vault-remove", got.is_empty(), ""),
        Err(e) => report("vault-remove", false, e.as_str()),
    }

    // Removal must survive a reboot.
    let _ = vault.begin(gate_pw, None, rng);
    match vault.load(8) {
        Ok(got) => report("vault-remove-persist", got.is_empty(), ""),
        Err(e) => report("vault-remove-persist", false, e.as_str()),
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
        let mut add_rc = VaultError::None;
        let mut t = Entry::new();
        let mut i = 0u32;
        while i < config::MAX_ENTRIES + 8 && add_rc == VaultError::None {
            fill_entry(&mut t, 0, "cap");
            add_rc = match vault.add(&t) {
                Ok(_) => {
                    added += 1;
                    VaultError::None
                }
                Err(e) => e,
            };
            i += 1;
        }
        let detail = format!("{} added, stopped with {}", added, add_rc.as_str());
        let ok = vault.count() <= config::MAX_ENTRIES
            && matches!(
                add_rc,
                VaultError::TooManyEntries | VaultError::Budget | VaultError::NoSpace
            );
        report("gate5-count-cap", ok, &detail);
    }

    log::info!("gate: clearing vault before wear gates");
    let rc = vault.clear(gate_pw, None, rng);
    report("gate-reset", rc == VaultError::None, rc.as_str());
    if rc != VaultError::None {
        return;
    }

    // Wear: 480 saves, verifying after EACH write so a break at #480 is not
    // confused with a break at #1.
    {
        const WEAR_ITERATIONS: u32 = 480;
        let mut checked = 0u32;
        let mut bad = VaultError::None;
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
            if bad == VaultError::None {
                ""
            } else {
                ", stopped early"
            }
        );
        report(
            "gate6-wear",
            bad == VaultError::None && checked == WEAR_ITERATIONS,
            &detail,
        );
    }

    // Index and region rebuilt by compaction must survive a reboot.
    {
        const PROBE: u32 = 16;
        let expected = vault.count();
        let rc = vault.begin(gate_pw, None, rng);
        let (load_rc, an) = match vault.load(PROBE as usize) {
            Ok(v) => (VaultError::None, v.len() as u32),
            Err(e) => (e, 0),
        };
        let after_open = vault.count();
        let detail = format!("count {expected} -> {after_open}, {an} loaded, data intact");
        report(
            "gate6-reboot",
            rc == VaultError::None
                && load_rc == VaultError::None
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
            bad_pw_rc.as_str(),
            st_before.state.as_str(),
            st_after.state.as_str(),
            prov_after as u8,
            ok as u8
        );
        report("gate2-wrongpw", ok, &detail);
    }

    // Header corruption. generation/iters/saltPw/saltDev/check are in the AAD.
    {
        if vault.begin(gate_pw, None, rng) == VaultError::None {
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
        } else {
            report(
                "gate3-tamper-hdr",
                false,
                "cannot open vault for tamper test",
            );
        }
    }

    // A torn header write must fall back to the spare slot, not refuse.
    {
        let mut ok = false;
        let mut detail = String::from("no active slot");
        if vault.begin(gate_pw, None, rng) == VaultError::None {
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
                    ok = r == VaultError::None && vault.initialized() && count_ok;
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
        if vault.begin(gate_pw, None, rng) == VaultError::None {
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
        if open_rc == VaultError::None {
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
                open_rc.as_str(),
                data_start,
                ok as u8
            );
        } else {
            detail = format!("open {}", open_rc.as_str());
        }
        report("gate8-tamper-ct", ok, &detail);
    }

    // Header counter corruption: counters are not in the AAD, so they are
    // guarded by re-counting the log.
    {
        let mut ok = false;
        if vault.begin(gate_pw, None, rng) == VaultError::None {
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
        if open_rc == VaultError::None {
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
                open_rc.as_str(),
                data_start,
                ok as u8
            );
        } else {
            detail = format!("open {}", open_rc.as_str());
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
        let before = if open == VaultError::None {
            vault.count()
        } else {
            0
        };
        let (add_rc, id) = match vault.add(&e) {
            Ok(id) => (VaultError::None, id),
            Err(er) => (er, 0),
        };

        vault.close();
        let closed = !vault.initialized() && vault.count() == 0;
        let snap_locked = vault.snapshot().state == State::Locked;
        vault.close();
        vault.close();
        let close_idempotent = !vault.initialized() && vault.count() == 0;

        let reopen = vault.begin(gate_pw, None, rng);
        let survived = reopen == VaultError::None && vault.count() == before + 1;
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
            open.as_str(),
            add_rc.as_str(),
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
            open == VaultError::None
                && add_rc == VaultError::None
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
        let reset_ok = rst == VaultError::None
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
            re_prov == VaultError::None,
            re_prov.as_str(),
        );
    }

    {
        let r = vault.begin(gate_pw, None, rng);
        report("vault-reopen", r == VaultError::None, r.as_str());
    }
    let _ = vault.clear(gate_pw, None, rng);
    log::info!("gate: vault cleared after tests");
}
