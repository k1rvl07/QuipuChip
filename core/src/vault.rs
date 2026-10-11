//! PMV1 on-flash vault, ported from `src/vault.cpp`.
//!
//! The container lives in the `vault` partition and is accessed as a flat
//! ciphertext blob, without a filesystem. Layout, record format, AAD rules and
//! the two-slot header are byte-compatible with the C++ reference so a vault
//! written by either implementation opens in the other.
//!
//! Hardware access is abstracted behind [`Storage`]; `pm-firmware` implements it
//! on top of `esp_partition_*`, while tests drive an in-memory flash that
//! reproduces the only property that matters for correctness: writes may only
//! clear bits (`1 -> 0`), and erase sets a sector back to `0xFF`.
//!
//! Device factor: the KEK is `PBKDF2(password_material, salt_pw) ^ HMAC-SHA256(mac6,
//! "pm-vault-device" || salt_dev)`. The MAC is passed to [`Vault::new`] already
//! in the reversed byte order the C++ reference produces.

use alloc::{vec, vec::Vec};

use crate::config::*;
use crate::crypto;
use crate::device;
use crate::entry::{Entry, Snapshot, State, Stats, VaultError};
use crate::rand::RandomSource;

// ── Header field offsets (from src/vault.cpp, anonymous namespace) ────────────

const HDR_MAGIC: usize = 0x00;
const HDR_VERSION: usize = 0x04;
const HDR_GENERATION: usize = 0x08;
const HDR_ENTRY_COUNT: usize = 0x0C;
const HDR_LIVE_BYTES: usize = 0x10;
const HDR_USED_BYTES: usize = 0x14;
const HDR_FLAGS: usize = 0x18;
const HDR_ITERS: usize = 0x1C;
const HDR_SALT_PW: usize = 0x20;
const HDR_SALT_DEV: usize = 0x30;
const HDR_DATA_START: usize = 0x50;
const HDR_SEQ: usize = 0x54;

/// Completion marker, written after the tag and therefore last on flash.
const COMMIT_BYTES: usize = 4;
const COMMIT_MAGIC: u32 = 0x5449_4D43; // 'CMIT' in write order
const HDR_CHECK: usize = VAULT_HEADER_BYTES - COMMIT_BYTES - GCM_TAG_LEN;
const HDR_COMMIT: usize = VAULT_HEADER_BYTES - COMMIT_BYTES;

const HDR_SLOT0: usize = 0;
const HDR_SLOT1: usize = VAULT_HEADER_SLOT_BYTES;

const FLAG_PROVISIONED: u32 = 1 << 0;
const FLAG_COMPACTED: u32 = 1 << 1;
const FLAG_KEYFILE: u32 = 1 << 2;

const REC_FIXED: usize = 4 + 2 + GCM_IV_LEN + GCM_TAG_LEN; // 34
const SENTINEL: &[u8; 7] = b"PMV1-OK"; // 7 bytes; the C++ `kSentinel[]` also has a NUL
const TOMBSTONE_BIT: u32 = 0x8000_0000;

/// Window scanned past `usedEnd` for a torn record; one record cannot exceed a
/// sector, two sectors are a comfortable margin.
const TORN_SCAN_BYTES: usize = 2 * FLASH_SECTOR_BYTES;

const _: () = assert!(HDR_CHECK + GCM_TAG_LEN + COMMIT_BYTES == VAULT_HEADER_BYTES);
const _: () = assert!(HDR_SEQ + 4 <= HDR_CHECK);

/// Block device abstraction. `write` must reproduce flash semantics: the stored
/// byte is the bitwise AND of the old and new values (bits can only go
/// `1 -> 0`). `erase` sets the whole range to `0xFF`.
pub trait Storage {
    fn size(&self) -> usize;
    fn read(&self, offset: usize, buf: &mut [u8]) -> Result<(), VaultError>;
    fn write(&mut self, offset: usize, buf: &[u8]) -> Result<(), VaultError>;
    fn erase(&mut self, offset: usize, len: usize) -> Result<(), VaultError>;
}

/// One live record's location. `live` entries are indices into `Vault::index`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Index {
    id: u32,
    offset: usize,
    len: u16,
}

/// KDF material with a wiping destructor: password bytes, and the key file's
/// SHA-256 appended when a key file is in use.
struct Secret(Vec<u8>);

impl Secret {
    fn new(v: Vec<u8>) -> Self {
        Self(v)
    }
    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        crypto::wipe(&mut self.0);
    }
}

/// What inspecting a header slot found. `Absent`/`Torn` permit falling back to
/// the other slot; `Invalid`/`TagMismatch` do not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotState {
    Absent,
    Torn,
    Valid,
    Invalid,
    TagMismatch,
}

pub struct Vault<S: Storage> {
    storage: S,
    mac6: [u8; 6],
    ready: bool,
    key: [u8; AES_KEY_LEN],
    salt_pw: [u8; PBKDF2_SALT_LEN],
    salt_dev: [u8; PBKDF2_SALT_LEN],
    hdr: [u8; VAULT_HEADER_BYTES],
    generation: u32,
    iters: u32,
    data_start: usize,
    used_end: usize,
    region: usize,
    hdr_seq: u32,
    index: Vec<Index>,
    live_payload: usize,
    next_id: u32,
    compacted_once: bool,
    key_file_flag: bool,
    provisioned: bool,
    snap: Snapshot,
}

impl<S: Storage> Vault<S> {
    /// Creates the vault state. `mac6` is the device MAC in the reversed order
    /// the C++ reference uses (see `device::factor`).
    pub fn new(storage: S, mac6: [u8; 6]) -> Self {
        Self {
            storage,
            mac6,
            ready: false,
            key: [0; AES_KEY_LEN],
            salt_pw: [0; PBKDF2_SALT_LEN],
            salt_dev: [0; PBKDF2_SALT_LEN],
            hdr: [0; VAULT_HEADER_BYTES],
            generation: 1,
            iters: PBKDF2_ITERS,
            data_start: region_start(0),
            used_end: region_start(0),
            region: 0,
            hdr_seq: 0,
            index: Vec::new(),
            live_payload: 0,
            next_id: 1,
            compacted_once: false,
            key_file_flag: false,
            provisioned: false,
            snap: Snapshot::default(),
        }
    }

    pub fn storage_ref(&self) -> &S {
        &self.storage
    }

    pub fn storage_mut(&mut self) -> &mut S {
        &mut self.storage
    }

    // ── Cheap state accessors ────────────────────────────────────────────────

    pub fn initialized(&self) -> bool {
        self.ready
    }

    pub fn count(&self) -> u32 {
        self.index.len() as u32
    }

    pub fn snapshot(&self) -> Snapshot {
        self.snap
    }

    pub fn stats(&self) -> Stats {
        Stats {
            entry_count: self.index.len() as u32,
            live_bytes: self.live_payload,
            used_bytes: self.used_end,
            generation: self.generation,
            compacted_once: self.compacted_once,
        }
    }

    /// Cheap one-time init: read the provisioned flag off flash and publish it.
    /// Works before any `begin` and needs no password.
    pub fn initialize(&mut self) {
        self.provisioned = self.probe_provisioned();
        self.publish_snapshot();
    }

    /// True when the partition holds a provisioned vault (flag in either slot).
    pub fn provisioned(&self) -> bool {
        self.probe_provisioned()
    }

    /// True when the newest completed header carries the key-file flag.
    pub fn key_file_required(&self) -> bool {
        self.probe_key_file_flag()
    }

    // ── Existing-header probes (no password) ─────────────────────────────────

    fn storage_ok(&self) -> bool {
        self.storage.size() >= VAULT_PARTITION_BYTES
    }

    fn probe_provisioned(&self) -> bool {
        if !self.storage_ok() {
            return false;
        }
        let mut raw = [0u8; VAULT_HEADER_BYTES];
        for slot in 0..2 {
            let off = slot * FLASH_SECTOR_BYTES;
            if self.storage.read(off, &mut raw).is_err() {
                continue;
            }
            if raw[HDR_MAGIC..HDR_MAGIC + 4] == VAULT_MAGIC
                && get32(&raw[HDR_FLAGS..]) & FLAG_PROVISIONED != 0
            {
                return true;
            }
        }
        false
    }

    fn probe_key_file_flag(&self) -> bool {
        if !self.storage_ok() {
            return false;
        }
        let mut raw = [0u8; VAULT_HEADER_BYTES];
        let mut found = false;
        let mut best_seq = 0u32;
        let mut best_flag = false;
        for slot in 0..2 {
            let off = slot * FLASH_SECTOR_BYTES;
            if self.storage.read(off, &mut raw).is_err() {
                continue;
            }
            if raw[HDR_MAGIC..HDR_MAGIC + 4] != VAULT_MAGIC
                || get32(&raw[HDR_COMMIT..]) != COMMIT_MAGIC
            {
                continue;
            }
            let seq = get32(&raw[HDR_SEQ..]);
            if !found || seq > best_seq {
                found = true;
                best_seq = seq;
                best_flag = get32(&raw[HDR_FLAGS..]) & FLAG_KEYFILE != 0;
            }
        }
        best_flag
    }

    fn publish_snapshot(&mut self) {
        let state = if self.ready {
            State::Unlocked
        } else if self.provisioned {
            State::Locked
        } else {
            State::Unprovisioned
        };
        self.snap = Snapshot {
            state,
            entry_count: self.index.len() as u32,
            generation: self.generation,
            live_bytes: self.live_payload,
        };
    }

    // ── Header handling ──────────────────────────────────────────────────────

    fn build_hdr(&mut self) {
        self.hdr[HDR_MAGIC..HDR_MAGIC + 4].copy_from_slice(&VAULT_MAGIC);
        put32(&mut self.hdr[HDR_VERSION..], 1);
        put32(&mut self.hdr[HDR_GENERATION..], self.generation);
        put32(&mut self.hdr[HDR_ENTRY_COUNT..], self.index.len() as u32);
        put32(&mut self.hdr[HDR_LIVE_BYTES..], self.live_payload as u32);
        put32(&mut self.hdr[HDR_USED_BYTES..], self.used_end as u32);
        let mut flags = FLAG_PROVISIONED;
        if self.compacted_once {
            flags |= FLAG_COMPACTED;
        }
        if self.key_file_flag {
            flags |= FLAG_KEYFILE;
        }
        put32(&mut self.hdr[HDR_FLAGS..], flags);
        put32(&mut self.hdr[HDR_ITERS..], self.iters);
        self.hdr[HDR_SALT_PW..HDR_SALT_PW + PBKDF2_SALT_LEN].copy_from_slice(&self.salt_pw);
        self.hdr[HDR_SALT_DEV..HDR_SALT_DEV + PBKDF2_SALT_LEN].copy_from_slice(&self.salt_dev);
        put32(&mut self.hdr[HDR_DATA_START..], self.data_start as u32);
        put32(&mut self.hdr[HDR_SEQ..], self.hdr_seq);
    }

    /// Writes the header to the slot selected by `hdr_seq`, erasing that slot
    /// first. The opposite slot keeps the previous generation as a backup.
    fn flush_header(&mut self) -> bool {
        self.build_hdr();
        let aad = build_aad(&self.hdr);
        let nonce = nonce_for(self.generation, 0);
        let mut ct = [0u8; SENTINEL.len()];
        let tag = match crypto::aes_gcm_encrypt(&self.key, &nonce, &aad, &mut ct) {
            Ok(t) => t,
            Err(_) => return false,
        };
        crypto::wipe(&mut ct);
        self.hdr[HDR_CHECK..HDR_CHECK + GCM_TAG_LEN].copy_from_slice(&tag);
        let slot = header_slot_offset(self.hdr_seq);
        if self.storage.erase(slot, VAULT_HEADER_SLOT_BYTES).is_err() {
            return false;
        }
        // The marker is placed after the tag and so is written last.
        put32(&mut self.hdr[HDR_COMMIT..], COMMIT_MAGIC);
        let hdr = self.hdr;
        if self.storage.write(slot, &hdr).is_err() {
            return false;
        }
        self.hdr_seq += 1;
        true
    }

    fn probe_header_slot(
        &self,
        slot: usize,
        out: &mut [u8; VAULT_HEADER_BYTES],
        mat: &[u8],
    ) -> SlotState {
        if self.storage.read(slot, out).is_err() {
            return SlotState::Absent;
        }
        if out[HDR_MAGIC..HDR_MAGIC + 4] != VAULT_MAGIC {
            return SlotState::Absent;
        }
        if get32(&out[HDR_VERSION..]) != 1 {
            return SlotState::Invalid;
        }
        if get32(&out[HDR_COMMIT..]) != COMMIT_MAGIC {
            return SlotState::Torn;
        }
        let iters = get32(&out[HDR_ITERS..]);
        let gen = get32(&out[HDR_GENERATION..]);
        if iters == 0 || iters > 10_000_000 || gen == 0 {
            return SlotState::Invalid;
        }

        let mut trial = [0u8; AES_KEY_LEN];
        match device::factor(
            &self.mac6,
            &out[HDR_SALT_DEV..HDR_SALT_DEV + PBKDF2_SALT_LEN],
        ) {
            Ok(term) => {
                match crypto::pbkdf2_hmac_sha256(
                    mat,
                    &out[HDR_SALT_PW..HDR_SALT_PW + PBKDF2_SALT_LEN],
                    iters,
                ) {
                    Ok(from_pw) => {
                        for i in 0..AES_KEY_LEN {
                            trial[i] = term[i] ^ from_pw[i];
                        }
                    }
                    Err(_) => {
                        trial[0] = 0;
                        trial[1] = 0;
                    }
                }
            }
            Err(_) => {
                trial[0] = 0;
                trial[1] = 0;
            }
        }
        let aad = build_aad(out);
        let nonce = nonce_for(gen, 0);
        let mut ct = [0u8; SENTINEL.len()];
        let tag = match crypto::aes_gcm_encrypt(&trial, &nonce, &aad, &mut ct) {
            Ok(t) => t,
            Err(_) => {
                crypto::wipe(&mut trial);
                return SlotState::Invalid;
            }
        };
        crypto::wipe(&mut ct);
        crypto::wipe(&mut trial);
        if crypto::ct_equal(&tag, &out[HDR_CHECK..HDR_CHECK + GCM_TAG_LEN]) {
            SlotState::Valid
        } else {
            SlotState::TagMismatch
        }
    }

    // ── Record I/O ───────────────────────────────────────────────────────────

    fn write_record_at(&mut self, off: usize, raw_id: u32, payload: &[u8]) -> VaultError {
        let len = payload.len();
        let total = REC_FIXED + if len > 0 { len } else { 1 };
        if off < self.data_start || off + total > region_start(self.region + 1) {
            return VaultError::NoSpace;
        }
        let mut rec = vec![0u8; total];
        put32(&mut rec[0..], raw_id);
        put16(&mut rec[4..], len as u16);
        let nonce = nonce_for(self.generation, off);
        rec[6..6 + GCM_IV_LEN].copy_from_slice(&nonce);
        let aad = build_aad(&self.hdr);

        let mut body;
        let tag = if len > 0 {
            body = payload.to_vec();
            crypto::aes_gcm_encrypt(&self.key, &nonce, &aad, &mut body)
        } else {
            body = SENTINEL[..1].to_vec();
            crypto::aes_gcm_encrypt(&self.key, &nonce, &aad, &mut body)
        };
        let tag = match tag {
            Ok(t) => t,
            Err(_) => {
                crypto::wipe(&mut rec);
                return VaultError::Crypto;
            }
        };
        rec[REC_FIXED..REC_FIXED + body.len()].copy_from_slice(&body);
        rec[6 + GCM_IV_LEN..REC_FIXED].copy_from_slice(&tag);
        crypto::wipe(&mut body);

        let res = self.storage.write(off, &rec);
        crypto::wipe(&mut rec);
        match res {
            Ok(()) => VaultError::Ok,
            Err(_) => VaultError::Io,
        }
    }

    fn read_record(&self, slot: usize) -> Result<Entry, VaultError> {
        let it = self.index[slot];
        let len = it.len as usize;
        if len == 0 || len > MAX_ENTRY_LEN {
            return Err(VaultError::Tampered);
        }
        let mut head = [0u8; REC_FIXED];
        self.storage
            .read(it.offset, &mut head)
            .map_err(|_| VaultError::Io)?;
        if get32(&head[0..]) != it.id || get16(&head[4..]) as usize != len {
            return Err(VaultError::Tampered);
        }
        let mut buf = vec![0u8; len];
        self.storage
            .read(it.offset + REC_FIXED, &mut buf)
            .map_err(|_| VaultError::Io)?;
        let aad = build_aad(&self.hdr);
        let tag = &head[6 + GCM_IV_LEN..REC_FIXED];
        if crypto::aes_gcm_decrypt(&self.key, &head[6..6 + GCM_IV_LEN], &aad, &mut buf, tag)
            .is_err()
        {
            crypto::wipe(&mut buf);
            return Err(VaultError::Tampered);
        }
        let e = Entry::deserialize(it.id, &buf);
        crypto::wipe(&mut buf);
        Ok(e)
    }

    // ── Index helpers ────────────────────────────────────────────────────────

    fn find_index(&self, id: u32) -> Option<usize> {
        self.index.iter().position(|e| e.id == id)
    }

    fn remove_at(&mut self, slot: usize) {
        if self.live_payload >= self.index[slot].len as usize {
            self.live_payload -= self.index[slot].len as usize;
        }
        let last = self.index.len() - 1;
        if slot < last {
            self.index[slot] = self.index[last];
        }
        self.index.pop();
    }

    fn apply_to_index(&mut self, raw_id: u32, offset: usize, len: u16) -> bool {
        let id = raw_id & !TOMBSTONE_BIT;
        let at = self.find_index(id);
        if raw_id & TOMBSTONE_BIT != 0 {
            if let Some(a) = at {
                self.remove_at(a);
            }
            return true;
        }
        if let Some(a) = at {
            self.live_payload -= self.index[a].len as usize;
            self.live_payload += len as usize;
            self.index[a].offset = offset;
            self.index[a].len = len;
            return true;
        }
        if self.index.len() as u32 >= MAX_ENTRIES {
            return false;
        }
        self.index.push(Index { id, offset, len });
        self.live_payload += len as usize;
        true
    }

    // ── Journal scan / compaction ────────────────────────────────────────────

    fn scan_log(&mut self) -> VaultError {
        self.index.clear();
        self.live_payload = 0;
        self.next_id = 1;
        let mut off = self.data_start;
        while off + REC_FIXED <= self.used_end {
            let mut head = [0u8; REC_FIXED];
            if self.storage.read(off, &mut head).is_err() {
                return VaultError::Io;
            }
            let raw_id = get32(&head[0..]);
            let len = get16(&head[4..]) as usize;
            let is_tomb = raw_id & TOMBSTONE_BIT != 0;
            if is_tomb && len != 0 {
                return VaultError::Tampered;
            }
            if len > MAX_ENTRY_LEN {
                return VaultError::Tampered;
            }
            let body = if len != 0 { len } else { 1 };
            let total = REC_FIXED + body;
            if off + total > self.used_end {
                break;
            }
            if !is_tomb && raw_id == 0 {
                return VaultError::Tampered;
            }
            let mut buf = vec![0u8; body];
            if self.storage.read(off + REC_FIXED, &mut buf).is_err() {
                return VaultError::Io;
            }
            let aad = build_aad(&self.hdr);
            let tag = &head[6 + GCM_IV_LEN..REC_FIXED];
            if crypto::aes_gcm_decrypt(&self.key, &head[6..6 + GCM_IV_LEN], &aad, &mut buf, tag)
                .is_err()
            {
                crypto::wipe(&mut buf);
                return VaultError::Tampered;
            }
            crypto::wipe(&mut buf);
            if !self.apply_to_index(raw_id, off, len as u16) {
                return VaultError::TooManyEntries;
            }
            if !is_tomb && (raw_id & !TOMBSTONE_BIT) >= self.next_id {
                self.next_id = (raw_id & !TOMBSTONE_BIT) + 1;
            }
            off += total;
        }
        VaultError::Ok
    }

    fn tail_is_dirty(&self) -> bool {
        let region_end = region_start(self.region + 1);
        let scan_end = self.used_end + TORN_SCAN_BYTES;
        let stop = if scan_end > region_end {
            region_end
        } else {
            scan_end
        };
        let mut buf = [0u8; 64];
        let mut off = self.used_end;
        while off < stop {
            let n = core::cmp::min(stop - off, buf.len());
            if self.storage.read(off, &mut buf[..n]).is_err() {
                return true;
            }
            if buf[..n].iter().any(|&b| b != 0xFF) {
                return true;
            }
            off += n;
        }
        false
    }

    fn compact(&mut self) -> VaultError {
        let old_data_start = self.data_start;
        let old_used_end = self.used_end;
        let old_region = self.region;
        let target_region = 1 - old_region;
        let target_start = region_start(target_region);
        let old_hdr = self.hdr;

        let saved = self.index.clone();
        let saved_payload = self.live_payload;
        let old_next_id = self.next_id;

        let mut need = 0usize;
        for it in &saved {
            need += REC_FIXED + it.len as usize;
        }
        if target_start + need > region_start(2) {
            return VaultError::NoSpace;
        }
        if self
            .storage
            .erase(target_start, VAULT_REGION_BYTES)
            .is_err()
        {
            return VaultError::Io;
        }

        let old_aad = build_aad(&self.hdr);

        // Switch to the new region before writing: `write_record_at` builds its
        // AAD from the header, which must carry the new generation/dataStart.
        self.generation += 1;
        self.region = target_region;
        self.data_start = target_start;
        self.used_end = target_start;
        self.compacted_once = true;
        self.build_hdr();

        let mut cursor = target_start;
        self.index.clear();
        self.live_payload = 0;
        let mut ok = true;
        for it in &saved {
            let mut head = [0u8; REC_FIXED];
            if self.storage.read(it.offset, &mut head).is_err() {
                ok = false;
                break;
            }
            let len = it.len as usize;
            let mut buf = vec![0u8; len];
            if self.storage.read(it.offset + REC_FIXED, &mut buf).is_err() {
                ok = false;
                break;
            }
            let tag = &head[6 + GCM_IV_LEN..REC_FIXED];
            if crypto::aes_gcm_decrypt(&self.key, &head[6..6 + GCM_IV_LEN], &old_aad, &mut buf, tag)
                .is_err()
            {
                ok = false;
                break;
            }
            let wr = self.write_record_at(cursor, it.id, &buf);
            crypto::wipe(&mut buf);
            if wr != VaultError::Ok {
                ok = false;
                break;
            }
            self.index.push(Index {
                id: it.id,
                offset: cursor,
                len: it.len,
            });
            self.live_payload += len;
            cursor += REC_FIXED + len;
        }

        if !ok {
            self.rollback_region(
                old_hdr,
                old_region,
                old_data_start,
                old_used_end,
                saved,
                saved_payload,
                old_next_id,
            );
            return VaultError::Io;
        }

        self.used_end = cursor;
        self.build_hdr();
        if !self.flush_header() {
            self.rollback_region(
                old_hdr,
                old_region,
                old_data_start,
                old_used_end,
                saved,
                saved_payload,
                old_next_id,
            );
            return VaultError::Io;
        }
        VaultError::Ok
    }

    #[allow(clippy::too_many_arguments)]
    fn rollback_region(
        &mut self,
        old_hdr: [u8; VAULT_HEADER_BYTES],
        old_region: usize,
        old_data_start: usize,
        old_used_end: usize,
        saved: Vec<Index>,
        saved_payload: usize,
        old_next_id: u32,
    ) {
        self.generation -= 1;
        self.region = old_region;
        self.data_start = old_data_start;
        self.used_end = old_used_end;
        self.compacted_once = get32(&old_hdr[HDR_FLAGS..]) & FLAG_COMPACTED != 0;
        self.hdr = old_hdr;
        self.index = saved;
        self.live_payload = saved_payload;
        self.next_id = old_next_id;
    }

    // ── Session lifecycle ────────────────────────────────────────────────────

    pub fn close(&mut self) {
        crypto::wipe(&mut self.key);
        crypto::wipe(&mut self.hdr);
        crypto::wipe(&mut self.salt_pw);
        crypto::wipe(&mut self.salt_dev);
        self.index.clear();
        self.live_payload = 0;
        self.used_end = region_start(0);
        self.data_start = region_start(0);
        self.region = 0;
        self.hdr_seq = 0;
        self.next_id = 1;
        self.generation = 1;
        self.iters = PBKDF2_ITERS;
        self.compacted_once = false;
        self.key_file_flag = false;
        self.ready = false;
        self.publish_snapshot();
    }

    /// Opens or provisions the vault. Mirrors `vault::begin`.
    ///
    /// On a fresh/empty partition, random salts are drawn from `rng` and a new
    /// vault is created. On an existing vault, both header slots are inspected
    /// independently: a rollback to the backup slot is only allowed when the
    /// fresh slot was torn or absent.
    pub fn begin(
        &mut self,
        password: &str,
        key_file: Option<&[u8]>,
        rng: &mut dyn RandomSource,
    ) -> VaultError {
        self.ready = false;
        self.provisioned = false;
        self.publish_snapshot();
        self.index.clear();
        self.live_payload = 0;
        self.used_end = region_start(0);
        self.data_start = region_start(0);
        self.region = 0;
        self.compacted_once = false;
        self.generation = 1;
        self.hdr_seq = 0;
        self.hdr = [0; VAULT_HEADER_BYTES];
        crypto::wipe(&mut self.key);

        if !self.storage_ok() {
            return VaultError::NotFound;
        }

        // Read provisioned state before touching the password: a wrong password
        // must leave the snapshot Locked, never Unprovisioned.
        self.provisioned = self.probe_provisioned();
        self.publish_snapshot();

        let pw_len = password.len();
        if !(MIN_PASS_CHARS..MAX_PASS_CHARS).contains(&pw_len) {
            return VaultError::WrongPassword;
        }

        let mat = match build_material(password, key_file) {
            Some(m) => Secret::new(m),
            None => return VaultError::WrongPassword,
        };
        self.key_file_flag = key_file.map(|k| !k.is_empty()).unwrap_or(false);

        let mut raw = [0u8; VAULT_HEADER_BYTES];
        if self.storage.read(0, &mut raw).is_err() {
            return VaultError::Io;
        }
        let magic_ok = raw[HDR_MAGIC..HDR_MAGIC + 4] == VAULT_MAGIC;
        let provisioned = get32(&raw[HDR_FLAGS..]) & FLAG_PROVISIONED != 0;

        if !magic_ok || !provisioned {
            // Provisioning.
            rng.fill(&mut self.salt_pw);
            rng.fill(&mut self.salt_dev);
            let sp = self.salt_pw;
            let sd = self.salt_dev;
            match derive_key(mat.as_slice(), &sp, &sd, PBKDF2_ITERS, &self.mac6) {
                Ok(k) => self.key = k,
                Err(e) => return e,
            }
            self.generation = 1;
            self.iters = PBKDF2_ITERS;
            self.next_id = 1;
            self.data_start = region_start(0);
            self.used_end = self.data_start;
            let size = self.storage.size();
            if self.storage.erase(0, size).is_err() {
                crypto::wipe(&mut self.key);
                return VaultError::Io;
            }
            if !self.flush_header() {
                crypto::wipe(&mut self.key);
                return VaultError::Io;
            }
            self.ready = true;
            self.provisioned = true;
            self.publish_snapshot();
            return VaultError::Ok;
        }

        // Existing vault: inspect both slots independently.
        let mut cand = [[0u8; VAULT_HEADER_BYTES]; 2];
        let st_a = self.probe_header_slot(HDR_SLOT0, &mut cand[0], mat.as_slice());
        let st_b = self.probe_header_slot(HDR_SLOT1, &mut cand[1], mat.as_slice());
        let seq_a = if st_a == SlotState::Absent {
            0
        } else {
            get32(&cand[0][HDR_SEQ..])
        };
        let seq_b = if st_b == SlotState::Absent {
            0
        } else {
            get32(&cand[1][HDR_SEQ..])
        };

        if st_a == SlotState::Invalid
            || st_b == SlotState::Invalid
            || st_a == SlotState::TagMismatch
            || st_b == SlotState::TagMismatch
        {
            let newer_broken = (st_a == SlotState::Invalid
                && (st_b != SlotState::Valid || seq_a > seq_b))
                || (st_b == SlotState::Invalid && (st_a != SlotState::Valid || seq_b > seq_a));
            let any_valid = st_a == SlotState::Valid || st_b == SlotState::Valid;
            if newer_broken && any_valid {
                return VaultError::Tampered;
            }
            if !any_valid {
                return VaultError::WrongPassword;
            }
            let newer_tag_mismatch = (st_a == SlotState::TagMismatch
                && (st_b != SlotState::Valid || seq_a > seq_b))
                || (st_b == SlotState::TagMismatch && (st_a != SlotState::Valid || seq_b > seq_a));
            if newer_tag_mismatch {
                return VaultError::WrongPassword;
            }
        }

        let use_a = st_a == SlotState::Valid && (st_b != SlotState::Valid || seq_a > seq_b);
        if !use_a && st_b != SlotState::Valid && st_a != SlotState::Valid {
            return VaultError::WrongPassword;
        }
        self.hdr = if use_a { cand[0] } else { cand[1] };
        self.hdr_seq = get32(&self.hdr[HDR_SEQ..]);

        self.generation = get32(&self.hdr[HDR_GENERATION..]);
        self.iters = get32(&self.hdr[HDR_ITERS..]);
        self.key_file_flag = get32(&self.hdr[HDR_FLAGS..]) & FLAG_KEYFILE != 0;
        self.data_start = get32(&self.hdr[HDR_DATA_START..]) as usize;
        self.used_end = get32(&self.hdr[HDR_USED_BYTES..]) as usize;
        if self.data_start != region_start(0) && self.data_start != region_start(1) {
            return VaultError::Tampered;
        }
        self.region = if self.data_start == region_start(1) {
            1
        } else {
            0
        };
        if self.used_end < self.data_start || self.used_end > region_start(2) {
            return VaultError::Tampered;
        }
        self.compacted_once = get32(&self.hdr[HDR_FLAGS..]) & FLAG_COMPACTED != 0;
        self.salt_pw
            .copy_from_slice(&self.hdr[HDR_SALT_PW..HDR_SALT_PW + PBKDF2_SALT_LEN]);
        self.salt_dev
            .copy_from_slice(&self.hdr[HDR_SALT_DEV..HDR_SALT_DEV + PBKDF2_SALT_LEN]);

        let sp = self.salt_pw;
        let sd = self.salt_dev;
        match derive_key(mat.as_slice(), &sp, &sd, self.iters, &self.mac6) {
            Ok(k) => self.key = k,
            Err(e) => {
                crypto::wipe(&mut self.key);
                return e;
            }
        }

        let sc = self.scan_log();
        if sc != VaultError::Ok {
            crypto::wipe(&mut self.key);
            self.index.clear();
            self.live_payload = 0;
            return sc;
        }

        if get32(&self.hdr[HDR_ENTRY_COUNT..]) != self.index.len() as u32
            || get32(&self.hdr[HDR_LIVE_BYTES..]) != self.live_payload as u32
        {
            crypto::wipe(&mut self.key);
            self.index.clear();
            self.live_payload = 0;
            return VaultError::Tampered;
        }

        if self.tail_is_dirty() {
            let rc = self.compact();
            if rc != VaultError::Ok {
                crypto::wipe(&mut self.key);
                self.index.clear();
                self.live_payload = 0;
                return rc;
            }
        }

        self.ready = true;
        self.provisioned = true;
        self.publish_snapshot();
        VaultError::Ok
    }

    // ── Entry operations ─────────────────────────────────────────────────────

    pub fn get(&self, id: u32) -> Result<Entry, VaultError> {
        if !self.ready {
            return Err(VaultError::BootStrap);
        }
        match self.find_index(id) {
            Some(at) => self.read_record(at),
            None => Err(VaultError::NotFound),
        }
    }

    pub fn load(&self, max_count: usize) -> Result<Vec<Entry>, VaultError> {
        if !self.ready {
            return Err(VaultError::BootStrap);
        }
        let mut out = Vec::new();
        for i in 0..self.index.len() {
            if out.len() >= max_count {
                break;
            }
            out.push(self.read_record(i)?);
        }
        Ok(out)
    }

    pub fn add(&mut self, e: &Entry) -> Result<u32, VaultError> {
        if !self.ready {
            return Err(VaultError::BootStrap);
        }
        let mut buf = vec![0u8; MAX_ENTRY_LEN];
        let plen = match e.serialize(&mut buf) {
            Some(n) if n <= MAX_ENTRY_LEN => n,
            _ => {
                crypto::wipe(&mut buf);
                return Err(VaultError::EntryTooLong);
            }
        };

        let id = if e.id != 0 { e.id } else { self.next_id };
        let at = self.find_index(id);
        let is_update = at.is_some();
        let prev_len = at.map(|i| self.index[i].len as usize).unwrap_or(0);

        if !is_update && self.index.len() as u32 >= MAX_ENTRIES {
            crypto::wipe(&mut buf);
            return Err(VaultError::TooManyEntries);
        }
        if self.live_payload - prev_len + plen > VAULT_LIVE_BUDGET_BYTES {
            crypto::wipe(&mut buf);
            return Err(VaultError::Budget);
        }
        if self.used_end - self.data_start + REC_FIXED + plen > VAULT_COMPACT_TRIGGER_BYTES {
            let c = self.compact();
            if c != VaultError::Ok {
                crypto::wipe(&mut buf);
                return Err(if c == VaultError::NoSpace {
                    VaultError::Budget
                } else {
                    c
                });
            }
            if self.used_end - self.data_start + REC_FIXED + plen > VAULT_REGION_BYTES {
                crypto::wipe(&mut buf);
                return Err(VaultError::Budget);
            }
        }

        let off = self.used_end;
        let wr = self.write_record_at(off, id, &buf[..plen]);
        crypto::wipe(&mut buf);
        if wr != VaultError::Ok {
            return Err(wr);
        }
        self.used_end = off + REC_FIXED + plen;
        if !self.apply_to_index(id, off, plen as u16) {
            self.used_end = off;
            return Err(VaultError::TooManyEntries);
        }
        if id >= self.next_id {
            self.next_id = id + 1;
        }
        if !self.flush_header() {
            return Err(VaultError::Io);
        }
        self.publish_snapshot();
        Ok(id)
    }

    pub fn remove(&mut self, id: u32) -> VaultError {
        if !self.ready {
            return VaultError::BootStrap;
        }
        if self.find_index(id).is_none() {
            return VaultError::NotFound;
        }
        if self.used_end - self.data_start + REC_FIXED + 1 > VAULT_REGION_BYTES {
            let c = self.compact();
            if c != VaultError::Ok {
                return c;
            }
            if self.used_end - self.data_start + REC_FIXED + 1 > VAULT_REGION_BYTES {
                return VaultError::NoSpace;
            }
        }
        let off = self.used_end;
        let wr = self.write_record_at(off, id | TOMBSTONE_BIT, &[]);
        if wr != VaultError::Ok {
            return wr;
        }
        self.used_end = off + REC_FIXED + 1;
        if let Some(at) = self.find_index(id) {
            self.remove_at(at);
        }
        if !self.flush_header() {
            return VaultError::Io;
        }
        self.publish_snapshot();
        VaultError::Ok
    }

    // ── Destructive operations ───────────────────────────────────────────────

    /// Erases the vault and provisions an empty one under `password` with fresh
    /// salts. Mirrors `vault::clear`.
    pub fn clear(
        &mut self,
        password: &str,
        key_file: Option<&[u8]>,
        rng: &mut dyn RandomSource,
    ) -> VaultError {
        if !self.ready {
            return VaultError::BootStrap;
        }
        let pw_len = password.len();
        if !(MIN_PASS_CHARS..MAX_PASS_CHARS).contains(&pw_len) {
            return VaultError::WrongPassword;
        }
        let mat = match build_material(password, key_file) {
            Some(m) => Secret::new(m),
            None => return VaultError::WrongPassword,
        };
        self.key_file_flag = key_file.map(|k| !k.is_empty()).unwrap_or(false);

        let size = self.storage.size();
        if self.storage.erase(0, size).is_err() {
            return VaultError::Io;
        }
        self.key = [0; AES_KEY_LEN];
        self.hdr = [0; VAULT_HEADER_BYTES];
        self.index.clear();
        self.salt_pw = [0; PBKDF2_SALT_LEN];
        self.salt_dev = [0; PBKDF2_SALT_LEN];
        self.live_payload = 0;
        self.generation = 1;
        self.iters = PBKDF2_ITERS;
        self.next_id = 1;
        self.compacted_once = false;
        self.region = 0;
        self.data_start = region_start(0);
        self.used_end = self.data_start;
        rng.fill(&mut self.salt_pw);
        rng.fill(&mut self.salt_dev);
        let sp = self.salt_pw;
        let sd = self.salt_dev;
        match derive_key(mat.as_slice(), &sp, &sd, self.iters, &self.mac6) {
            Ok(k) => self.key = k,
            Err(e) => return e,
        }
        if !self.flush_header() {
            return VaultError::Io;
        }
        self.publish_snapshot();
        VaultError::Ok
    }

    /// Changes the master password of an open vault. Mirrors `vault::rekey`.
    pub fn rekey(
        &mut self,
        new_password: &str,
        key_file: Option<&[u8]>,
        rng: &mut dyn RandomSource,
    ) -> VaultError {
        if !self.ready {
            return VaultError::BootStrap;
        }
        let pw_len = new_password.len();
        if !(MIN_PASS_CHARS..MAX_PASS_CHARS).contains(&pw_len) {
            return VaultError::WrongPassword;
        }
        let mat = match build_material(new_password, key_file) {
            Some(m) => Secret::new(m),
            None => return VaultError::WrongPassword,
        };
        let new_keyfile = key_file.map(|k| !k.is_empty()).unwrap_or(false);

        let saved = RekeySaved {
            old_data_start: self.data_start,
            old_used_end: self.used_end,
            old_region: self.region,
            old_hdr: self.hdr,
            old_salt_pw: self.salt_pw,
            old_salt_dev: self.salt_dev,
            old_key: self.key,
            old_keyfile: self.key_file_flag,
            old_next_id: self.next_id,
            saved_index: self.index.clone(),
            saved_payload: self.live_payload,
        };
        let old_aad = build_aad(&self.hdr);
        let target_region = 1 - saved.old_region;
        let target_start = region_start(target_region);

        let mut need = 0usize;
        for it in &saved.saved_index {
            need += REC_FIXED + it.len as usize;
        }
        if target_start + need > region_start(2) {
            return VaultError::NoSpace;
        }

        rng.fill(&mut self.salt_pw);
        rng.fill(&mut self.salt_dev);
        let sp = self.salt_pw;
        let sd = self.salt_dev;
        match derive_key(mat.as_slice(), &sp, &sd, self.iters, &self.mac6) {
            Ok(k) => self.key = k,
            Err(e) => {
                self.rekey_restore(&saved, false);
                return e;
            }
        }
        self.key_file_flag = new_keyfile;

        if self
            .storage
            .erase(target_start, VAULT_REGION_BYTES)
            .is_err()
        {
            self.rekey_restore(&saved, false);
            return VaultError::Io;
        }

        self.generation += 1;
        self.region = target_region;
        self.data_start = target_start;
        self.used_end = target_start;
        self.build_hdr();

        let mut cursor = target_start;
        self.index.clear();
        self.live_payload = 0;
        let mut ok = true;
        for it in &saved.saved_index {
            let mut head = [0u8; REC_FIXED];
            if self.storage.read(it.offset, &mut head).is_err() {
                ok = false;
                break;
            }
            let len = it.len as usize;
            let mut buf = vec![0u8; len];
            if self.storage.read(it.offset + REC_FIXED, &mut buf).is_err() {
                ok = false;
                break;
            }
            let tag = &head[6 + GCM_IV_LEN..REC_FIXED];
            if crypto::aes_gcm_decrypt(
                &saved.old_key,
                &head[6..6 + GCM_IV_LEN],
                &old_aad,
                &mut buf,
                tag,
            )
            .is_err()
            {
                ok = false;
                break;
            }
            let wr = self.write_record_at(cursor, it.id, &buf);
            crypto::wipe(&mut buf);
            if wr != VaultError::Ok {
                ok = false;
                break;
            }
            self.index.push(Index {
                id: it.id,
                offset: cursor,
                len: it.len,
            });
            self.live_payload += len;
            cursor += REC_FIXED + len;
        }

        if !ok {
            self.rekey_restore(&saved, true);
            return VaultError::Io;
        }

        self.used_end = cursor;
        self.build_hdr();
        if !self.flush_header() {
            self.rekey_restore(&saved, true);
            return VaultError::Io;
        }

        // The old region holds records under the old key; sweep it best-effort.
        let _ = self
            .storage
            .erase(region_start(saved.old_region), VAULT_REGION_BYTES);
        self.publish_snapshot();
        VaultError::Ok
    }

    fn rekey_restore(&mut self, saved: &RekeySaved, gen_bumped: bool) {
        self.salt_pw = saved.old_salt_pw;
        self.salt_dev = saved.old_salt_dev;
        self.key = saved.old_key;
        if gen_bumped {
            self.generation -= 1;
        }
        self.key_file_flag = saved.old_keyfile;
        self.region = saved.old_region;
        self.data_start = saved.old_data_start;
        self.used_end = saved.old_used_end;
        self.compacted_once = get32(&saved.old_hdr[HDR_FLAGS..]) & FLAG_COMPACTED != 0;
        self.hdr = saved.old_hdr;
        self.index = saved.saved_index.clone();
        self.live_payload = saved.saved_payload;
        self.next_id = saved.old_next_id;
    }

    /// Destroys the vault without a password. Mirrors `vault::reset`.
    pub fn reset(&mut self) -> VaultError {
        if !self.storage_ok() {
            return VaultError::NotFound;
        }
        let size = self.storage.size();
        if self.storage.erase(0, size).is_err() {
            return VaultError::Io;
        }
        crypto::wipe(&mut self.key);
        crypto::wipe(&mut self.hdr);
        crypto::wipe(&mut self.salt_pw);
        crypto::wipe(&mut self.salt_dev);
        self.index.clear();
        self.live_payload = 0;
        self.generation = 1;
        self.iters = PBKDF2_ITERS;
        self.next_id = 1;
        self.compacted_once = false;
        self.key_file_flag = false;
        self.region = 0;
        self.data_start = region_start(0);
        self.used_end = self.data_start;
        self.hdr_seq = 0;
        self.ready = false;
        self.provisioned = false;
        self.publish_snapshot();
        VaultError::Ok
    }
}

/// Snapshot of everything `rekey` must restore on a pre-commit failure.
struct RekeySaved {
    old_data_start: usize,
    old_used_end: usize,
    old_region: usize,
    old_hdr: [u8; VAULT_HEADER_BYTES],
    old_salt_pw: [u8; PBKDF2_SALT_LEN],
    old_salt_dev: [u8; PBKDF2_SALT_LEN],
    old_key: [u8; AES_KEY_LEN],
    old_keyfile: bool,
    old_next_id: u32,
    saved_index: Vec<Index>,
    saved_payload: usize,
}

impl Drop for RekeySaved {
    fn drop(&mut self) {
        crypto::wipe(&mut self.old_key);
        crypto::wipe(&mut self.old_salt_pw);
        crypto::wipe(&mut self.old_salt_dev);
    }
}

// ── Free helpers ─────────────────────────────────────────────────────────────

fn region_start(region: usize) -> usize {
    VAULT_REGION0_OFFSET + region * VAULT_REGION_BYTES
}

fn header_slot_offset(seq: u32) -> usize {
    if seq & 1 == 1 {
        HDR_SLOT1
    } else {
        HDR_SLOT0
    }
}

fn put32(p: &mut [u8], v: u32) {
    p[0] = v as u8;
    p[1] = (v >> 8) as u8;
    p[2] = (v >> 16) as u8;
    p[3] = (v >> 24) as u8;
}

fn put16(p: &mut [u8], v: u16) {
    p[0] = v as u8;
    p[1] = (v >> 8) as u8;
}

fn get32(p: &[u8]) -> u32 {
    u32::from(p[0]) | (u32::from(p[1]) << 8) | (u32::from(p[2]) << 16) | (u32::from(p[3]) << 24)
}

fn get16(p: &[u8]) -> u16 {
    u16::from(p[0]) | (u16::from(p[1]) << 8)
}

/// AAD for header tags and record tags. Counters, flags, the check tag, the
/// commit marker and the header sequence all change on every save and are
/// therefore zeroed here; otherwise adding a record would invalidate the tags
/// of every record already on flash.
fn build_aad(hdr: &[u8; VAULT_HEADER_BYTES]) -> [u8; VAULT_HEADER_BYTES] {
    let mut aad = *hdr;
    aad[HDR_ENTRY_COUNT..HDR_FLAGS].fill(0); // entryCount + liveBytes + usedBytes
    aad[HDR_FLAGS..HDR_FLAGS + 4].fill(0);
    aad[HDR_CHECK..HDR_CHECK + GCM_TAG_LEN].fill(0);
    aad[HDR_COMMIT..HDR_COMMIT + COMMIT_BYTES].fill(0);
    aad[HDR_SEQ..HDR_SEQ + 4].fill(0);
    aad
}

/// GCM nonce = 4-byte generation + 8-byte big-endian record offset.
fn nonce_for(generation: u32, offset: usize) -> [u8; GCM_IV_LEN] {
    let mut nonce = [0u8; GCM_IV_LEN];
    put32(&mut nonce[0..], generation);
    let off = offset as u64;
    for i in 0..8 {
        nonce[4 + i] = (off >> ((7 - i) * 8)) as u8;
    }
    nonce
}

/// Builds the KDF material: `password` bytes, plus the key file's SHA-256 when
/// a key file is supplied. Without a key file the result is exactly the
/// password string, so pre-key-file vaults keep opening.
fn build_material(password: &str, key_file: Option<&[u8]>) -> Option<Vec<u8>> {
    let pw = password.as_bytes();
    if pw.len() >= MAX_PASS_CHARS || pw.len() + 32 > MAX_PASS_CHARS + 32 {
        return None;
    }
    let mut v = Vec::with_capacity(pw.len() + 32);
    v.extend_from_slice(pw);
    if let Some(kf) = key_file {
        if !kf.is_empty() {
            let h = crypto::sha256(kf);
            v.extend_from_slice(&h);
        }
    }
    Some(v)
}

/// KEK = PBKDF2(material, salt_pw) XOR device factor(mac6, salt_dev).
fn derive_key(
    mat: &[u8],
    salt_pw: &[u8],
    salt_dev: &[u8],
    iters: u32,
    mac6: &[u8; 6],
) -> Result<[u8; AES_KEY_LEN], VaultError> {
    let from_pw =
        crypto::pbkdf2_hmac_sha256(mat, salt_pw, iters).map_err(|_| VaultError::Crypto)?;
    let term = device::factor(mac6, salt_dev).map_err(|_| VaultError::Crypto)?;
    let mut key = [0u8; AES_KEY_LEN];
    for i in 0..AES_KEY_LEN {
        key[i] = from_pw[i] ^ term[i];
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::Field;
    use crate::rand::CycleSource;

    const MAC: [u8; 6] = [0x44, 0x21, 0x5b, 0x5f, 0x0c, 0x7c];
    const SALT_BYTES: &[u8] = b"deterministic-salt-material-0123456789";
    const PW: &str = "correct horse battery staple";
    const PW2: &str = "another correct battery staple";

    struct MemStorage {
        data: Vec<u8>,
    }

    impl MemStorage {
        fn new(size: usize) -> Self {
            Self {
                data: vec![0xFF; size],
            }
        }
    }

    impl Storage for MemStorage {
        fn size(&self) -> usize {
            self.data.len()
        }
        fn read(&self, offset: usize, buf: &mut [u8]) -> Result<(), VaultError> {
            let end = offset.checked_add(buf.len()).ok_or(VaultError::Io)?;
            if end > self.data.len() {
                return Err(VaultError::Io);
            }
            buf.copy_from_slice(&self.data[offset..end]);
            Ok(())
        }
        fn write(&mut self, offset: usize, buf: &[u8]) -> Result<(), VaultError> {
            let end = offset.checked_add(buf.len()).ok_or(VaultError::Io)?;
            if end > self.data.len() {
                return Err(VaultError::Io);
            }
            for (dst, &src) in self.data[offset..end].iter_mut().zip(buf) {
                *dst &= src; // flash can only clear bits
            }
            Ok(())
        }
        fn erase(&mut self, offset: usize, len: usize) -> Result<(), VaultError> {
            let end = offset.checked_add(len).ok_or(VaultError::Io)?;
            if end > self.data.len() {
                return Err(VaultError::Io);
            }
            self.data[offset..end].fill(0xFF);
            Ok(())
        }
    }

    fn vault() -> Vault<MemStorage> {
        Vault::new(MemStorage::new(VAULT_PARTITION_BYTES), MAC)
    }

    fn rng() -> CycleSource<'static> {
        CycleSource::new(SALT_BYTES)
    }

    fn entry(title: &str, password: &str) -> Entry {
        let mut e = Entry::new();
        e.set(Field::Title, title.as_bytes());
        e.set(Field::Login, b"user@example.com");
        e.set(Field::Password, password.as_bytes());
        e.set(Field::Url, b"https://example.com");
        e.set(Field::Note, b"a note");
        e
    }

    #[test]
    fn provision_add_reopen() {
        let mut v = vault();
        assert_eq!(v.snapshot().state, State::Unprovisioned);
        assert!(!v.provisioned());
        assert_eq!(v.begin(PW, None, &mut rng()), VaultError::Ok);
        assert!(v.provisioned());
        assert_eq!(v.snapshot().state, State::Unlocked);

        let id = v.add(&entry("Mail", "hunter2")).unwrap();
        assert_eq!(v.count(), 1);
        let got = v.get(id).unwrap();
        assert_eq!(got.get(Field::Password), b"hunter2");

        v.close();
        assert!(!v.initialized());
        assert_eq!(v.count(), 0);
        assert_eq!(v.snapshot().state, State::Locked);

        assert_eq!(v.begin(PW, None, &mut rng()), VaultError::Ok);
        assert_eq!(v.count(), 1);
        let got = v.get(id).unwrap();
        assert_eq!(got.get(Field::Title), b"Mail");
        assert_eq!(got.get(Field::Password), b"hunter2");
    }

    #[test]
    fn wrong_password_keeps_locked() {
        let mut v = vault();
        assert_eq!(v.begin(PW, None, &mut rng()), VaultError::Ok);
        v.close();
        assert_eq!(
            v.begin("definitely the wrong password", None, &mut rng()),
            VaultError::WrongPassword
        );
        assert_eq!(v.snapshot().state, State::Locked);
        assert!(v.provisioned());
        assert!(!v.initialized());
    }

    #[test]
    fn remove_drops_entry_after_reopen() {
        let mut v = vault();
        assert_eq!(v.begin(PW, None, &mut rng()), VaultError::Ok);
        let a = v.add(&entry("A", "pw-a")).unwrap();
        let b = v.add(&entry("B", "pw-b")).unwrap();
        assert_eq!(v.remove(a), VaultError::Ok);
        assert_eq!(v.count(), 1);
        assert_eq!(v.get(a), Err(VaultError::NotFound));
        assert_eq!(v.get(b).unwrap().get(Field::Password), b"pw-b");

        v.close();
        assert_eq!(v.begin(PW, None, &mut rng()), VaultError::Ok);
        assert_eq!(v.count(), 1);
        assert_eq!(v.get(a), Err(VaultError::NotFound));
    }

    #[test]
    fn update_reuses_id() {
        let mut v = vault();
        assert_eq!(v.begin(PW, None, &mut rng()), VaultError::Ok);
        let id = v.add(&entry("A", "old")).unwrap();
        let mut e = entry("A", "new");
        e.id = id;
        assert_eq!(v.add(&e).unwrap(), id);
        assert_eq!(v.count(), 1);
        assert_eq!(v.get(id).unwrap().get(Field::Password), b"new");
    }

    #[test]
    fn rekey_changes_password() {
        let mut v = vault();
        assert_eq!(v.begin(PW, None, &mut rng()), VaultError::Ok);
        v.add(&entry("Mail", "secret")).unwrap();
        assert_eq!(v.rekey(PW2, None, &mut rng()), VaultError::Ok);
        v.close();

        assert_eq!(v.begin(PW, None, &mut rng()), VaultError::WrongPassword);
        assert_eq!(v.begin(PW2, None, &mut rng()), VaultError::Ok);
        assert_eq!(v.count(), 1);
        let entries = v.load(10).unwrap();
        assert_eq!(entries[0].get(Field::Password), b"secret");
    }

    #[test]
    fn compaction_preserves_entries() {
        let mut v = vault();
        assert_eq!(v.begin(PW, None, &mut rng()), VaultError::Ok);

        let note = vec![b'x'; 400];
        let mut ids = Vec::new();
        for i in 0..300 {
            let mut e = entry("bulk", "password");
            e.set(Field::Note, &note);
            e.set(Field::Login, format!("user{i}").as_bytes());
            ids.push(v.add(&e).unwrap());
        }
        let st = v.stats();
        assert!(st.compacted_once, "compaction should have run");
        assert!(st.generation > 1, "generation should advance");
        assert_eq!(v.count(), 300);

        v.close();
        assert_eq!(v.begin(PW, None, &mut rng()), VaultError::Ok);
        assert_eq!(v.count(), 300);
        for &id in &ids {
            assert!(v.get(id).is_ok());
        }
        assert_eq!(v.get(ids[150]).unwrap().get(Field::Login), b"user150");
    }

    #[test]
    fn key_file_required_and_enforced() {
        let mut v = vault();
        let kf = b"super-secret-key-file";
        assert_eq!(v.begin(PW, Some(kf), &mut rng()), VaultError::Ok);
        v.add(&entry("Mail", "secret")).unwrap();
        assert!(v.key_file_required());
        v.close();

        assert_eq!(v.begin(PW, None, &mut rng()), VaultError::WrongPassword);
        assert_eq!(
            v.begin(PW, Some(b"wrong-key-file"), &mut rng()),
            VaultError::WrongPassword
        );
        assert_eq!(v.begin(PW, Some(kf), &mut rng()), VaultError::Ok);
        assert_eq!(v.count(), 1);
    }

    #[test]
    fn tampered_newest_header_is_rejected() {
        let mut v = vault();
        assert_eq!(v.begin(PW, None, &mut rng()), VaultError::Ok);
        v.add(&entry("Mail", "secret")).unwrap();
        v.close();

        // After provisioning + one add the newest slot is slot 1 (offset 4096).
        // Clear a bit in the version field: structure invalid, and the slot is
        // newer than the valid backup -> Tampered, not a silent rollback.
        let off = HDR_SLOT1 + HDR_VERSION;
        let mut byte = [0u8; 1];
        v.storage_ref().read(off, &mut byte).unwrap();
        byte[0] &= 0xFE;
        v.storage_mut().write(off, &byte).unwrap();

        assert_eq!(v.begin(PW, None, &mut rng()), VaultError::Tampered);
    }

    #[test]
    fn torn_tail_triggers_rebuild() {
        let mut v = vault();
        assert_eq!(v.begin(PW, None, &mut rng()), VaultError::Ok);
        // No records yet: used_end is the region start. Drop a dirty byte just
        // past it; begin() must notice and rebuild into the clean region.
        let dirty_at = region_start(0);
        v.storage_mut().write(dirty_at, &[0x00]).unwrap();
        v.close();

        assert_eq!(v.begin(PW, None, &mut rng()), VaultError::Ok);
        assert_eq!(v.stats().generation, 2);
        assert!(v.stats().compacted_once);
    }

    #[test]
    fn clear_reprovisions_and_reset_destroys() {
        let mut v = vault();
        assert_eq!(v.begin(PW, None, &mut rng()), VaultError::Ok);
        v.add(&entry("Mail", "secret")).unwrap();

        assert_eq!(v.clear(PW2, None, &mut rng()), VaultError::Ok);
        assert!(v.initialized());
        assert_eq!(v.count(), 0);
        v.close();
        assert_eq!(v.begin(PW2, None, &mut rng()), VaultError::Ok);
        assert_eq!(v.count(), 0);

        assert_eq!(v.reset(), VaultError::Ok);
        assert_eq!(v.snapshot().state, State::Unprovisioned);
        assert!(!v.provisioned());
        assert!(!v.initialized());
    }

    #[test]
    fn load_honors_max_count() {
        let mut v = vault();
        assert_eq!(v.begin(PW, None, &mut rng()), VaultError::Ok);
        for i in 0..5 {
            v.add(&entry("x", &format!("pw{i}"))).unwrap();
        }
        assert_eq!(v.load(3).unwrap().len(), 3);
        assert_eq!(v.load(100).unwrap().len(), 5);
    }
}
