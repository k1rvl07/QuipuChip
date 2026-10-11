//! Auth worker: owns the PMV1 vault and the authorization FSM, and runs the
//! expensive PBKDF2 work off the single httpd task.
//!
//! This mirrors the concurrency contract of the C++ `src/auth.cpp`. One worker
//! thread owns the [`Auth`] state machine and the [`Vault`]; the HTTP layer asks
//! it to start a job, polls the one-shot result, and otherwise reads a
//! lock-free snapshot for the hot `GET /api/auth/state` path. A running KDF
//! therefore never blocks the server task, which is what makes the
//! `202 Accepted` + `/api/auth/job/{id}` protocol work.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::Mutex;
use std::time::Duration;

use esp_idf_svc::sys;
use pm_core::auth::{
    Auth, Job, JobId, JobResult, KeyfileAction, State, NO_JOB, SESSION_TOKEN_HEX_LEN,
};
use pm_core::config::MAX_ENTRIES;
use pm_core::crypto;
use pm_core::entry::{Entry, Field, VaultError};
use pm_core::rand::RandomSource;
use pm_core::vault::Vault;

use crate::platform::device;
use crate::platform::storage::EspVaultStorage;
use crate::platform::time::{now_ms, SystemClock};

/// Interval between idle checks on the worker (`config::kAuthIdleCheckMs`); the
/// worker also wakes immediately when a command arrives.
const IDLE_TICK: Duration = Duration::from_millis(1000);
/// Worker stack. The KDF and the vault journal scan need more than the tiny
/// default a `std::thread` gets on ESP-IDF.
const WORKER_STACK: usize = 24 * 1024;

/// Entropy from the hardware RNG.
struct EspRandom;

impl RandomSource for EspRandom {
    fn fill(&mut self, buf: &mut [u8]) {
        unsafe { sys::esp_fill_random(buf.as_mut_ptr().cast(), buf.len()) };
    }
}

// ── Lock-free snapshot read by the HTTP layer ────────────────────────────────
//
// These are the only fields the HTTP layer needs without talking to the worker.
// Publishing them as atomics keeps `GET /api/auth/state` and the session check
// responsive while a 2.9 s PBKDF2 runs on the worker.

static PROVISIONED: AtomicBool = AtomicBool::new(false);
static UNLOCKED: AtomicBool = AtomicBool::new(false);
static BUSY: AtomicBool = AtomicBool::new(false);
static KEY_FILE_REQUIRED: AtomicBool = AtomicBool::new(false);
static FAIL_COUNT: AtomicU32 = AtomicU32::new(0);
static LOCKOUT_UNTIL_MS: AtomicU32 = AtomicU32::new(0);
static ENTRY_COUNT: AtomicU32 = AtomicU32::new(0);

/// Current session token as 64 hex characters, or `None`. Guarded by a short-
/// lived mutex: it is only touched when the session opens or closes, never
/// during a KDF.
static TOKEN_HEX: Mutex<Option<[u8; SESSION_TOKEN_HEX_LEN]>> = Mutex::new(None);

/// One-shot job result slot, mirroring the C++ `g_slot`. Written by the worker
/// at publish time; the secrets are taken exactly once by [`poll`].
static JOB: Mutex<JobSlot> = Mutex::new(JobSlot::new());

/// Hand-off channel to the worker. `None` until [`install`] runs.
static SENDER: Mutex<Option<Sender<Command>>> = Mutex::new(None);

struct JobSlot {
    id: JobId,
    kind: Job,
    result: JobResult,
    password: Vec<u8>,
    token: Vec<u8>,
}

impl JobSlot {
    const fn new() -> Self {
        Self {
            id: NO_JOB,
            kind: Job::Provision,
            result: JobResult::Pending,
            password: Vec::new(),
            token: Vec::new(),
        }
    }

    fn clear_secrets(&mut self) {
        crypto::wipe(&mut self.password);
        self.password.clear();
        crypto::wipe(&mut self.token);
        self.token.clear();
    }

    fn begin(&mut self, id: JobId, kind: Job) {
        self.clear_secrets();
        self.id = id;
        self.kind = kind;
        self.result = JobResult::Pending;
    }

    fn complete(&mut self, kind: Job, result: JobResult, password: Vec<u8>, token: Vec<u8>) {
        self.kind = kind;
        self.result = result;
        self.password = password;
        self.token = token;
    }
}

/// A polling response. Wipes its secrets on drop; the caller consumes them
/// first.
pub struct PolledJob {
    pub kind: Job,
    pub result: JobResult,
    pub password: Vec<u8>,
    pub session_token: Vec<u8>,
}

impl Drop for PolledJob {
    fn drop(&mut self) {
        crypto::wipe(&mut self.password);
        crypto::wipe(&mut self.session_token);
    }
}

/// A command for the worker. Each carries its own reply channel so that the
/// HTTP handler's short operations (submit, lock) return promptly.
enum Command {
    Provision {
        key_file: Vec<u8>,
        reply: Sender<JobId>,
    },
    Unlock {
        password: Vec<u8>,
        key_file: Vec<u8>,
        reply: Sender<JobId>,
    },
    Reset {
        reply: Sender<JobId>,
    },
    Rekey {
        old_password: Vec<u8>,
        new_password: Option<Vec<u8>>,
        cur_key_file: Vec<u8>,
        new_key_file: Vec<u8>,
        action: KeyfileAction,
        reply: Sender<JobId>,
    },
    Lock {
        reply: Sender<()>,
    },
    GeneratePassword {
        reply: Sender<String>,
    },
    EntriesList {
        reply: Sender<Result<Vec<Entry>, VaultError>>,
    },
    EntryGet {
        id: u32,
        reply: Sender<Result<Box<Entry>, VaultError>>,
    },
    EntryWrite {
        id: u32,
        entry: Box<Entry>,
        reply: Sender<Result<u32, VaultError>>,
    },
    EntryRemove {
        id: u32,
        reply: Sender<Result<(), VaultError>>,
    },
    ImportBatch {
        entries: Vec<Entry>,
        reply: Sender<ImportOutcome>,
    },
}

/// Result of an import batch: how many records landed and the first error that
/// stopped it (if any). Records already added are kept — no rollback.
pub struct ImportOutcome {
    pub added: u32,
    pub error: Option<VaultError>,
}

struct Worker {
    auth: Auth<EspRandom, SystemClock>,
    vault: Vault<EspVaultStorage>,
}

impl Worker {
    /// Publishes the lock-free snapshot and the current token/counters.
    fn publish(&self) {
        let s = self.auth.state();
        PROVISIONED.store(s.provisioned, Ordering::Relaxed);
        UNLOCKED.store(s.unlocked, Ordering::Relaxed);
        BUSY.store(s.busy, Ordering::Relaxed);
        FAIL_COUNT.store(u32::from(s.fail_count), Ordering::Relaxed);
        let until = if s.lockout_ms_left == 0 {
            0
        } else {
            now_ms().wrapping_add(s.lockout_ms_left)
        };
        LOCKOUT_UNTIL_MS.store(until, Ordering::Relaxed);
        KEY_FILE_REQUIRED.store(self.vault.key_file_required(), Ordering::Relaxed);
        ENTRY_COUNT.store(self.vault.count(), Ordering::Relaxed);

        let token = self.auth.session_token_hex().and_then(hex_to_array);
        if let Ok(mut guard) = TOKEN_HEX.lock() {
            *guard = token;
        }
    }

    fn run_and_finish(&mut self, id: JobId, req: Option<pm_core::auth::Request>) {
        if let Some(req) = req {
            self.auth.run(&mut self.vault, &req);
            if let Some(view) = self.auth.poll(id) {
                let password = view.password.clone();
                let token = view.session_token.clone();
                if let Ok(mut slot) = JOB.lock() {
                    slot.complete(view.kind, view.result, password, token);
                }
            }
        }
        self.publish();
    }
}

fn hex_to_array(s: String) -> Option<[u8; SESSION_TOKEN_HEX_LEN]> {
    let bytes = s.as_bytes();
    if bytes.len() != SESSION_TOKEN_HEX_LEN {
        return None;
    }
    let mut out = [0u8; SESSION_TOKEN_HEX_LEN];
    out.copy_from_slice(bytes);
    Some(out)
}

fn worker_loop(mut w: Worker, rx: Receiver<Command>) {
    loop {
        w.auth.tick(&mut w.vault);
        w.publish();
        match rx.recv_timeout(IDLE_TICK) {
            Ok(cmd) => handle(&mut w, cmd),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn handle(w: &mut Worker, cmd: Command) {
    match cmd {
        Command::Provision {
            mut key_file,
            reply,
        } => {
            let (id, req) = w.auth.submit_provision(&key_file);
            begin(w, id, Job::Provision, &reply);
            crypto::wipe(&mut key_file);
            w.run_and_finish(id, req);
        }
        Command::Unlock {
            password,
            mut key_file,
            reply,
        } => {
            let pw = core::str::from_utf8(&password).unwrap_or("");
            let (id, req) = w.auth.submit_unlock(pw, &key_file);
            begin(w, id, Job::Unlock, &reply);
            let mut password = password;
            crypto::wipe(&mut password);
            crypto::wipe(&mut key_file);
            w.run_and_finish(id, req);
        }
        Command::Reset { reply } => {
            let (id, req) = w.auth.submit_reset();
            begin(w, id, Job::Reset, &reply);
            w.run_and_finish(id, req);
        }
        Command::Rekey {
            mut old_password,
            new_password,
            mut cur_key_file,
            mut new_key_file,
            action,
            reply,
        } => {
            let old = core::str::from_utf8(&old_password).unwrap_or("");
            let new = new_password
                .as_deref()
                .and_then(|b| core::str::from_utf8(b).ok());
            let (id, req) = w
                .auth
                .submit_rekey(old, new, &cur_key_file, &new_key_file, action);
            begin(w, id, Job::Rekey, &reply);
            crypto::wipe(&mut old_password);
            crypto::wipe(&mut cur_key_file);
            crypto::wipe(&mut new_key_file);
            w.run_and_finish(id, req);
        }
        Command::Lock { reply } => {
            w.auth.lock(&mut w.vault);
            w.publish();
            let _ = reply.send(());
        }
        Command::GeneratePassword { reply } => {
            let pw = w.auth.generate_master_password();
            let _ = reply.send(pw);
        }
        Command::EntriesList { reply } => {
            let _ = reply.send(w.vault.load(MAX_ENTRIES as usize));
        }
        Command::EntryGet { id, reply } => {
            let _ = reply.send(w.vault.get(id).map(Box::new));
        }
        Command::EntryWrite {
            id,
            mut entry,
            reply,
        } => {
            // Update merges the stored password when the request omits it, so a
            // card edit does not wipe the credential.
            let res = if id != 0 {
                match w.vault.get(id) {
                    Ok(old) => {
                        if entry.get(Field::Password).is_empty() {
                            entry.set(Field::Password, old.get(Field::Password));
                        }
                        w.vault.add(&entry)
                    }
                    Err(e) => Err(e),
                }
            } else {
                w.vault.add(&entry)
            };
            let _ = reply.send(res);
        }
        Command::EntryRemove { id, reply } => {
            let res = match w.vault.remove(id) {
                VaultError::Ok => Ok(()),
                e => Err(e),
            };
            let _ = reply.send(res);
        }
        Command::ImportBatch { entries, reply } => {
            let mut added = 0u32;
            let mut error = None;
            for e in &entries {
                match w.vault.add(e) {
                    Ok(_) => added += 1,
                    Err(err) => {
                        error = Some(err);
                        break;
                    }
                }
            }
            let _ = reply.send(ImportOutcome { added, error });
        }
    }
}

/// Records acceptance and replies to the HTTP handler before the KDF starts.
fn begin(w: &mut Worker, id: JobId, kind: Job, reply: &Sender<JobId>) {
    if id != NO_JOB {
        if let Ok(mut slot) = JOB.lock() {
            slot.begin(id, kind);
        }
    }
    let _ = reply.send(id);
    w.publish();
}

/// Installs the worker. Opens the vault partition, reads the provisioned flag
/// from flash, and starts the thread.
pub fn install() -> anyhow::Result<()> {
    let storage = EspVaultStorage::open("vault")
        .map_err(|e| anyhow::anyhow!("vault partition: {}", e.to_str()))?;
    let size = pm_core::vault::Storage::size(&storage);
    log::info!("vault partition: {} KiB", size / 1024);

    let mac6 = device::reversed_mac6().ok_or_else(|| anyhow::anyhow!("efuse MAC unreadable"))?;
    let mut vault = Vault::new(storage, mac6);
    vault.initialize();
    log::info!(
        "vault: provisioned {} count {}",
        vault.provisioned() as u8,
        vault.count()
    );

    let mut auth = Auth::new(EspRandom, SystemClock);
    auth.initialize(&vault);

    let worker = Worker { auth, vault };
    worker.publish();

    let (tx, rx) = mpsc::channel();
    {
        let mut guard = SENDER
            .lock()
            .map_err(|_| anyhow::anyhow!("auth sender poisoned"))?;
        *guard = Some(tx);
    }
    std::thread::Builder::new()
        .name("auth_worker".into())
        .stack_size(WORKER_STACK)
        .spawn(move || worker_loop(worker, rx))?;
    Ok(())
}

/// Lock-free snapshot for `GET /api/auth/state`.
pub fn state() -> State {
    State {
        provisioned: PROVISIONED.load(Ordering::Relaxed),
        unlocked: UNLOCKED.load(Ordering::Relaxed),
        busy: BUSY.load(Ordering::Relaxed),
        fail_count: FAIL_COUNT.load(Ordering::Relaxed) as u8,
        lockout_ms_left: lockout_left_ms(),
    }
}

fn lockout_left_ms() -> u32 {
    let until = LOCKOUT_UNTIL_MS.load(Ordering::Relaxed);
    if until == 0 {
        return 0;
    }
    // Signed difference: an unsigned `until - now` would report "expired" right
    // at the `millis()` wrap.
    let left = until.wrapping_sub(now_ms()) as i32;
    if left > 0 {
        left as u32
    } else {
        0
    }
}

/// Whether the open/closed vault needs a key file (drives the unlock form).
pub fn key_file_required() -> bool {
    KEY_FILE_REQUIRED.load(Ordering::Relaxed)
}

/// Live entry count, for `GET /api/auth/session`.
pub fn entry_count() -> u32 {
    ENTRY_COUNT.load(Ordering::Relaxed)
}

/// Validates `X-PM-Session` in constant time.
pub fn session_valid(token_hex: &str) -> bool {
    if token_hex.len() != SESSION_TOKEN_HEX_LEN {
        return false;
    }
    match TOKEN_HEX.lock() {
        Ok(guard) => match guard.as_ref() {
            Some(expected) => crypto::ct_equal(expected, token_hex.as_bytes()),
            None => false,
        },
        Err(_) => false,
    }
}

/// The current session token as hex, for `GET /api/auth/session`.
pub fn session_token_hex() -> Option<String> {
    let guard = TOKEN_HEX.lock().ok()?;
    let bytes = guard.as_ref()?;
    String::from_utf8(bytes.to_vec()).ok()
}

pub fn submit_provision(key_file: Vec<u8>) -> JobId {
    dispatch(|reply| Command::Provision { key_file, reply })
}

pub fn submit_unlock(password: Vec<u8>, key_file: Vec<u8>) -> JobId {
    dispatch(|reply| Command::Unlock {
        password,
        key_file,
        reply,
    })
}

pub fn submit_reset() -> JobId {
    dispatch(|reply| Command::Reset { reply })
}

pub fn submit_rekey(
    old_password: Vec<u8>,
    new_password: Option<Vec<u8>>,
    cur_key_file: Vec<u8>,
    new_key_file: Vec<u8>,
    action: KeyfileAction,
) -> JobId {
    dispatch(|reply| Command::Rekey {
        old_password,
        new_password,
        cur_key_file,
        new_key_file,
        action,
        reply,
    })
}

/// Sends a submitted job and waits for its id. Returns [`NO_JOB`] when the
/// worker is busy or not installed.
fn dispatch<F>(make: F) -> JobId
where
    F: FnOnce(Sender<JobId>) -> Command,
{
    // Cheap lock-free pre-check: a job is running, so nothing would be accepted.
    if BUSY.load(Ordering::Relaxed) {
        return NO_JOB;
    }
    let (tx, rx) = mpsc::channel();
    if !send(make(tx)) {
        return NO_JOB;
    }
    rx.recv().unwrap_or(NO_JOB)
}

fn send(cmd: Command) -> bool {
    match SENDER.lock() {
        Ok(guard) => match guard.as_ref() {
            Some(sender) => sender.send(cmd).is_ok(),
            None => false,
        },
        Err(_) => false,
    }
}

/// Polls a job id. `None` when the id is unknown.
pub fn poll(id: JobId) -> Option<PolledJob> {
    if id == NO_JOB {
        return None;
    }
    let mut slot = JOB.lock().ok()?;
    if slot.id != id {
        return None;
    }
    let kind = slot.kind;
    let result = slot.result;
    let password = core::mem::take(&mut slot.password);
    let session_token = core::mem::take(&mut slot.token);
    Some(PolledJob {
        kind,
        result,
        password,
        session_token,
    })
}

/// Closes the session (`POST /api/auth/lock`).
pub fn lock() -> bool {
    let (tx, rx) = mpsc::channel();
    if !send(Command::Lock { reply: tx }) {
        return false;
    }
    rx.recv().is_ok()
}

/// A fresh master-password candidate (`GET /api/auth/password`).
pub fn generate_master_password() -> String {
    let (tx, rx) = mpsc::channel();
    if !send(Command::GeneratePassword { reply: tx }) {
        return String::new();
    }
    rx.recv().unwrap_or_default()
}

// ── Entries / export / import (all serialized through the vault owner) ───────

/// Every record, without decrypting anything beyond the journal scan
/// (`GET /api/entries`, `GET /api/export`).
pub fn entries_list() -> Result<Vec<Entry>, VaultError> {
    let (tx, rx) = mpsc::channel();
    if !send(Command::EntriesList { reply: tx }) {
        return Err(VaultError::Io);
    }
    rx.recv().unwrap_or(Err(VaultError::Io))
}

pub fn entry_get(id: u32) -> Result<Box<Entry>, VaultError> {
    let (tx, rx) = mpsc::channel();
    if !send(Command::EntryGet { id, reply: tx }) {
        return Err(VaultError::Io);
    }
    rx.recv().unwrap_or(Err(VaultError::Io))
}

/// Creates (`id == 0`) or updates (`id != 0`) a record, merging the stored
/// password on update when the request leaves it empty.
pub fn entry_write(id: u32, entry: Entry) -> Result<u32, VaultError> {
    let (tx, rx) = mpsc::channel();
    if !send(Command::EntryWrite {
        id,
        entry: Box::new(entry),
        reply: tx,
    }) {
        return Err(VaultError::Io);
    }
    rx.recv().unwrap_or(Err(VaultError::Io))
}

pub fn entry_remove(id: u32) -> Result<(), VaultError> {
    let (tx, rx) = mpsc::channel();
    if !send(Command::EntryRemove { id, reply: tx }) {
        return Err(VaultError::Io);
    }
    rx.recv().unwrap_or(Err(VaultError::Io))
}

/// Adds a validated import batch. Already-added records are kept on failure.
pub fn import_batch(entries: Vec<Entry>) -> ImportOutcome {
    let (tx, rx) = mpsc::channel();
    if !send(Command::ImportBatch { entries, reply: tx }) {
        return ImportOutcome {
            added: 0,
            error: Some(VaultError::Io),
        };
    }
    rx.recv().unwrap_or(ImportOutcome {
        added: 0,
        error: Some(VaultError::Io),
    })
}
