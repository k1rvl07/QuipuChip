//! Auth worker and its client API.
//!
//! Owns the PMV1 vault and the `pm-core` authorization FSM. The worker runs as
//! a task on the **second core** so a 2.9 s PBKDF2 never stalls the core-0
//! executor that drives USB, the network and HTTP.
//!
//! The HTTP layer talks to the worker over a pair of channels: one command
//! channel (capacity 2, so an idle [`Command::Tick`] never blocks a request)
//! and one reply channel (capacity 1). A `Mutex` serialises request/response
//! round trips, which keeps replies matched — only one command that produces a
//! reply is ever outstanding. Commands that mirror the reference's lock-free
//! fast paths (`poll`, `state`, `session_valid`) read shared state directly and
//! never touch the channels, so they stay responsive during a KDF.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use embassy_sync::blocking_mutex::Mutex as BlockingMutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex as Cs;
use embassy_sync::channel::Channel;
use embassy_sync::mutex::Mutex as AsyncMutex;
use pm_core::auth::{Auth, Job, JobId, JobResult, KeyfileAction, NO_JOB, State};
use pm_core::config::{MAX_ENTRIES, SESSION_TOKEN_LEN};
use pm_core::crypto;
use pm_core::entry::{Entry, Field};
use pm_core::hex;
use pm_core::types::VaultError;
use pm_core::vault::Vault;

use crate::hw::{EspClock, EspRng, now_ms};
use crate::storage::VaultStorage;

/// The worker's auth state machine.
pub type WorkerAuth = Auth<EspRng, EspClock>;
/// The vault the worker owns.
pub type WorkerVault = Vault<VaultStorage>;

static CMD: Channel<Cs, Command, 2> = Channel::new();
static REPLY: Channel<Cs, Reply, 1> = Channel::new();
/// Serialises channel round trips so replies cannot cross streams.
static RPC: AsyncMutex<Cs, ()> = AsyncMutex::new(());

/// A command for the worker.
enum Command {
    /// Idle wake-up: runs the session-expiry tick.
    Tick,
    Provision {
        key_file: Vec<u8>,
    },
    Unlock {
        password: Vec<u8>,
        key_file: Vec<u8>,
    },
    Reset,
    Rekey {
        old_password: Vec<u8>,
        new_password: Option<Vec<u8>>,
        cur_key_file: Vec<u8>,
        new_key_file: Vec<u8>,
        action: KeyfileAction,
    },
    Lock,
    GeneratePassword,
    EntriesList,
    EntryGet {
        id: u32,
    },
    EntryWrite {
        id: u32,
        entry: Box<Entry>,
    },
    EntryRemove {
        id: u32,
    },
    ImportBatch {
        entries: Vec<Entry>,
    },
}

/// A reply to a [`Command`] that produced one.
enum Reply {
    Job(JobId),
    Lock(bool),
    Password(String),
    Entries(Result<Vec<Entry>, VaultError>),
    Entry(Result<Box<Entry>, VaultError>),
    Id(Result<u32, VaultError>),
    Removed(Result<(), VaultError>),
    Import(ImportOutcome),
}

/// Result of an import batch: how many records landed and the first error that
/// stopped it (if any). Records already added are kept — no rollback.
pub struct ImportOutcome {
    pub added: u32,
    pub error: Option<VaultError>,
}

// ── Lock-free snapshot read by the HTTP layer ────────────────────────────────

struct Shared {
    provisioned: AtomicBool,
    unlocked: AtomicBool,
    busy: AtomicBool,
    key_file_required: AtomicBool,
    fail_count: AtomicU32,
    lockout_until_ms: AtomicU32,
    entry_count: AtomicU32,
    token: BlockingMutex<Cs, RefCell<Option<[u8; SESSION_TOKEN_LEN]>>>,
    job: BlockingMutex<Cs, RefCell<JobSlot>>,
}

static SHARED: Shared = Shared {
    provisioned: AtomicBool::new(false),
    unlocked: AtomicBool::new(false),
    busy: AtomicBool::new(false),
    key_file_required: AtomicBool::new(false),
    fail_count: AtomicU32::new(0),
    lockout_until_ms: AtomicU32::new(0),
    entry_count: AtomicU32::new(0),
    token: BlockingMutex::new(RefCell::new(None)),
    job: BlockingMutex::new(RefCell::new(JobSlot::new())),
};

/// One-shot job result slot, mirroring the C++ `g_slot`.
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

fn publish(auth: &WorkerAuth, vault: &WorkerVault) {
    let s = auth.state();
    SHARED.provisioned.store(s.provisioned, Ordering::Relaxed);
    SHARED.unlocked.store(s.unlocked, Ordering::Relaxed);
    SHARED.busy.store(s.busy, Ordering::Relaxed);
    SHARED
        .fail_count
        .store(u32::from(s.fail_count), Ordering::Relaxed);
    let until = if s.lockout_ms_left == 0 {
        0
    } else {
        now_ms().wrapping_add(s.lockout_ms_left)
    };
    SHARED.lockout_until_ms.store(until, Ordering::Relaxed);
    SHARED
        .key_file_required
        .store(vault.key_file_required(), Ordering::Relaxed);
    SHARED.entry_count.store(vault.count(), Ordering::Relaxed);

    let token = auth.session_token_hex().and_then(|h| {
        let mut out = [0u8; SESSION_TOKEN_LEN];
        hex::decode_into(h.as_bytes(), &mut out).then_some(out)
    });
    SHARED.token.lock(|t| *t.borrow_mut() = token);
}

// ── Worker ───────────────────────────────────────────────────────────────────

/// The auth worker. Spawned once on the second core; runs forever.
#[embassy_executor::task]
pub async fn worker(mut auth: WorkerAuth, mut vault: WorkerVault) {
    publish(&auth, &vault);
    loop {
        auth.tick(&mut vault);
        publish(&auth, &vault);
        let cmd = CMD.receive().await;
        handle(&mut auth, &mut vault, cmd).await;
    }
}

async fn handle(auth: &mut WorkerAuth, vault: &mut WorkerVault, cmd: Command) {
    match cmd {
        Command::Tick => {}
        Command::Provision { mut key_file } => {
            let (id, req) = auth.submit_provision(&key_file);
            begin(auth, vault, id, Job::Provision).await;
            crypto::wipe(&mut key_file);
            run_and_finish(auth, vault, id, req);
        }
        Command::Unlock {
            mut password,
            mut key_file,
        } => {
            let pw = core::str::from_utf8(&password).unwrap_or("");
            let (id, req) = auth.submit_unlock(pw, &key_file);
            begin(auth, vault, id, Job::Unlock).await;
            crypto::wipe(&mut password);
            crypto::wipe(&mut key_file);
            run_and_finish(auth, vault, id, req);
        }
        Command::Reset => {
            let (id, req) = auth.submit_reset();
            begin(auth, vault, id, Job::Reset).await;
            run_and_finish(auth, vault, id, req);
        }
        Command::Rekey {
            mut old_password,
            new_password,
            mut cur_key_file,
            mut new_key_file,
            action,
        } => {
            let old = core::str::from_utf8(&old_password).unwrap_or("");
            let new = new_password
                .as_deref()
                .and_then(|b| core::str::from_utf8(b).ok());
            let (id, req) = auth.submit_rekey(old, new, &cur_key_file, &new_key_file, action);
            begin(auth, vault, id, Job::Rekey).await;
            crypto::wipe(&mut old_password);
            crypto::wipe(&mut cur_key_file);
            crypto::wipe(&mut new_key_file);
            run_and_finish(auth, vault, id, req);
        }
        Command::Lock => {
            auth.lock(vault);
            publish(auth, vault);
            let _ = REPLY.send(Reply::Lock(true)).await;
        }
        Command::GeneratePassword => {
            let pw = auth.generate_master_password();
            let _ = REPLY.send(Reply::Password(pw)).await;
        }
        Command::EntriesList => {
            let res = vault.load(MAX_ENTRIES as usize);
            let _ = REPLY.send(Reply::Entries(res)).await;
        }
        Command::EntryGet { id } => {
            let res = vault.get(id).map(Box::new);
            let _ = REPLY.send(Reply::Entry(res)).await;
        }
        Command::EntryWrite { id, mut entry } => {
            // Update merges the stored password when the request omits it, so a
            // card edit does not wipe the credential.
            let res = if id != 0 {
                match vault.get(id) {
                    Ok(old) => {
                        if entry.get(Field::Password).is_empty() {
                            entry.set(Field::Password, old.get(Field::Password));
                        }
                        vault.add(&entry)
                    }
                    Err(e) => Err(e),
                }
            } else {
                vault.add(&entry)
            };
            publish(auth, vault);
            let _ = REPLY.send(Reply::Id(res)).await;
        }
        Command::EntryRemove { id } => {
            let res = match vault.remove(id) {
                VaultError::None => Ok(()),
                e => Err(e),
            };
            publish(auth, vault);
            let _ = REPLY.send(Reply::Removed(res)).await;
        }
        Command::ImportBatch { entries } => {
            let mut added = 0u32;
            let mut error = None;
            for e in &entries {
                match vault.add(e) {
                    Ok(_) => added += 1,
                    Err(err) => {
                        error = Some(err);
                        break;
                    }
                }
            }
            publish(auth, vault);
            let _ = REPLY
                .send(Reply::Import(ImportOutcome { added, error }))
                .await;
        }
    }
}

/// Records acceptance and replies to the HTTP handler before the KDF starts.
async fn begin(auth: &mut WorkerAuth, vault: &mut WorkerVault, id: JobId, kind: Job) {
    if id != NO_JOB {
        SHARED.job.lock(|j| j.borrow_mut().begin(id, kind));
    }
    publish(auth, vault);
    let _ = REPLY.send(Reply::Job(id)).await;
}

fn run_and_finish(
    auth: &mut WorkerAuth,
    vault: &mut WorkerVault,
    id: JobId,
    req: Option<pm_core::auth::Request>,
) {
    if let Some(req) = req {
        auth.run(vault, &req);
        if let Some(view) = auth.poll(id) {
            let password = view.password.clone();
            let token = view.session_token.clone();
            SHARED.job.lock(|j| {
                j.borrow_mut()
                    .complete(view.kind, view.result, password, token)
            });
        }
    }
    publish(auth, vault);
}

async fn round_trip(cmd: Command) -> Reply {
    let _guard = RPC.lock().await;
    CMD.send(cmd).await;
    REPLY.receive().await
}

// ── Client API (called from the HTTP tasks on core 0) ────────────────────────

async fn submit(cmd: Command) -> JobId {
    // Cheap lock-free pre-check: a job is running, so nothing would be accepted.
    if SHARED.busy.load(Ordering::Relaxed) {
        return NO_JOB;
    }
    match round_trip(cmd).await {
        Reply::Job(id) => id,
        _ => NO_JOB,
    }
}

pub async fn submit_provision(key_file: Vec<u8>) -> JobId {
    submit(Command::Provision { key_file }).await
}

pub async fn submit_unlock(password: Vec<u8>, key_file: Vec<u8>) -> JobId {
    submit(Command::Unlock { password, key_file }).await
}

pub async fn submit_reset() -> JobId {
    submit(Command::Reset).await
}

pub async fn submit_rekey(
    old_password: Vec<u8>,
    new_password: Option<Vec<u8>>,
    cur_key_file: Vec<u8>,
    new_key_file: Vec<u8>,
    action: KeyfileAction,
) -> JobId {
    submit(Command::Rekey {
        old_password,
        new_password,
        cur_key_file,
        new_key_file,
        action,
    })
    .await
}

/// Closes the session (`POST /api/auth/lock`).
pub async fn lock() -> bool {
    match round_trip(Command::Lock).await {
        Reply::Lock(v) => v,
        _ => false,
    }
}

/// A fresh master-password candidate (`GET /api/auth/password`).
pub async fn generate_master_password() -> String {
    match round_trip(Command::GeneratePassword).await {
        Reply::Password(p) => p,
        _ => String::new(),
    }
}

pub async fn entries_list() -> Result<Vec<Entry>, VaultError> {
    match round_trip(Command::EntriesList).await {
        Reply::Entries(r) => r,
        _ => Err(VaultError::Io),
    }
}

pub async fn entry_get(id: u32) -> Result<Box<Entry>, VaultError> {
    match round_trip(Command::EntryGet { id }).await {
        Reply::Entry(r) => r,
        _ => Err(VaultError::Io),
    }
}

pub async fn entry_write(id: u32, entry: Entry) -> Result<u32, VaultError> {
    match round_trip(Command::EntryWrite {
        id,
        entry: Box::new(entry),
    })
    .await
    {
        Reply::Id(r) => r,
        _ => Err(VaultError::Io),
    }
}

pub async fn entry_remove(id: u32) -> Result<(), VaultError> {
    match round_trip(Command::EntryRemove { id }).await {
        Reply::Removed(r) => r,
        _ => Err(VaultError::Io),
    }
}

pub async fn import_batch(entries: Vec<Entry>) -> ImportOutcome {
    match round_trip(Command::ImportBatch { entries }).await {
        Reply::Import(o) => o,
        _ => ImportOutcome {
            added: 0,
            error: Some(VaultError::Io),
        },
    }
}

/// Wake-up used by the core-0 idle tick. Never blocks: a full channel means the
/// worker is busy and the tick is simply skipped.
pub fn tick() {
    let _ = CMD.try_send(Command::Tick);
}

/// Lock-free snapshot for `GET /api/auth/state`.
pub fn state() -> State {
    State {
        provisioned: SHARED.provisioned.load(Ordering::Relaxed),
        unlocked: SHARED.unlocked.load(Ordering::Relaxed),
        busy: SHARED.busy.load(Ordering::Relaxed),
        fail_count: SHARED.fail_count.load(Ordering::Relaxed) as u8,
        lockout_ms_left: lockout_left_ms(),
    }
}

fn lockout_left_ms() -> u32 {
    let until = SHARED.lockout_until_ms.load(Ordering::Relaxed);
    if until == 0 {
        return 0;
    }
    // Signed difference: an unsigned `until - now` would report "expired" right
    // at the `millis()` wrap.
    let left = until.wrapping_sub(now_ms()) as i32;
    if left > 0 { left as u32 } else { 0 }
}

/// Whether the open/closed vault needs a key file (drives the unlock form).
pub fn key_file_required() -> bool {
    SHARED.key_file_required.load(Ordering::Relaxed)
}

/// Live entry count, for `GET /api/auth/session`.
pub fn entry_count() -> u32 {
    SHARED.entry_count.load(Ordering::Relaxed)
}

/// Validates `X-PM-Session` in constant time. The hex is decoded from either
/// case first, so an upper- or lower-case token takes the same comparison path
/// as the reference.
pub fn session_valid(token_hex: &str) -> bool {
    let mut given = [0u8; SESSION_TOKEN_LEN];
    if !hex::decode_into(token_hex.as_bytes(), &mut given) {
        return false;
    }
    let ok = SHARED.token.lock(|t| match t.borrow().as_ref() {
        Some(expected) => crypto::ct_equal(expected, &given),
        None => false,
    });
    crypto::wipe(&mut given);
    ok
}

/// The current session token as hex, for `GET /api/auth/session`.
pub fn session_token_hex() -> Option<String> {
    SHARED.token.lock(|t| {
        let token = *t.borrow();
        token.as_ref().map(|bytes| hex::encode(bytes))
    })
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

/// Polls a job id. `None` when the id is unknown.
pub fn poll(id: JobId) -> Option<PolledJob> {
    if id == NO_JOB {
        return None;
    }
    SHARED.job.lock(|j| {
        let mut slot = j.borrow_mut();
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
    })
}
