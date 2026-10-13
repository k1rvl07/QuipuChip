//! Authorization layer, ported from the removed C++ reference.
//!
//! Provisioning, unlock, session handling and failure lockout. The module knows
//! nothing about HTTP and never touches the network itself: secrets (the
//! one-shot provisioning password and the session token) leave through
//! [`Auth::poll`] and are handed out **exactly once**.
//!
//! This is the synchronous state machine. The board runs it inside a worker
//! task; here every transition is a plain method call, which keeps the logic
//! host-testable. Randomness and time are injected so tests are deterministic.

use core::cell::Cell;

use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;

use crate::config::{
    AUTH_LOCKOUT_MS, AUTH_MAX_FAIL, KEYFILE_GENERATED_BYTES, KEYFILE_MAX_BYTES,
    MASTER_PASSWORD_CHARS, MAX_PASS_CHARS, SESSION_TOKEN_LEN, SESSION_TTL_MS,
};
use crate::crypto;
use crate::hex;
use crate::password::generate_password;
use crate::rand::RandomSource;
use crate::types::VaultError;
use crate::vault::{Storage, Vault};

/// Length of the session token as it travels on the wire: 32 bytes in hex.
pub const SESSION_TOKEN_HEX_LEN: usize = SESSION_TOKEN_LEN * 2;

/// What to ask the worker to do. Discriminants land in the log, so the
/// representation is fixed to `u8` rather than the default `isize`.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Job {
    /// Create a fresh vault and its master password.
    Provision = 0,
    /// Unlock an existing vault with a password.
    Unlock = 1,
    /// Wipe the vault and return to the unprovisioned state.
    Reset = 2,
    /// Re-encrypt the vault under a new password/key file.
    Rekey = 3,
}

impl Job {
    /// Wire/log wording of the job kind.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Job::Provision => "provision",
            Job::Unlock => "unlock",
            Job::Reset => "reset",
            Job::Rekey => "rekey",
        }
    }
}

impl core::fmt::Display for Job {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str((*self).as_str())
    }
}

/// Outcome of an operation. `Pending` and `Busy` are not errors.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobResult {
    /// Accepted but not finished yet.
    Pending = 0,
    /// Finished successfully.
    Ok = 1,
    /// The supplied password was rejected.
    WrongPassword = 2,
    /// Refused because the vault is in the wrong state for this job.
    Refused = 3,
    /// Refused because of the failure lockout.
    Lockout = 4,
    /// Rejected because another job is in flight.
    Busy = 5,
    /// Failed for an internal reason.
    Error = 6,
}

impl JobResult {
    /// Wire/log wording of the outcome.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            JobResult::Pending => "pending",
            JobResult::Ok => "ok",
            JobResult::WrongPassword => "wrong_password",
            JobResult::Refused => "refused",
            JobResult::Lockout => "lockout",
            JobResult::Busy => "busy",
            JobResult::Error => "error",
        }
    }
}

impl core::fmt::Display for JobResult {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str((*self).as_str())
    }
}

/// Fate of the key file during a rekey.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyfileAction {
    /// Keep the existing key file.
    Keep = 0,
    /// Replace the key file with a new one.
    Set = 1,
    /// Remove the key file.
    Clear = 2,
    /// Replace the key file with one generated on the device.
    Generate = 3,
}

impl core::fmt::Display for KeyfileAction {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            KeyfileAction::Keep => "keep",
            KeyfileAction::Set => "set",
            KeyfileAction::Clear => "clear",
            KeyfileAction::Generate => "generate",
        })
    }
}

/// A queued request. Owns its secrets; dropping it wipes them.
///
/// Opaque outside the crate: callers only ever receive it from a `submit*`
/// method and hand it back to [`Auth::run`].
pub struct Request {
    kind: Job,
    id: JobId,
    password: Vec<u8>,
    old_password: Vec<u8>,
    key_file: Vec<u8>,
    key_file_new: Vec<u8>,
    keyfile_action: KeyfileAction,
    has_new_password: bool,
    generate_keyfile: bool,
}

impl Request {
    fn new(kind: Job) -> Self {
        Self {
            kind,
            id: NO_JOB,
            password: Vec::new(),
            old_password: Vec::new(),
            key_file: Vec::new(),
            key_file_new: Vec::new(),
            keyfile_action: KeyfileAction::Keep,
            has_new_password: false,
            generate_keyfile: false,
        }
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        crypto::wipe(&mut self.password);
        crypto::wipe(&mut self.old_password);
        crypto::wipe(&mut self.key_file);
        crypto::wipe(&mut self.key_file_new);
    }
}

/// Snapshot for `GET /api/auth/state`. Cheap: reads cached fields only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct State {
    /// Whether a vault has been provisioned.
    pub provisioned: bool,
    /// Whether the vault is currently unlocked.
    pub unlocked: bool,
    /// Whether a job is in flight.
    pub busy: bool,
    /// Consecutive failed unlock attempts.
    pub fail_count: u8,
    /// Remaining lockout time in milliseconds.
    pub lockout_ms_left: u32,
}

/// Result of a job handed to `poll()`.
pub struct JobView {
    /// Which operation finished.
    pub kind: Job,
    /// Its outcome.
    pub result: JobResult,
    /// One-shot provisioning password, if any.
    pub password: Vec<u8>,
    /// One-shot session token (hex ASCII), if any.
    pub session_token: Vec<u8>,
    /// One-shot device-generated key file, if any.
    pub key_file: Vec<u8>,
}

impl Drop for JobView {
    fn drop(&mut self) {
        crypto::wipe(&mut self.password);
        crypto::wipe(&mut self.session_token);
        crypto::wipe(&mut self.key_file);
    }
}

/// Identifier of a job. `0` is reserved for "not accepted".
///
/// Random 64 bits, not a counter: the id is the only secret guarding
/// `/api/auth/job/{id}` until a session exists, and that route hands out the
/// one-shot provisioning password.
pub type JobId = u64;
/// Sentinel id meaning "no job accepted".
pub const NO_JOB: JobId = 0;

/// Time source. Injected so tests can move the clock (and cross the 49.7-day
/// `millis()` wrap).
pub trait Clock {
    /// Milliseconds since boot, wrapping every 49.7 days.
    fn now_ms(&self) -> u32;
}

/// Test clock: clones share one counter.
#[derive(Clone)]
pub struct ManualClock(Rc<Cell<u32>>);

impl ManualClock {
    /// Creates a clock reading `now_ms`.
    pub fn new(now_ms: u32) -> Self {
        Self(Rc::new(Cell::new(now_ms)))
    }
    /// Sets the clock to `now_ms`.
    pub fn set(&self, now_ms: u32) {
        self.0.set(now_ms);
    }
    /// Advances the clock by `delta_ms` (wrapping).
    pub fn advance(&self, delta_ms: u32) {
        self.0.set(self.0.get().wrapping_add(delta_ms));
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> u32 {
        self.0.get()
    }
}

struct Slot {
    id: JobId,
    kind: Job,
    result: JobResult,
    /// One-shot provisioning password, wiped on first poll / next submit.
    password: Vec<u8>,
    /// One-shot session token (hex ASCII).
    session_token: Vec<u8>,
    /// One-shot device-generated key file, wiped on first poll / next submit.
    key_file: Vec<u8>,
}

impl Slot {
    fn new() -> Self {
        Self {
            id: NO_JOB,
            kind: Job::Provision,
            result: JobResult::Pending,
            password: Vec::new(),
            session_token: Vec::new(),
            key_file: Vec::new(),
        }
    }
    fn wipe_secrets(&mut self) {
        wipe_vec(&mut self.password);
        wipe_vec(&mut self.session_token);
        wipe_vec(&mut self.key_file);
    }
}

/// The authorization state machine.
pub struct Auth<R: RandomSource, C: Clock> {
    rng: R,
    clock: C,
    provisioned: bool,
    unlocked: bool,
    busy: bool,
    fail_count: u8,
    lockout_until_ms: u32,
    unlocked_at_ms: u32,
    token: [u8; SESSION_TOKEN_LEN],
    slot: Slot,
}

/// Result of a submit: the id (0 = rejected) plus the request to enqueue.
pub type Submit = (JobId, Option<Request>);

impl<R: RandomSource, C: Clock> Auth<R, C> {
    /// Creates the state machine with the given randomness and clock sources.
    pub fn new(rng: R, clock: C) -> Self {
        Self {
            rng,
            clock,
            provisioned: false,
            unlocked: false,
            busy: false,
            fail_count: 0,
            lockout_until_ms: 0,
            unlocked_at_ms: 0,
            token: [0; SESSION_TOKEN_LEN],
            slot: Slot::new(),
        }
    }

    /// Reads the provisioned flag from flash. Call once from `setup()` before
    /// the worker and HTTP server start.
    pub fn initialize<S: Storage>(&mut self, vault: &Vault<S>) {
        self.provisioned = vault.provisioned();
        self.unlocked = false;
        self.busy = false;
        self.fail_count = 0;
        self.lockout_until_ms = 0;
        self.unlocked_at_ms = 0;
        crypto::wipe(&mut self.token);
        self.slot = Slot::new();
    }

    // ── Submit ───────────────────────────────────────────────────────────────

    /// Orders provisioning. Refused up-front when the vault is already
    /// provisioned: provisioning wipes the whole partition.
    ///
    /// `generate_keyfile` asks the device to mint a key file. It conflicts with
    /// a client-supplied `key_file`: one source only.
    pub fn submit_provision(&mut self, key_file: &[u8], generate_keyfile: bool) -> Submit {
        if self.provisioned
            || key_file.len() > KEYFILE_MAX_BYTES
            || (generate_keyfile && !key_file.is_empty())
        {
            return (NO_JOB, None);
        }
        let mut req = Request::new(Job::Provision);
        req.key_file.extend_from_slice(key_file);
        req.generate_keyfile = generate_keyfile;
        self.enqueue(req)
    }

    /// Orders an unlock. Refused when a lockout is in effect or when there is
    /// no vault to unlock: running the KDF against an empty partition would
    /// waste seconds and then fail with a meaningless error.
    pub fn submit_unlock(&mut self, password: &str, key_file: &[u8]) -> Submit {
        if !self.provisioned {
            return (NO_JOB, None);
        }
        if self.lockout_left_ms() > 0 {
            return (NO_JOB, None);
        }
        let n = password.len();
        if n == 0 || n >= MAX_PASS_CHARS || key_file.len() > KEYFILE_MAX_BYTES {
            return (NO_JOB, None);
        }
        let mut req = Request::new(Job::Unlock);
        req.password.extend_from_slice(password.as_bytes());
        req.key_file.extend_from_slice(key_file);
        self.enqueue(req)
    }

    /// Orders a full wipe. No password is needed and none is accepted.
    ///
    /// The provisioned check is deliberately *not* done here: it is what lets
    /// the HTTP layer tell "busy, retry" (503) from "nothing to destroy" (409).
    /// The worker reports `Refused` for an unprovisioned vault.
    pub fn submit_reset(&mut self) -> Submit {
        self.enqueue(Request::new(Job::Reset))
    }

    /// Orders a master-password and/or key-file change. Only valid on an open
    /// vault; the old password is the object of verification in the worker.
    pub fn submit_rekey(
        &mut self,
        old_password: &str,
        new_password: Option<&str>,
        cur_key_file: &[u8],
        new_key_file: &[u8],
        action: KeyfileAction,
    ) -> Submit {
        if old_password.is_empty() || old_password.len() >= MAX_PASS_CHARS {
            return (NO_JOB, None);
        }
        if cur_key_file.len() > KEYFILE_MAX_BYTES || new_key_file.len() > KEYFILE_MAX_BYTES {
            return (NO_JOB, None);
        }
        if matches!(action, KeyfileAction::Set) && new_key_file.is_empty() {
            return (NO_JOB, None);
        }
        if matches!(action, KeyfileAction::Generate | KeyfileAction::Clear)
            && !new_key_file.is_empty()
        {
            return (NO_JOB, None);
        }
        // A Keep with no new password would only re-encrypt under the same
        // material; refuse it so a caller cannot submit an empty change.
        if matches!(action, KeyfileAction::Keep) && new_password.map_or(true, str::is_empty) {
            return (NO_JOB, None);
        }

        let mut req = Request::new(Job::Rekey);
        req.keyfile_action = action;
        req.old_password.extend_from_slice(old_password.as_bytes());
        if let Some(np) = new_password
            && !np.is_empty()
        {
            if np.len() >= MAX_PASS_CHARS {
                return (NO_JOB, None);
            }
            req.password.extend_from_slice(np.as_bytes());
            req.has_new_password = true;
        }
        req.key_file.extend_from_slice(cur_key_file);
        req.key_file_new.extend_from_slice(new_key_file);
        self.enqueue(req)
    }

    /// Common submit tail: slot bookkeeping, id, busy, then hand back the
    /// request for the caller to enqueue onto the worker.
    fn enqueue(&mut self, mut req: Request) -> Submit {
        if self.busy {
            return (NO_JOB, None);
        }
        // Secrets of the previous job go before the slot is overwritten: an
        // uncollected provisioning password may still be sitting there.
        self.slot.wipe_secrets();

        let mut id_bytes = [0u8; 8];
        self.rng.fill(&mut id_bytes);
        let mut id = JobId::from_le_bytes(id_bytes);
        if id == NO_JOB {
            id = 1;
        }
        self.slot.id = id;
        self.slot.kind = req.kind;
        self.slot.result = JobResult::Pending;
        self.busy = true;
        req.id = id;
        (id, Some(req))
    }

    // ── Run (worker side) ────────────────────────────────────────────────────

    /// Executes a request. Runs on the worker only.
    pub fn run<S: Storage>(&mut self, vault: &mut Vault<S>, req: &Request) {
        match req.kind {
            Job::Provision => self.run_provision(vault, req),
            Job::Unlock => self.run_unlock(vault, req),
            Job::Reset => self.run_reset(vault, req),
            Job::Rekey => self.run_rekey(vault, req),
        }
    }

    #[allow(
        clippy::expect_used,
        reason = "generated password is ASCII by construction"
    )]
    fn run_provision<S: Storage>(&mut self, vault: &mut Vault<S>, req: &Request) {
        // Re-checked here, not only in submit: another job's result may have
        // appeared in between, and wiping a provisioned vault is data loss.
        if vault.provisioned() {
            self.publish_result(req.id, Job::Provision, JobResult::Refused);
            return;
        }

        let mut pw = generate_password(&mut self.rng);
        debug_assert_eq!(pw.len(), MASTER_PASSWORD_CHARS);
        // A device-generated key file lives on the stack only until it is
        // copied into the slot, and is wiped unconditionally afterwards.
        let mut gen_kf = [0u8; KEYFILE_GENERATED_BYTES];
        let kf = if req.generate_keyfile {
            self.rng.fill(&mut gen_kf);
            Some(gen_kf.as_slice())
        } else {
            keyfile_opt(&req.key_file)
        };
        let pw_str = core::str::from_utf8(&pw).expect("password is ASCII");
        let rc = vault.begin(pw_str, kf, &mut self.rng);
        if rc != VaultError::None {
            crypto::wipe(&mut pw);
            crypto::wipe(&mut gen_kf);
            self.publish_result(req.id, Job::Provision, JobResult::Error);
            return;
        }

        self.refresh_token();
        self.provisioned = true;
        self.unlocked = true;
        self.unlocked_at_ms = self.clock.now_ms();
        self.fail_count = 0;
        self.lockout_until_ms = 0;

        // Password, token and a generated key file are placed in the slot
        // *before* publish_result() clears busy, so the next submit cannot wipe
        // an uncollected secret.
        self.slot.password.extend_from_slice(&pw);
        self.slot
            .session_token
            .extend_from_slice(hex::encode(&self.token).as_bytes());
        if req.generate_keyfile {
            self.slot.key_file.extend_from_slice(&gen_kf);
        }
        crypto::wipe(&mut pw);
        crypto::wipe(&mut gen_kf);

        self.publish_result(req.id, Job::Provision, JobResult::Ok);
    }

    fn run_unlock<S: Storage>(&mut self, vault: &mut Vault<S>, req: &Request) {
        if self.lockout_left_ms() > 0 {
            self.publish_result(req.id, Job::Unlock, JobResult::Lockout);
            return;
        }
        // Re-checked here, not only in submit: a reset may have wiped the
        // vault between submit and run, and a fresh provision would be a
        // different vault with a different key.
        if !vault.provisioned() {
            self.publish_result(req.id, Job::Unlock, JobResult::Refused);
            return;
        }

        let pw_str = core::str::from_utf8(&req.password).unwrap_or("");
        let kf = keyfile_opt(&req.key_file);
        let rc = vault.begin(pw_str, kf, &mut self.rng);
        if rc == VaultError::None {
            self.fail_count = 0;
            self.lockout_until_ms = 0;
            self.unlocked = true;
            self.unlocked_at_ms = self.clock.now_ms();
            self.refresh_token();
            self.slot
                .session_token
                .extend_from_slice(hex::encode(&self.token).as_bytes());
            self.publish_result(req.id, Job::Unlock, JobResult::Ok);
            return;
        }

        // Storage errors (Tampered, Io, Crypto) do not count as failures: that
        // is not the user's fault, and locking them out over a flash fault
        // would be wrong.
        if rc == VaultError::WrongPassword {
            let fails = self.fail_count.saturating_add(1);
            let mut until = 0u32;
            if fails >= AUTH_MAX_FAIL {
                until = self.clock.now_ms().wrapping_add(AUTH_LOCKOUT_MS);
            }
            self.fail_count = fails;
            self.lockout_until_ms = until;
            self.publish_result(req.id, Job::Unlock, JobResult::WrongPassword);
            return;
        }

        self.publish_result(req.id, Job::Unlock, JobResult::Error);
    }

    fn run_reset<S: Storage>(&mut self, vault: &mut Vault<S>, req: &Request) {
        if !vault.provisioned() {
            self.publish_result(req.id, Job::Reset, JobResult::Refused);
            return;
        }
        if vault.reset() != VaultError::None {
            self.publish_result(req.id, Job::Reset, JobResult::Error);
            return;
        }

        self.close_session(vault);
        self.provisioned = false;
        self.unlocked = false;
        self.unlocked_at_ms = 0;
        self.fail_count = 0;
        self.lockout_until_ms = 0;
        // Secrets from the previous job are wiped here, before the next poll.
        self.slot.wipe_secrets();
        self.publish_result(req.id, Job::Reset, JobResult::Ok);
    }

    fn run_rekey<S: Storage>(&mut self, vault: &mut Vault<S>, req: &Request) {
        if !vault.initialized() {
            self.publish_result(req.id, Job::Rekey, JobResult::Refused);
            return;
        }

        // The old password + current key file are verified with the real KDF.
        // begin() closes the vault on a bad pair, so the session must close too.
        let old_str = core::str::from_utf8(&req.old_password).unwrap_or("");
        let cur = keyfile_opt(&req.key_file);
        let vb = vault.begin(old_str, cur, &mut self.rng);
        if vb != VaultError::None {
            let res = if vb == VaultError::WrongPassword {
                JobResult::WrongPassword
            } else {
                JobResult::Error
            };
            self.publish_result(req.id, Job::Rekey, res);
            self.close_session(vault);
            return;
        }

        let new_str = if req.has_new_password {
            core::str::from_utf8(&req.password).unwrap_or(old_str)
        } else {
            old_str
        };
        let mut gen_kf = [0u8; KEYFILE_GENERATED_BYTES];
        let target = match req.keyfile_action {
            KeyfileAction::Set => keyfile_opt(&req.key_file_new),
            KeyfileAction::Keep => keyfile_opt(&req.key_file),
            KeyfileAction::Clear => None,
            KeyfileAction::Generate => {
                self.rng.fill(&mut gen_kf);
                Some(gen_kf.as_slice())
            }
        };
        let rc = vault.rekey(new_str, target, &mut self.rng);
        let generated = req.keyfile_action == KeyfileAction::Generate;
        match rc {
            VaultError::None => {
                // The new key file is placed in the slot before publish_result()
                // clears busy, so the next submit cannot wipe it uncollected.
                if generated {
                    self.slot.key_file.extend_from_slice(&gen_kf);
                }
                crypto::wipe(&mut gen_kf);
                self.publish_result(req.id, Job::Rekey, JobResult::Ok);
            }
            VaultError::BootStrap => {
                crypto::wipe(&mut gen_kf);
                self.publish_result(req.id, Job::Rekey, JobResult::Refused);
            }
            _ => {
                crypto::wipe(&mut gen_kf);
                self.publish_result(req.id, Job::Rekey, JobResult::Error);
            }
        }
    }

    fn publish_result(&mut self, id: JobId, kind: Job, result: JobResult) {
        self.slot.id = id;
        self.slot.kind = kind;
        self.slot.result = result;
        self.busy = false;
    }

    // ── Poll / state ─────────────────────────────────────────────────────────

    /// Polls a job. `None` when the id is unknown. After a completed job the
    /// slot is reused, so callers must check `kind`.
    pub fn poll(&mut self, job_id: JobId) -> Option<JobView> {
        if job_id == NO_JOB || self.slot.id != job_id {
            return None;
        }
        let ok = self.slot.result == JobResult::Ok;
        let password = if ok && !self.slot.password.is_empty() {
            let p = self.slot.password.clone();
            wipe_vec(&mut self.slot.password);
            p
        } else {
            Vec::new()
        };
        let session_token = if ok && !self.slot.session_token.is_empty() {
            let t = self.slot.session_token.clone();
            wipe_vec(&mut self.slot.session_token);
            t
        } else {
            Vec::new()
        };
        let key_file = if ok && !self.slot.key_file.is_empty() {
            let k = self.slot.key_file.clone();
            wipe_vec(&mut self.slot.key_file);
            k
        } else {
            Vec::new()
        };
        Some(JobView {
            kind: self.slot.kind,
            result: self.slot.result,
            password,
            session_token,
            key_file,
        })
    }

    #[must_use]
    /// Cached snapshot for `GET /api/auth/state`.
    pub fn state(&self) -> State {
        State {
            provisioned: self.provisioned,
            unlocked: self.unlocked,
            busy: self.busy,
            fail_count: self.fail_count,
            lockout_ms_left: self.lockout_left_ms(),
        }
    }

    /// Remaining lockout time. Signed difference: an unsigned `until > now`
    /// would report "expired" right at the `millis()` wrap.
    fn lockout_left_ms(&self) -> u32 {
        if self.lockout_until_ms == 0 {
            return 0;
        }
        let left = self.lockout_until_ms.wrapping_sub(self.clock.now_ms()) as i32;
        if left > 0 { left as u32 } else { 0 }
    }

    // ── Session ──────────────────────────────────────────────────────────────

    /// Closes the session on explicit request. The flash vault is untouched.
    pub fn lock<S: Storage>(&mut self, vault: &mut Vault<S>) {
        self.slot.wipe_secrets();
        self.close_session(vault);
    }

    fn close_session<S: Storage>(&mut self, vault: &mut Vault<S>) {
        crypto::wipe(&mut self.token);
        self.unlocked = false;
        self.unlocked_at_ms = 0;
        vault.close();
    }

    fn refresh_token(&mut self) {
        crypto::wipe(&mut self.token);
        self.rng.fill(&mut self.token);
    }

    fn token_all_zero(&self) -> bool {
        self.token.iter().fold(0u8, |a, &b| a | b) == 0
    }

    /// Copies the current token as 64 hex chars. `None` when there is no
    /// session or the token has been wiped.
    pub fn session_token_hex(&self) -> Option<String> {
        if !self.unlocked || self.token_all_zero() {
            return None;
        }
        Some(hex::encode(&self.token))
    }

    /// Validates `X-PM-Session`. Constant-time compare: an early exit would
    /// leak the length of a matching prefix.
    #[must_use]
    pub fn session_valid(&self, token_hex: &str) -> bool {
        if token_hex.len() != SESSION_TOKEN_HEX_LEN || !self.unlocked || self.token_all_zero() {
            return false;
        }
        let bytes = token_hex.as_bytes();
        let mut given = [0u8; SESSION_TOKEN_LEN];
        if !hex::decode_into(bytes, &mut given) {
            return false;
        }
        let ok = crypto::ct_equal(&self.token, &given);
        crypto::wipe(&mut given);
        ok
    }

    /// Closes the session after `ttl_ms` of idleness. The worker calls this
    /// with [`SESSION_TTL_MS`] on every loop.
    pub fn expire_idle_session<S: Storage>(&mut self, vault: &mut Vault<S>, ttl_ms: u32) {
        let opened = self.unlocked_at_ms;
        if opened != 0 && self.clock.now_ms().wrapping_sub(opened) >= ttl_ms {
            self.close_session(vault);
        }
    }

    /// Convenience for the worker loop: idle check against the configured TTL.
    pub fn tick<S: Storage>(&mut self, vault: &mut Vault<S>) {
        self.expire_idle_session(vault, SESSION_TTL_MS);
    }

    /// Clears the failure lockout. For selftest; otherwise it expires on its own.
    pub fn clear_lockout(&mut self) {
        self.fail_count = 0;
        self.lockout_until_ms = 0;
    }

    /// Generates a master password. Public because its format is a user-facing
    /// contract that selftest validates independently of provisioning.
    #[must_use]
    #[allow(clippy::expect_used, reason = "generator emits ASCII by construction")]
    pub fn generate_master_password(&mut self) -> String {
        let bytes = generate_password(&mut self.rng);
        String::from_utf8(bytes.to_vec()).expect("password is ASCII by construction")
    }

    /// Generates a key file: `KEYFILE_GENERATED_BYTES` raw random bytes. Public
    /// because its size is a user-facing contract that selftest validates.
    #[must_use]
    pub fn generate_keyfile(&mut self) -> [u8; KEYFILE_GENERATED_BYTES] {
        let mut kf = [0u8; KEYFILE_GENERATED_BYTES];
        self.rng.fill(&mut kf);
        kf
    }
}

/// Wipes then truncates a secret buffer so "non-empty" means "still set".
fn wipe_vec(v: &mut Vec<u8>) {
    crypto::wipe(v);
    v.clear();
}

fn keyfile_opt(key_file: &[u8]) -> Option<&[u8]> {
    if key_file.is_empty() {
        None
    } else {
        Some(key_file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rand::CycleSource;
    use crate::testutil::{MemStorage, vault};

    const SALT_BYTES: &[u8] = b"deterministic-salt-material-0123456789";
    const PW: &str = "correct horse battery staple";
    const PW2: &str = "another correct battery staple";

    fn auth(clock: ManualClock) -> Auth<CycleSource<'static>, ManualClock> {
        Auth::new(CycleSource::new(SALT_BYTES), clock)
    }

    /// Provisions through the full submit/run/poll cycle and returns the
    /// generated master password.
    fn provision(
        a: &mut Auth<CycleSource<'static>, ManualClock>,
        v: &mut Vault<MemStorage>,
    ) -> String {
        let (id, req) = a.submit_provision(&[], false);
        assert_ne!(id, NO_JOB);
        a.run(v, req.as_ref().unwrap());
        let view = a.poll(id).unwrap();
        assert_eq!(view.result, JobResult::Ok);
        let pw = String::from_utf8(view.password.clone()).unwrap();
        assert_eq!(pw.len(), MASTER_PASSWORD_CHARS);
        assert_eq!(view.session_token.len(), SESSION_TOKEN_HEX_LEN);
        pw
    }

    #[test]
    fn provision_then_lock_then_unlock() {
        let clock = ManualClock::new(1_000);
        let mut a = auth(clock.clone());
        let mut v = vault();
        a.initialize(&v);

        let pw = provision(&mut a, &mut v);
        assert!(v.provisioned());
        let st = a.state();
        assert!(st.provisioned && st.unlocked && !st.busy);
        assert!(a.session_token_hex().is_some());

        a.lock(&mut v);
        let st = a.state();
        assert!(st.provisioned && !st.unlocked);
        assert!(a.session_token_hex().is_none());

        let (id, req) = a.submit_unlock(&pw, &[]);
        assert_ne!(id, NO_JOB);
        a.run(&mut v, req.as_ref().unwrap());
        let view = a.poll(id).unwrap();
        assert_eq!(view.result, JobResult::Ok);
        assert!(view.password.is_empty());
        assert_eq!(view.session_token.len(), SESSION_TOKEN_HEX_LEN);
        assert!(a.state().unlocked);
    }

    #[test]
    fn wrong_password_keeps_locked_and_counts() {
        let clock = ManualClock::new(1_000);
        let mut a = auth(clock.clone());
        let mut v = vault();
        a.initialize(&v);
        let _pw = provision(&mut a, &mut v);
        a.lock(&mut v);

        for expected in 1..AUTH_MAX_FAIL {
            let (id, req) = a.submit_unlock("definitely the wrong password", &[]);
            assert_ne!(id, NO_JOB);
            a.run(&mut v, req.as_ref().unwrap());
            assert_eq!(a.poll(id).unwrap().result, JobResult::WrongPassword);
            let st = a.state();
            assert_eq!(st.fail_count, expected);
            assert!(!st.unlocked);
            assert_eq!(st.lockout_ms_left, 0);
            assert!(v.provisioned());
        }

        // Fifth failure triggers the lockout.
        let (id, req) = a.submit_unlock("definitely the wrong password", &[]);
        a.run(&mut v, req.as_ref().unwrap());
        assert_eq!(a.poll(id).unwrap().result, JobResult::WrongPassword);
        let st = a.state();
        assert_eq!(st.fail_count, AUTH_MAX_FAIL);
        assert!(st.lockout_ms_left > 0 && st.lockout_ms_left <= AUTH_LOCKOUT_MS);

        // While locked out, submit is refused up-front.
        let (id, _req) = a.submit_unlock("definitely the wrong password", &[]);
        assert_eq!(id, NO_JOB);
    }

    #[test]
    fn secrets_are_handed_out_exactly_once() {
        let clock = ManualClock::new(0);
        let mut a = auth(clock);
        let mut v = vault();
        a.initialize(&v);

        let (id, req) = a.submit_provision(&[], false);
        a.run(&mut v, req.as_ref().unwrap());

        let first = a.poll(id).unwrap();
        assert_eq!(first.result, JobResult::Ok);
        assert!(!first.password.is_empty());
        assert!(!first.session_token.is_empty());
        assert!(first.key_file.is_empty());

        let second = a.poll(id).unwrap();
        assert_eq!(second.result, JobResult::Ok);
        assert!(second.password.is_empty());
        assert!(second.session_token.is_empty());
        assert!(second.key_file.is_empty());
    }

    #[test]
    fn provision_refused_when_already_provisioned() {
        let clock = ManualClock::new(0);
        let mut a = auth(clock);
        let mut v = vault();
        a.initialize(&v);
        let _pw = provision(&mut a, &mut v);
        assert!(a.state().provisioned);

        let (id, _req) = a.submit_provision(&[], false);
        assert_eq!(id, NO_JOB);
    }

    #[test]
    fn reset_on_empty_vault_is_refused_by_worker() {
        let clock = ManualClock::new(0);
        let mut a = auth(clock);
        let mut v = vault();
        a.initialize(&v);

        let (id, req) = a.submit_reset();
        assert_ne!(id, NO_JOB, "reset submit must be accepted so HTTP sees 409");
        a.run(&mut v, req.as_ref().unwrap());
        assert_eq!(a.poll(id).unwrap().result, JobResult::Refused);
    }

    #[test]
    fn reset_destroys_vault_and_locks_session() {
        let clock = ManualClock::new(0);
        let mut a = auth(clock);
        let mut v = vault();
        a.initialize(&v);
        let _pw = provision(&mut a, &mut v);
        assert!(v.provisioned());

        let (id, req) = a.submit_reset();
        a.run(&mut v, req.as_ref().unwrap());
        assert_eq!(a.poll(id).unwrap().result, JobResult::Ok);
        assert!(!v.provisioned());
        let st = a.state();
        assert!(!st.provisioned && !st.unlocked);
        assert!(a.session_token_hex().is_none());
    }

    #[test]
    fn unlock_refused_when_unprovisioned() {
        let clock = ManualClock::new(0);
        let mut a = auth(clock);
        let v = vault();
        a.initialize(&v);

        let (id, _req) = a.submit_unlock("any password", &[]);
        assert_eq!(
            id, NO_JOB,
            "unlock on an empty vault must be refused up-front"
        );
    }

    #[test]
    fn unlock_refused_when_vault_reset_underneath() {
        let clock = ManualClock::new(0);
        let mut a = auth(clock);
        let mut v = vault();
        a.initialize(&v);
        let pw = provision(&mut a, &mut v);

        let (id, req) = a.submit_unlock(&pw, &[]);
        assert_ne!(id, NO_JOB);

        // The vault becomes unprovisioned between submit and run (e.g. a
        // concurrent reset): the worker must refuse, not run a KDF.
        assert_eq!(v.reset(), VaultError::None);
        a.run(&mut v, req.as_ref().unwrap());
        assert_eq!(a.poll(id).unwrap().result, JobResult::Refused);
    }

    #[test]
    fn rekey_changes_password() {
        let clock = ManualClock::new(0);
        let mut a = auth(clock);
        let mut v = vault();
        a.initialize(&v);
        let old = provision(&mut a, &mut v);

        let (id, req) = a.submit_rekey(&old, Some(PW2), &[], &[], KeyfileAction::Keep);
        assert_ne!(id, NO_JOB);
        a.run(&mut v, req.as_ref().unwrap());
        assert_eq!(a.poll(id).unwrap().result, JobResult::Ok);
        // Session survives a rekey.
        assert!(a.state().unlocked);

        a.lock(&mut v);
        let (id, req) = a.submit_unlock(&old, &[]);
        a.run(&mut v, req.as_ref().unwrap());
        assert_eq!(a.poll(id).unwrap().result, JobResult::WrongPassword);

        let (id, req) = a.submit_unlock(PW2, &[]);
        a.run(&mut v, req.as_ref().unwrap());
        assert_eq!(a.poll(id).unwrap().result, JobResult::Ok);
    }

    #[test]
    fn rekey_wrong_old_password_closes_session() {
        let clock = ManualClock::new(0);
        let mut a = auth(clock);
        let mut v = vault();
        a.initialize(&v);
        let _pw = provision(&mut a, &mut v);

        let (id, req) = a.submit_rekey(
            "definitely the wrong password",
            Some(PW2),
            &[],
            &[],
            KeyfileAction::Keep,
        );
        assert_ne!(id, NO_JOB);
        a.run(&mut v, req.as_ref().unwrap());
        assert_eq!(a.poll(id).unwrap().result, JobResult::WrongPassword);
        assert!(!a.state().unlocked);
        assert!(!v.initialized());
    }

    #[test]
    fn rekey_refused_when_vault_closed() {
        let clock = ManualClock::new(0);
        let mut a = auth(clock);
        let mut v = vault();
        a.initialize(&v);
        let pw = provision(&mut a, &mut v);
        a.lock(&mut v);

        let (id, req) = a.submit_rekey(&pw, Some(PW2), &[], &[], KeyfileAction::Keep);
        assert_ne!(id, NO_JOB);
        a.run(&mut v, req.as_ref().unwrap());
        assert_eq!(a.poll(id).unwrap().result, JobResult::Refused);
    }

    #[test]
    fn rekey_requires_new_keyfile_for_set() {
        let clock = ManualClock::new(0);
        let mut a = auth(clock);
        assert_eq!(
            a.submit_rekey(PW, Some(PW2), &[], &[], KeyfileAction::Set)
                .0,
            NO_JOB
        );
    }

    #[test]
    fn rekey_clear_targets_new_keyfile_not_current() {
        // The current key file authenticates the vault, so Clear must accept
        // it; it is a stray *new* file that Clear rejects.
        let clock = ManualClock::new(0);
        let mut a = auth(clock);
        assert_ne!(
            a.submit_rekey(PW, None, b"cur", &[], KeyfileAction::Clear)
                .0,
            NO_JOB
        );

        let clock = ManualClock::new(0);
        let mut a = auth(clock);
        assert_eq!(
            a.submit_rekey(PW, None, b"cur", b"stray", KeyfileAction::Clear)
                .0,
            NO_JOB
        );
    }

    #[test]
    fn rekey_rejects_empty_change() {
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
    }

    #[test]
    fn rekey_keyfile_only_set_keeps_password() {
        let clock = ManualClock::new(0);
        let mut a = auth(clock);
        let mut v = vault();
        a.initialize(&v);
        let pw = provision(&mut a, &mut v);

        let new_kf = b"client supplied keyfile material";
        let (id, req) = a.submit_rekey(&pw, None, &[], new_kf, KeyfileAction::Set);
        assert_ne!(id, NO_JOB);
        a.run(&mut v, req.as_ref().unwrap());
        assert_eq!(a.poll(id).unwrap().result, JobResult::Ok);
        assert!(v.key_file_required());
        assert!(a.state().unlocked);

        // The password is unchanged: it opens only together with the new file.
        a.lock(&mut v);
        let (id, req) = a.submit_unlock(&pw, &[]);
        a.run(&mut v, req.as_ref().unwrap());
        assert_eq!(a.poll(id).unwrap().result, JobResult::WrongPassword);

        let (id, req) = a.submit_unlock(&pw, new_kf);
        a.run(&mut v, req.as_ref().unwrap());
        assert_eq!(a.poll(id).unwrap().result, JobResult::Ok);
    }

    #[test]
    fn rekey_clear_removes_keyfile() {
        let clock = ManualClock::new(0);
        let mut a = auth(clock);
        let mut v = vault();
        a.initialize(&v);
        // Start from a key-file-protected vault.
        let (id, req) = a.submit_provision(&[], true);
        assert_ne!(id, NO_JOB);
        a.run(&mut v, req.as_ref().unwrap());
        let view = a.poll(id).unwrap();
        assert_eq!(view.result, JobResult::Ok);
        let pw = String::from_utf8(view.password.clone()).unwrap();
        let kf = view.key_file.clone();
        assert!(v.key_file_required());

        // The password is kept; only the key file is removed.
        let (id, req) = a.submit_rekey(&pw, None, &kf, &[], KeyfileAction::Clear);
        assert_ne!(id, NO_JOB);
        a.run(&mut v, req.as_ref().unwrap());
        assert_eq!(a.poll(id).unwrap().result, JobResult::Ok);
        assert!(!v.key_file_required());

        a.lock(&mut v);
        let (id, req) = a.submit_unlock(&pw, &[]);
        a.run(&mut v, req.as_ref().unwrap());
        assert_eq!(a.poll(id).unwrap().result, JobResult::Ok);
    }

    #[test]
    fn provision_generates_keyfile_and_requires_it() {
        let clock = ManualClock::new(0);
        let mut a = auth(clock);
        let mut v = vault();
        a.initialize(&v);

        let (id, req) = a.submit_provision(&[], true);
        assert_ne!(id, NO_JOB);
        a.run(&mut v, req.as_ref().unwrap());
        let view = a.poll(id).unwrap();
        assert_eq!(view.result, JobResult::Ok);
        let pw = String::from_utf8(view.password.clone()).unwrap();
        assert_eq!(view.key_file.len(), KEYFILE_GENERATED_BYTES);
        assert!(v.key_file_required());
        let kf = view.key_file.clone();

        // Without the file the password alone is not enough; with it, it opens.
        a.lock(&mut v);
        let (id, req) = a.submit_unlock(&pw, &[]);
        a.run(&mut v, req.as_ref().unwrap());
        assert_eq!(a.poll(id).unwrap().result, JobResult::WrongPassword);

        let (id, req) = a.submit_unlock(&pw, &kf);
        a.run(&mut v, req.as_ref().unwrap());
        assert_eq!(a.poll(id).unwrap().result, JobResult::Ok);
    }

    #[test]
    fn provision_generate_conflicts_with_supplied_keyfile() {
        let clock = ManualClock::new(0);
        let mut a = auth(clock);
        assert_eq!(a.submit_provision(b"client file", true).0, NO_JOB);
    }

    #[test]
    fn poll_delivers_generated_keyfile_once() {
        let clock = ManualClock::new(0);
        let mut a = auth(clock);
        let mut v = vault();
        a.initialize(&v);
        let (id, req) = a.submit_provision(&[], true);
        a.run(&mut v, req.as_ref().unwrap());
        let first = a.poll(id).unwrap();
        assert_eq!(first.key_file.len(), KEYFILE_GENERATED_BYTES);
        let second = a.poll(id).unwrap();
        assert!(second.key_file.is_empty());
    }

    #[test]
    fn rekey_generate_replaces_keyfile() {
        let clock = ManualClock::new(0);
        let mut a = auth(clock);
        let mut v = vault();
        a.initialize(&v);
        let pw = provision(&mut a, &mut v);

        let (id, req) = a.submit_rekey(&pw, None, &[], &[], KeyfileAction::Generate);
        assert_ne!(id, NO_JOB);
        a.run(&mut v, req.as_ref().unwrap());
        let view = a.poll(id).unwrap();
        assert_eq!(view.result, JobResult::Ok);
        assert_eq!(view.key_file.len(), KEYFILE_GENERATED_BYTES);
        assert!(v.key_file_required());
        let kf = view.key_file.clone();

        a.lock(&mut v);
        let (id, req) = a.submit_unlock(&pw, &[]);
        a.run(&mut v, req.as_ref().unwrap());
        assert_eq!(a.poll(id).unwrap().result, JobResult::WrongPassword);

        let (id, req) = a.submit_unlock(&pw, &kf);
        a.run(&mut v, req.as_ref().unwrap());
        assert_eq!(a.poll(id).unwrap().result, JobResult::Ok);
    }

    #[test]
    fn rekey_generate_rejects_supplied_new_keyfile() {
        let clock = ManualClock::new(0);
        let mut a = auth(clock);
        assert_eq!(
            a.submit_rekey(PW, Some(PW2), &[], b"client file", KeyfileAction::Generate)
                .0,
            NO_JOB
        );
    }

    #[test]
    fn generate_keyfile_uses_rng_not_a_constant() {
        let clock = ManualClock::new(0);
        let mut a = auth(clock);
        let kf1 = a.generate_keyfile();
        let kf2 = a.generate_keyfile();
        assert_eq!(kf1.len(), KEYFILE_GENERATED_BYTES);
        assert!(kf1.iter().any(|&b| b != 0));
        assert_ne!(kf1, kf2, "consecutive draws must differ");
    }

    #[test]
    fn session_validation_accepts_case_insensitive_hex_only() {
        let clock = ManualClock::new(0);
        let mut a = auth(clock);
        let mut v = vault();
        a.initialize(&v);
        let _pw = provision(&mut a, &mut v);

        let token = a.session_token_hex().unwrap();
        assert_eq!(token.len(), SESSION_TOKEN_HEX_LEN);
        assert!(a.session_valid(&token));
        assert!(a.session_valid(&token.to_uppercase()));

        let mut bad = token.clone();
        bad.replace_range(0..1, if token.starts_with('0') { "1" } else { "0" });
        assert!(!a.session_valid(&bad));
        assert!(!a.session_valid(&token[..SESSION_TOKEN_HEX_LEN - 1]));
        assert!(!a.session_valid("not hex at all"));
    }

    #[test]
    fn idle_timeout_closes_session() {
        let clock = ManualClock::new(1_000);
        let mut a = auth(clock.clone());
        let mut v = vault();
        a.initialize(&v);
        let _pw = provision(&mut a, &mut v);
        assert!(a.state().unlocked);

        clock.advance(SESSION_TTL_MS - 1);
        a.tick(&mut v);
        assert!(a.state().unlocked);

        clock.advance(1);
        a.tick(&mut v);
        assert!(!a.state().unlocked);
    }

    #[test]
    fn lockout_survives_millis_wraparound() {
        // Start just before the u32 wrap so the lockout window straddles it.
        let clock = ManualClock::new(u32::MAX - 10);
        let mut a = auth(clock.clone());
        let mut v = vault();
        a.initialize(&v);
        let _pw = provision(&mut a, &mut v);
        a.lock(&mut v);

        for _ in 0..AUTH_MAX_FAIL {
            let (id, req) = a.submit_unlock("definitely the wrong password", &[]);
            if id == NO_JOB {
                // Already locked out; stop.
                break;
            }
            a.run(&mut v, req.as_ref().unwrap());
        }
        assert!(a.state().lockout_ms_left > 0);

        clock.advance(11); // crosses the wrap to a small value
        assert!(
            a.state().lockout_ms_left > 0,
            "wrap must not end the lockout"
        );

        clock.advance(AUTH_LOCKOUT_MS);
        assert_eq!(a.state().lockout_ms_left, 0);
    }

    #[test]
    fn clear_lockout_reenables_submit() {
        let clock = ManualClock::new(0);
        let mut a = auth(clock);
        let mut v = vault();
        a.initialize(&v);
        let _pw = provision(&mut a, &mut v);
        a.lock(&mut v);
        for _ in 0..AUTH_MAX_FAIL {
            let (id, req) = a.submit_unlock("definitely the wrong password", &[]);
            if id == NO_JOB {
                break;
            }
            a.run(&mut v, req.as_ref().unwrap());
        }
        assert_eq!(a.submit_unlock("x", &[]).0, NO_JOB);
        a.clear_lockout();
        assert_ne!(
            a.submit_unlock("definitely the wrong password", &[]).0,
            NO_JOB
        );
    }

    #[test]
    fn generate_master_password_has_expected_shape() {
        let clock = ManualClock::new(0);
        let mut a = auth(clock);
        let pw = a.generate_master_password();
        assert_eq!(pw.len(), MASTER_PASSWORD_CHARS);
        assert_eq!(pw.split('-').count(), 6 + 1);
    }
}
