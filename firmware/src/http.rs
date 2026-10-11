//! HTTP server: health probe, the auth API, and read-only static serving of
//! the SPA assets from the `web` partition.
//!
//! The server is started once and kept alive for the whole program lifetime
//! (dropping it would stop httpd). `/api/*` routes are registered before the
//! static `/*` catch-all so they cannot be shadowed by it.

use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use esp_idf_svc::http::server::{Configuration, EspHttpConnection, EspHttpServer, Request};
use esp_idf_svc::http::Method;
use esp_idf_svc::io::Write;
use pm_core::auth::{Job, JobId, JobResult, KeyfileAction, NO_JOB, SESSION_TOKEN_HEX_LEN};
use pm_core::entry::{Entry, Field, VaultError};
use pm_core::export;
use serde_json::{json, Value};

use crate::auth_worker;
use crate::static_cell::StaticCell;
use crate::web;

/// Stack for the httpd task. Larger than the 4 KiB default because the static
/// handler streams files from a stack buffer; up to four sessions run at once,
/// so a shared static buffer would be a race.
const STACK_BYTES: usize = 8192;
/// Read/serve chunk size, matching `config::kHttpChunkBytes`.
const CHUNK: usize = 1024;
/// JSON request body cap, matching `config::kHttpMaxBody`.
const MAX_BODY: usize = 8192;
const HTTP_PORT: u16 = 80;
/// Matches `config::kHttpMaxSessions`.
const MAX_SESSIONS: usize = 4;

/// A handler's request, tied to the connection's two lifetimes.
type Req<'a, 'b> = Request<&'a mut EspHttpConnection<'b>>;

/// Owns the running server. Written once in [`install`]; never mutated after.
static SERVER: StaticCell<Option<EspHttpServer<'static>>> = StaticCell::new(None);
static INSTALLED: AtomicBool = AtomicBool::new(false);

static REQUESTS: AtomicU32 = AtomicU32::new(0);
static IN_FLIGHT: AtomicU32 = AtomicU32::new(0);

/// Counts requests and in-flight requests; decrements on every exit path,
/// including early error returns.
struct RequestGuard;

impl RequestGuard {
    fn new() -> Self {
        REQUESTS.fetch_add(1, Ordering::Relaxed);
        IN_FLIGHT.fetch_add(1, Ordering::Relaxed);
        RequestGuard
    }
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        IN_FLIGHT.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A controlled API error: HTTP status, reason phrase and JSON `error` code.
struct HttpError {
    status: u16,
    reason: &'static str,
    code: &'static str,
}

fn bad_request(code: &'static str) -> HttpError {
    HttpError {
        status: 400,
        reason: "Bad Request",
        code,
    }
}

fn conflict(code: &'static str) -> HttpError {
    HttpError {
        status: 409,
        reason: "Conflict",
        code,
    }
}

fn unauthorized() -> HttpError {
    HttpError {
        status: 401,
        reason: "Unauthorized",
        code: "session_required",
    }
}

/// Starts the HTTP server. Idempotent.
pub fn install() -> anyhow::Result<()> {
    if INSTALLED.load(Ordering::Acquire) {
        return Ok(());
    }

    let config = Configuration {
        http_port: HTTP_PORT,
        // Default IDF value, set explicitly so the control port is not random.
        ctrl_port: 32768,
        stack_size: STACK_BYTES,
        // Room for the planned routes (see the registrations below).
        max_uri_handlers: 24,
        max_open_sockets: MAX_SESSIONS,
        // Without wildcard matching httpd finds only the exact "/" and 404s
        // every asset like "/assets/app.js".
        uri_match_wildcard: true,
        ..Default::default()
    };

    let mut server = EspHttpServer::new(&config)?;

    server.fn_handler::<anyhow::Error, _>("/api/health", Method::Get, health_handler)?;
    server.fn_handler::<anyhow::Error, _>("/api/auth/state", Method::Get, auth_state_handler)?;
    server.fn_handler::<anyhow::Error, _>(
        "/api/auth/provision",
        Method::Post,
        auth_provision_handler,
    )?;
    server.fn_handler::<anyhow::Error, _>("/api/auth/unlock", Method::Post, auth_unlock_handler)?;
    server.fn_handler::<anyhow::Error, _>("/api/auth/job/*", Method::Get, auth_job_handler)?;
    server.fn_handler::<anyhow::Error, _>("/api/auth/lock", Method::Post, auth_lock_handler)?;
    server.fn_handler::<anyhow::Error, _>(
        "/api/auth/session",
        Method::Get,
        auth_session_handler,
    )?;
    server.fn_handler::<anyhow::Error, _>("/api/auth/reset", Method::Post, auth_reset_handler)?;
    server.fn_handler::<anyhow::Error, _>("/api/auth/rekey", Method::Post, auth_rekey_handler)?;
    server.fn_handler::<anyhow::Error, _>(
        "/api/auth/password",
        Method::Get,
        auth_password_handler,
    )?;
    server.fn_handler::<anyhow::Error, _>("/api/entries", Method::Get, entries_list_handler)?;
    server.fn_handler::<anyhow::Error, _>("/api/entries", Method::Post, entries_write_handler)?;
    server.fn_handler::<anyhow::Error, _>("/api/entries/*", Method::Get, entries_get_handler)?;
    server.fn_handler::<anyhow::Error, _>("/api/entries/*", Method::Post, entries_write_handler)?;
    server.fn_handler::<anyhow::Error, _>(
        "/api/entries/*",
        Method::Delete,
        entries_delete_handler,
    )?;
    server.fn_handler::<anyhow::Error, _>("/api/export", Method::Get, export_handler)?;
    server.fn_handler::<anyhow::Error, _>("/api/import", Method::Post, import_handler)?;
    server.fn_handler::<anyhow::Error, _>("/", Method::Get, static_handler)?;
    server.fn_handler::<anyhow::Error, _>("/*", Method::Get, static_handler)?;

    // SAFETY: single-threaded initialisation; the slot is written exactly once
    // (guarded by `INSTALLED`) before any request can be served.
    unsafe { *SERVER.get() = Some(server) };
    INSTALLED.store(true, Ordering::Release);

    if web::mounted() {
        log::info!(
            "http listening on port {HTTP_PORT}, web {} KB",
            web::used_bytes() >> 10
        );
    } else {
        log::warn!("http listening on port {HTTP_PORT}, web NOT mounted: static will 404");
    }
    Ok(())
}

// ── Response helpers ─────────────────────────────────────────────────────────

fn send_json(req: Req<'_, '_>, status: u16, reason: &str, value: &Value) -> anyhow::Result<()> {
    let body = serde_json::to_vec(value)?;
    let mut resp = req.into_response(
        status,
        Some(reason),
        &[
            ("Content-Type", "application/json"),
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
        ],
    )?;
    resp.write_all(&body)?;
    Ok(())
}

fn fail(req: Req<'_, '_>, e: HttpError) -> anyhow::Result<()> {
    if e.status >= 500 {
        log::error!("http: {} {}", e.status, e.code);
    } else {
        log::warn!("http: {} {}", e.status, e.code);
    }
    send_json(
        req,
        e.status,
        e.reason,
        &json!({"ok": false, "error": e.code}),
    )
}

/// 202 Accepted with the job id as 16 hex chars (never a JSON number: 64 bits
/// do not fit a double).
fn send_job_accepted(req: Req<'_, '_>, id: JobId) -> anyhow::Result<()> {
    let body = json!({"ok": true, "job": format!("{id:016x}")});
    send_json(req, 202, "Accepted", &body)
}

// ── Request helpers ──────────────────────────────────────────────────────────

fn content_type_is_json(req: &Req<'_, '_>) -> bool {
    let Some(ct) = req.header("Content-Type") else {
        return false;
    };
    if ct.len() >= 64 {
        return false;
    }
    let ct = ct.to_ascii_lowercase();
    ct == "application/json"
        || ct.starts_with("application/json;")
        || ct.starts_with("application/json ")
}

fn content_length(req: &Req<'_, '_>) -> Option<usize> {
    req.header("Content-Length")?.trim().parse().ok()
}

fn read_json_body(req: &mut Req<'_, '_>) -> Result<Value, HttpError> {
    if !content_type_is_json(req) {
        return Err(HttpError {
            status: 415,
            reason: "Unsupported Media Type",
            code: "json_content_type_required",
        });
    }
    let len = content_length(req).ok_or(HttpError {
        status: 411,
        reason: "Length Required",
        code: "content_length_required",
    })?;
    if len == 0 {
        return Err(bad_request("empty_body"));
    }
    if len > MAX_BODY {
        return Err(HttpError {
            status: 413,
            reason: "Payload Too Large",
            code: "body_too_large",
        });
    }

    let mut buf = vec![0u8; len];
    let mut got = 0;
    while got < len {
        match req.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(_) => {
                pm_core::crypto::wipe(&mut buf);
                return Err(HttpError {
                    status: 408,
                    reason: "Request Timeout",
                    code: "body_read_timeout",
                });
            }
        }
    }

    let parsed = serde_json::from_slice::<Value>(&buf[..got]);
    pm_core::crypto::wipe(&mut buf);
    let value = parsed.map_err(|_| bad_request("malformed_json"))?;
    if !value.is_object() {
        return Err(bad_request("expected_json_object"));
    }
    Ok(value)
}

/// Validates `X-PM-Session`. One 401 for every reason, so the code cannot be
/// used to distinguish "no session" from "wrong token".
fn require_session(req: &Req<'_, '_>) -> Result<(), HttpError> {
    let Some(tok) = req.header("X-PM-Session") else {
        return Err(unauthorized());
    };
    if tok.len() != SESSION_TOKEN_HEX_LEN || !auth_worker::session_valid(tok) {
        return Err(unauthorized());
    }
    Ok(())
}

fn require_same_origin(req: &Req<'_, '_>) -> Result<(), HttpError> {
    if !origin_matches_host(req) {
        return Err(HttpError {
            status: 403,
            reason: "Forbidden",
            code: "cross_origin_refused",
        });
    }
    if !sec_fetch_site_allowed(req) {
        return Err(HttpError {
            status: 403,
            reason: "Forbidden",
            code: "cross_site_refused",
        });
    }
    if !host_is_device(req) {
        return Err(HttpError {
            status: 403,
            reason: "Forbidden",
            code: "host_refused",
        });
    }
    Ok(())
}

/// `Origin`, when present, must name the same host as `Host`. Missing `Origin`
/// (curl, tests) is allowed.
fn origin_matches_host(req: &Req<'_, '_>) -> bool {
    let Some(origin) = req.header("Origin") else {
        return true;
    };
    if origin.len() >= 80 {
        return false;
    }
    let Some(scheme_end) = origin.find("://") else {
        return false;
    };
    let authority = &origin[scheme_end + 3..];
    let host_port = authority.split('/').next().unwrap_or("");
    let host = host_port.split(':').next().unwrap_or("");
    if host.is_empty() {
        return false;
    }
    let Some(hdr) = req.header("Host") else {
        return false;
    };
    if hdr.len() >= 80 {
        return false;
    }
    let hdr_host = hdr.split(':').next().unwrap_or("");
    host.eq_ignore_ascii_case(hdr_host)
}

/// `Sec-Fetch-Site`, which JS cannot forge, must be `same-origin` or `none`
/// when present.
fn sec_fetch_site_allowed(req: &Req<'_, '_>) -> bool {
    let Some(value) = req.header("Sec-Fetch-Site") else {
        return true;
    };
    if value.len() >= 32 {
        return false;
    }
    value.eq_ignore_ascii_case("same-origin") || value.eq_ignore_ascii_case("none")
}

/// `Host` must be a numeric address of this device.
fn host_is_device(req: &Req<'_, '_>) -> bool {
    let Some(hdr) = req.header("Host") else {
        return false;
    };
    if hdr.len() >= 80 {
        return false;
    }
    let host = hdr.split(':').next().unwrap_or("");
    if host.is_empty() || host.len() >= 16 {
        return false;
    }
    let Some(mine) = crate::net_bridge::ip() else {
        return true; // no address yet — nothing to compare against
    };
    parse_ipv4(host).is_some_and(|got| got == mine)
}

/// Strict `a.b.c.d` parse: four parts, each 0..=255, no leading junk.
fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut parts = s.split('.');
    for slot in out.iter_mut() {
        let part = parts.next()?;
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let v: u32 = part.parse().ok()?;
        if v > 255 {
            return None;
        }
        *slot = v as u8;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(out)
}

/// Parses the optional key-file field (`base64`). Absent/empty means "no file".
fn keyfile_field(doc: &Value, key: &str) -> Result<Vec<u8>, HttpError> {
    let Some(value) = doc.get(key) else {
        return Ok(Vec::new());
    };
    if value.is_null() {
        return Ok(Vec::new());
    }
    let Some(b64) = value.as_str() else {
        return Err(bad_request("keyfile_not_a_string"));
    };
    if b64.is_empty() {
        return Ok(Vec::new());
    }
    if !b64.len().is_multiple_of(4) {
        return Err(bad_request("keyfile_invalid_base64"));
    }
    if (b64.len() / 4) * 3 > pm_core::config::KEYFILE_MAX_BYTES {
        return Err(bad_request("keyfile_too_large"));
    }
    match base64_decode(b64) {
        Some(bytes) if bytes.is_empty() => Ok(Vec::new()),
        Some(bytes) => Ok(bytes),
        None => Err(bad_request("keyfile_invalid_base64")),
    }
}

fn b64_value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Strict RFC 4648 base64: standard alphabet, padding only in the last group.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.is_empty() || !b.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    for chunk in b.chunks_exact(4) {
        let a = b64_value(chunk[0])?;
        let b2 = b64_value(chunk[1])?;
        let c_pad = chunk[2] == b'=';
        let d_pad = chunk[3] == b'=';
        if c_pad && !d_pad {
            return None;
        }
        let c = if c_pad { 0 } else { b64_value(chunk[2])? };
        let d = if d_pad { 0 } else { b64_value(chunk[3])? };
        out.push((a << 2) | (b2 >> 4));
        if c_pad {
            continue;
        }
        out.push(((b2 & 0x0F) << 4) | (c >> 2));
        if d_pad {
            continue;
        }
        out.push(((c & 0x03) << 6) | d);
    }
    if out.len() > pm_core::config::KEYFILE_MAX_BYTES {
        return None;
    }
    Some(out)
}

fn parse_job_id(uri: &str) -> Option<JobId> {
    let rest = uri.strip_prefix("/api/auth/job/")?;
    let seg = rest.split(['/', '?']).next().unwrap_or("");
    if seg.len() != 16 {
        return None;
    }
    u64::from_str_radix(seg, 16).ok().filter(|&v| v != NO_JOB)
}

fn job_kind_name(job: Job) -> &'static str {
    match job {
        Job::Provision => "provision",
        Job::Unlock => "unlock",
        Job::Reset => "reset",
        Job::Rekey => "rekey",
    }
}

fn send_job_error(req: Req<'_, '_>, result: JobResult) -> anyhow::Result<()> {
    let e = match result {
        JobResult::Busy => HttpError {
            status: 503,
            reason: "Service Unavailable",
            code: "busy",
        },
        JobResult::WrongPassword => HttpError {
            status: 401,
            reason: "Unauthorized",
            code: "wrong_password",
        },
        JobResult::Refused => conflict("refused"),
        JobResult::Lockout => HttpError {
            status: 429,
            reason: "Too Many Requests",
            code: "lockout",
        },
        JobResult::Error => HttpError {
            status: 500,
            reason: "Internal Server Error",
            code: "worker_error",
        },
        JobResult::Pending | JobResult::Ok => HttpError {
            status: 500,
            reason: "Internal Server Error",
            code: "unknown_result",
        },
    };
    fail(req, e)
}

// ── Entries / export / import helpers ────────────────────────────────────────

/// One of the three entry routes encoded by `/api/entries*`.
enum EntryRoute {
    /// `/api/entries` — list / create.
    Collection,
    /// `/api/entries/{id}` — detail / update / delete.
    Item(u32),
    /// `/api/entries/{id}/secret` — password.
    Secret(u32),
    /// `/api/entries/{id}/totp` — one-time code.
    Totp(u32),
}

/// The path with the query string removed (suffix checks must ignore `?t=…`).
fn strip_query(uri: &str) -> &str {
    uri.split(['?', '#']).next().unwrap_or(uri)
}

/// Splits `/api/entries[/*]` into an [`EntryRoute`]. `None` means the suffix is
/// malformed (`/api/entries/abc`, `/api/entries/7/secretx`), which the reference
/// answers with `400 bad_entry_id`. A strict numeric id (never `0`) is required,
/// so a typo cannot silently mean "create".
fn entry_route(uri: &str) -> Option<EntryRoute> {
    let rest = strip_query(uri).strip_prefix("/api/entries")?;
    if rest.is_empty() {
        return Some(EntryRoute::Collection);
    }
    let rest = rest.strip_prefix('/')?;
    let mut parts = rest.splitn(2, '/');
    let id_seg = parts.next().unwrap_or("");
    if id_seg.is_empty() || !id_seg.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let id: u32 = id_seg.parse().ok().filter(|&v| v != 0)?;
    match parts.next() {
        None => Some(EntryRoute::Item(id)),
        Some("secret") => Some(EntryRoute::Secret(id)),
        Some("totp") => Some(EntryRoute::Totp(id)),
        Some(_) => None,
    }
}

/// Extracts `t=<epoch-seconds>` from the query string. Other parameters are
/// ignored, matching the reference; the first `t=` wins. The board has no clock,
/// so time is always supplied by the client.
fn query_time(uri: &str) -> Option<u32> {
    let query = uri.split_once('?')?.1;
    for part in query.split('&') {
        if let Some(v) = part.strip_prefix("t=") {
            if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            return v.parse::<u32>().ok();
        }
    }
    None
}

/// A field as UTF-8, rejecting a slot with no NUL terminator (only reachable
/// through flash corruption). The reference maps this to `500`.
fn field_checked(e: &Entry, field: Field) -> Result<&str, ()> {
    let raw = e.raw(field);
    let end = raw.iter().position(|&b| b == 0).ok_or(())?;
    core::str::from_utf8(&raw[..end]).map_err(|_| ())
}

/// Field for the list, where the reference substitutes an empty string for a
/// corrupt (unterminated) slot rather than failing the whole listing.
fn field_list(e: &Entry, field: Field) -> String {
    match field_checked(e, field) {
        Ok(s) => s.to_owned(),
        Err(()) => String::new(),
    }
}

fn internal(code: &'static str) -> HttpError {
    HttpError {
        status: 500,
        reason: "Internal Server Error",
        code,
    }
}

fn not_found(code: &'static str) -> HttpError {
    HttpError {
        status: 404,
        reason: "Not Found",
        code,
    }
}

/// Maps a failed `Vault::add` to the reference's status/code. Shared by the
/// CRUD write and the import batch.
fn add_error(e: VaultError) -> HttpError {
    match e {
        VaultError::TooManyEntries => conflict("too_many_entries"),
        VaultError::Budget => conflict("storage_full"),
        VaultError::EntryTooLong => bad_request("entry_too_long"),
        VaultError::BootStrap => conflict("vault_not_open"),
        _ => internal("vault_add_failed"),
    }
}

/// Fills an [`Entry`] from a JSON object, enforcing every field's capacity.
/// `Entry::set` would truncate silently, which is exactly the silent corruption
/// the reference refuses with `400 field_too_long_or_not_a_string`.
fn fill_entry(doc: &Value, e: &mut Entry) -> Result<(), HttpError> {
    const FIELDS: &[(&str, Field)] = &[
        ("title", Field::Title),
        ("login", Field::Login),
        ("password", Field::Password),
        ("url", Field::Url),
        ("note", Field::Note),
        ("tags", Field::Tags),
        ("totp", Field::Totp),
    ];
    for (key, field) in FIELDS {
        match doc.get(*key) {
            None | Some(Value::Null) => {}
            Some(Value::String(s)) => {
                if s.len() >= e.raw(*field).len() {
                    return Err(bad_request("field_too_long_or_not_a_string"));
                }
                e.set(*field, s.as_bytes());
            }
            Some(_) => return Err(bad_request("field_too_long_or_not_a_string")),
        }
    }
    if !e.get(Field::Totp).is_empty() {
        let ok = core::str::from_utf8(e.get(Field::Totp))
            .ok()
            .is_some_and(pm_core::totp::valid_secret);
        if !ok {
            return Err(bad_request("totp_secret_invalid"));
        }
    }
    Ok(())
}

/// `GET /api/entries/{id}` body. `None` in place of a field means the slot had
/// no terminator (corruption).
fn detail_body(e: &Entry) -> Result<Value, ()> {
    Ok(json!({
        "ok": true,
        "id": e.id,
        "title": field_checked(e, Field::Title)?,
        "login": field_checked(e, Field::Login)?,
        "url": field_checked(e, Field::Url)?,
        "note": field_checked(e, Field::Note)?,
        "tags": field_checked(e, Field::Tags)?,
        "totp": field_checked(e, Field::Totp)?,
        "hasPassword": !e.get(Field::Password).is_empty(),
        "hasTotp": !e.get(Field::Totp).is_empty(),
    }))
}

// ── Handlers ─────────────────────────────────────────────────────────────────

fn health_handler(req: Req<'_, '_>) -> anyhow::Result<()> {
    // Guard first so the reported counters include this very request.
    let _guard = RequestGuard::new();

    let body = json!({
        "ok": true,
        "fw": pm_core::config::FIRMWARE_VERSION,
        "uptime_ms": crate::platform::time::now_ms(),
        "in_flight": IN_FLIGHT.load(Ordering::Relaxed),
        "max_sessions": MAX_SESSIONS,
        "requests": REQUESTS.load(Ordering::Relaxed),
        "web_used_kb": web::used_bytes() >> 10,
        "web_total_kb": web::total_bytes() >> 10,
    });
    send_json(req, 200, "OK", &body)
}

fn auth_state_handler(req: Req<'_, '_>) -> anyhow::Result<()> {
    let _guard = RequestGuard::new();
    let s = auth_worker::state();
    let body = json!({
        "ok": true,
        "provisioned": s.provisioned,
        "unlocked": s.unlocked,
        "busy": s.busy,
        "failCount": s.fail_count,
        "lockoutMsLeft": s.lockout_ms_left,
        "keyfileRequired": auth_worker::key_file_required(),
        "masterPasswordChars": pm_core::config::MASTER_PASSWORD_CHARS,
        "maxEntryCount": pm_core::config::MAX_ENTRIES,
        "keyFileMaxBytes": pm_core::config::KEYFILE_MAX_BYTES,
    });
    send_json(req, 200, "OK", &body)
}

fn auth_provision_handler(mut req: Req<'_, '_>) -> anyhow::Result<()> {
    let _guard = RequestGuard::new();
    if let Err(e) = require_same_origin(&req) {
        return fail(req, e);
    }

    // Refuse before reading the body: a second provisioning over a non-empty
    // partition wipes it.
    let s = auth_worker::state();
    if s.provisioned {
        log::warn!("http: provision refused, already provisioned");
        return fail(req, conflict("already_provisioned"));
    }
    if s.unlocked {
        log::error!("http: provision refused, unprovisioned but unlocked");
        return fail(req, conflict("inconsistent_state"));
    }

    let key_file = if content_length(&req).is_some_and(|n| n > 0) {
        match read_json_body(&mut req) {
            Ok(doc) => match keyfile_field(&doc, "keyfile") {
                Ok(kf) => kf,
                Err(e) => return fail(req, e),
            },
            Err(e) => return fail(req, e),
        }
    } else {
        Vec::new()
    };

    let id = auth_worker::submit_provision(key_file);
    if id == NO_JOB {
        return fail(
            req,
            HttpError {
                status: 503,
                reason: "Service Unavailable",
                code: "busy",
            },
        );
    }
    log::info!("http: provisioning requested");
    send_job_accepted(req, id)
}

fn auth_unlock_handler(mut req: Req<'_, '_>) -> anyhow::Result<()> {
    let _guard = RequestGuard::new();
    if let Err(e) = require_same_origin(&req) {
        return fail(req, e);
    }

    let doc = match read_json_body(&mut req) {
        Ok(doc) => doc,
        Err(e) => return fail(req, e),
    };
    let Some(password) = doc.get("password").and_then(Value::as_str) else {
        return fail(req, bad_request("password_required"));
    };
    let n = password.len();
    if !(pm_core::config::MIN_PASS_CHARS..pm_core::config::MAX_PASS_CHARS).contains(&n) {
        log::warn!("http: unlock rejected, password length {n} out of range");
        return fail(req, bad_request("password_length_out_of_range"));
    }
    let key_file = match keyfile_field(&doc, "keyfile") {
        Ok(kf) => kf,
        Err(e) => return fail(req, e),
    };

    let id = auth_worker::submit_unlock(password.as_bytes().to_vec(), key_file);
    if id == NO_JOB {
        return fail(
            req,
            HttpError {
                status: 503,
                reason: "Service Unavailable",
                code: "busy",
            },
        );
    }
    log::info!("http: unlock requested");
    send_job_accepted(req, id)
}

fn auth_job_handler(req: Req<'_, '_>) -> anyhow::Result<()> {
    let _guard = RequestGuard::new();
    let Some(id) = parse_job_id(req.uri()) else {
        return fail(req, bad_request("bad_job_id"));
    };
    let Some(view) = auth_worker::poll(id) else {
        return fail(
            req,
            HttpError {
                status: 404,
                reason: "Not Found",
                code: "unknown_job",
            },
        );
    };

    if view.result == JobResult::Pending {
        return send_json(req, 200, "OK", &json!({"ok": true, "state": "pending"}));
    }
    if view.result != JobResult::Ok {
        return send_job_error(req, view.result);
    }

    let mut body = json!({
        "ok": true,
        "result": "ok",
        "job": job_kind_name(view.kind),
    });
    if view.kind == Job::Provision && !view.password.is_empty() {
        if let Ok(pw) = std::str::from_utf8(&view.password) {
            body["password"] = Value::String(pw.to_owned());
        }
    }
    if !view.session_token.is_empty() {
        if let Ok(tok) = std::str::from_utf8(&view.session_token) {
            body["session_token"] = Value::String(tok.to_owned());
        }
    }
    send_json(req, 200, "OK", &body)
}

fn auth_lock_handler(req: Req<'_, '_>) -> anyhow::Result<()> {
    let _guard = RequestGuard::new();
    if let Err(e) = require_same_origin(&req) {
        return fail(req, e);
    }
    if let Err(e) = require_session(&req) {
        return fail(req, e);
    }
    if !auth_worker::lock() {
        return fail(
            req,
            HttpError {
                status: 500,
                reason: "Internal Server Error",
                code: "lock_failed",
            },
        );
    }
    send_json(req, 200, "OK", &json!({"ok": true, "unlocked": false}))
}

fn auth_session_handler(req: Req<'_, '_>) -> anyhow::Result<()> {
    let _guard = RequestGuard::new();
    if let Err(e) = require_session(&req) {
        return fail(req, e);
    }
    let Some(token) = auth_worker::session_token_hex() else {
        log::error!("http: session valid but token unreadable");
        return fail(
            req,
            HttpError {
                status: 500,
                reason: "Internal Server Error",
                code: "token_unavailable",
            },
        );
    };
    let s = auth_worker::state();
    let entry_count = if s.provisioned && s.unlocked {
        auth_worker::entry_count()
    } else {
        0
    };
    let body = json!({
        "ok": true,
        "token": token,
        "expiresInMs": pm_core::config::SESSION_TTL_MS,
        "entryCount": entry_count,
    });
    send_json(req, 200, "OK", &body)
}

fn auth_reset_handler(mut req: Req<'_, '_>) -> anyhow::Result<()> {
    let _guard = RequestGuard::new();
    if let Err(e) = require_same_origin(&req) {
        return fail(req, e);
    }
    // Session mandatory by design: reset destroys the vault.
    if let Err(e) = require_session(&req) {
        return fail(req, e);
    }

    let doc = match read_json_body(&mut req) {
        Ok(doc) => doc,
        Err(e) => return fail(req, e),
    };
    if doc.get("confirm").and_then(Value::as_str) != Some("RESET") {
        log::warn!("http: reset refused, no confirmation");
        return fail(req, bad_request("confirmation_required"));
    }

    let id = auth_worker::submit_reset();
    if id == NO_JOB {
        return fail(
            req,
            HttpError {
                status: 503,
                reason: "Service Unavailable",
                code: "busy",
            },
        );
    }
    log::warn!("http: vault reset requested");
    send_job_accepted(req, id)
}

fn auth_rekey_handler(mut req: Req<'_, '_>) -> anyhow::Result<()> {
    let _guard = RequestGuard::new();
    if let Err(e) = require_same_origin(&req) {
        return fail(req, e);
    }
    if let Err(e) = require_session(&req) {
        return fail(req, e);
    }

    let doc = match read_json_body(&mut req) {
        Ok(doc) => doc,
        Err(e) => return fail(req, e),
    };
    let Some(old) = doc.get("old_password").and_then(Value::as_str) else {
        return fail(req, bad_request("old_password_required"));
    };
    let old_len = old.len();
    if !(pm_core::config::MIN_PASS_CHARS..pm_core::config::MAX_PASS_CHARS).contains(&old_len) {
        log::warn!("http: rekey rejected, old password length {old_len} out of range");
        return fail(req, bad_request("old_password_length_out_of_range"));
    }

    let new_password = match doc.get("password") {
        None | Some(Value::Null) => None,
        Some(Value::String(np)) if np.is_empty() => None,
        Some(Value::String(np)) => {
            let n = np.len();
            if !(pm_core::config::MIN_PASS_CHARS..pm_core::config::MAX_PASS_CHARS).contains(&n) {
                return fail(req, bad_request("password_length_out_of_range"));
            }
            Some(np.as_bytes().to_vec())
        }
        Some(_) => return fail(req, bad_request("password_not_a_string")),
    };

    let cur_key_file = if auth_worker::key_file_required() {
        match keyfile_field(&doc, "keyfile_current") {
            Ok(kf) if !kf.is_empty() => kf,
            Ok(_) => return fail(req, bad_request("keyfile_current_required")),
            Err(e) => return fail(req, e),
        }
    } else {
        Vec::new()
    };

    let action = match doc.get("keyfile_action") {
        None | Some(Value::Null) => KeyfileAction::Keep,
        Some(Value::String(a)) if a == "keep" => KeyfileAction::Keep,
        Some(Value::String(a)) if a == "set" => KeyfileAction::Set,
        Some(Value::String(a)) if a == "clear" => KeyfileAction::Clear,
        Some(_) => return fail(req, bad_request("keyfile_action_invalid")),
    };

    let new_key_file = if action == KeyfileAction::Set {
        match keyfile_field(&doc, "keyfile_new") {
            Ok(kf) if !kf.is_empty() => kf,
            Ok(_) => return fail(req, bad_request("keyfile_new_required")),
            Err(e) => return fail(req, e),
        }
    } else {
        Vec::new()
    };

    let id = auth_worker::submit_rekey(
        old.as_bytes().to_vec(),
        new_password,
        cur_key_file,
        new_key_file,
        action,
    );
    if id == NO_JOB {
        return fail(
            req,
            HttpError {
                status: 503,
                reason: "Service Unavailable",
                code: "busy",
            },
        );
    }
    log::info!("http: master password and/or keyfile change requested");
    send_job_accepted(req, id)
}

fn auth_password_handler(req: Req<'_, '_>) -> anyhow::Result<()> {
    let _guard = RequestGuard::new();
    if let Err(e) = require_session(&req) {
        return fail(req, e);
    }
    let password = auth_worker::generate_master_password();
    send_json(req, 200, "OK", &json!({"ok": true, "password": password}))
}

fn entries_list_handler(req: Req<'_, '_>) -> anyhow::Result<()> {
    let _guard = RequestGuard::new();
    if let Err(e) = require_session(&req) {
        return fail(req, e);
    }
    let entries = match auth_worker::entries_list() {
        Ok(v) => v,
        Err(err) => {
            log::error!("http: vault load failed: {}", err.to_str());
            return fail(req, internal("vault_load_failed"));
        }
    };
    let list: Vec<Value> = entries
        .iter()
        .map(|e| {
            json!({
                "id": e.id,
                "title": field_list(e, Field::Title),
                "login": field_list(e, Field::Login),
                "url": field_list(e, Field::Url),
                "tags": field_list(e, Field::Tags),
                "hasTotp": !e.get(Field::Totp).is_empty(),
            })
        })
        .collect();
    send_json(
        req,
        200,
        "OK",
        &json!({"ok": true, "count": list.len(), "entries": list}),
    )
}

fn entries_write_handler(mut req: Req<'_, '_>) -> anyhow::Result<()> {
    let _guard = RequestGuard::new();
    if let Err(e) = require_same_origin(&req) {
        return fail(req, e);
    }
    if let Err(e) = require_session(&req) {
        return fail(req, e);
    }

    // A path without a numeric tail is a create only on the exact collection
    // path; anything else is a typo, not "id 0".
    let (id, is_create) = match entry_route(req.uri()) {
        Some(EntryRoute::Collection) => (0u32, true),
        Some(EntryRoute::Item(id)) => (id, false),
        _ => return fail(req, bad_request("bad_entry_id")),
    };

    let doc = match read_json_body(&mut req) {
        Ok(doc) => doc,
        Err(e) => return fail(req, e),
    };
    let mut entry = Entry::new();
    entry.id = id;
    if let Err(e) = fill_entry(&doc, &mut entry) {
        return fail(req, e);
    }

    match auth_worker::entry_write(id, entry) {
        Ok(new_id) => {
            let (status, reason) = if is_create {
                (201, "Created")
            } else {
                (200, "OK")
            };
            send_json(req, status, reason, &json!({"ok": true, "id": new_id}))
        }
        Err(VaultError::NotFound) => fail(req, not_found("entry_not_found")),
        Err(e) => {
            log::error!("http: vault add failed: {}", e.to_str());
            fail(req, add_error(e))
        }
    }
}

fn entries_get_handler(req: Req<'_, '_>) -> anyhow::Result<()> {
    let _guard = RequestGuard::new();
    if let Err(e) = require_session(&req) {
        return fail(req, e);
    }
    match entry_route(req.uri()) {
        Some(EntryRoute::Item(id)) => entry_detail(req, id),
        Some(EntryRoute::Secret(id)) => entry_secret(req, id),
        Some(EntryRoute::Totp(id)) => entry_totp(req, id),
        _ => fail(req, bad_request("bad_entry_id")),
    }
}

fn entry_detail(req: Req<'_, '_>, id: u32) -> anyhow::Result<()> {
    let e = match auth_worker::entry_get(id) {
        Ok(e) => e,
        Err(VaultError::NotFound) => return fail(req, not_found("entry_not_found")),
        Err(err) => {
            log::error!("http: vault get failed: {}", err.to_str());
            return fail(req, internal("vault_get_failed"));
        }
    };
    match detail_body(&e) {
        Ok(body) => send_json(req, 200, "OK", &body),
        Err(()) => {
            log::warn!("http: entry {id} has unterminated field");
            fail(req, internal("entry_field_unterminated"))
        }
    }
}

fn entry_secret(req: Req<'_, '_>, id: u32) -> anyhow::Result<()> {
    let e = match auth_worker::entry_get(id) {
        Ok(e) => e,
        Err(VaultError::NotFound) => return fail(req, not_found("entry_not_found")),
        Err(err) => {
            log::error!("http: vault get failed: {}", err.to_str());
            return fail(req, internal("vault_get_failed"));
        }
    };
    let password = match field_checked(&e, Field::Password) {
        Ok(s) => s,
        Err(()) => {
            log::warn!("http: entry {id} password unterminated");
            return fail(req, internal("entry_field_unterminated"));
        }
    };
    send_json(
        req,
        200,
        "OK",
        &json!({"ok": true, "id": e.id, "password": password}),
    )
}

fn entry_totp(req: Req<'_, '_>, id: u32) -> anyhow::Result<()> {
    let Some(when) = query_time(req.uri()) else {
        return fail(req, bad_request("time_required"));
    };
    let e = match auth_worker::entry_get(id) {
        Ok(e) => e,
        Err(VaultError::NotFound) => return fail(req, not_found("entry_not_found")),
        Err(err) => {
            log::error!("http: vault get failed: {}", err.to_str());
            return fail(req, internal("vault_get_failed"));
        }
    };
    if e.get(Field::Totp).is_empty() {
        return fail(req, conflict("totp_not_configured"));
    }
    let secret = match core::str::from_utf8(e.get(Field::Totp)) {
        Ok(s) => s,
        Err(_) => {
            log::error!("http: entry {id} totp secret unusable");
            return fail(req, internal("totp_secret_invalid"));
        }
    };
    // The secret passed `valid_secret` at write time; a failure here is
    // corruption, not user error.
    let code = match pm_core::totp::code(secret, u64::from(when)) {
        Ok(c) => c,
        Err(_) => {
            log::error!("http: entry {id} totp secret unusable");
            return fail(req, internal("totp_secret_invalid"));
        }
    };
    let period = pm_core::config::TOTP_PERIOD_SEC;
    send_json(
        req,
        200,
        "OK",
        &json!({
            "ok": true,
            "code": code,
            "periodSec": period,
            "expiresInSec": period - (u64::from(when) % period),
        }),
    )
}

fn entries_delete_handler(mut req: Req<'_, '_>) -> anyhow::Result<()> {
    let _guard = RequestGuard::new();
    if let Err(e) = require_same_origin(&req) {
        return fail(req, e);
    }
    if let Err(e) = require_session(&req) {
        return fail(req, e);
    }
    let id = match entry_route(req.uri()) {
        Some(EntryRoute::Item(id)) => id,
        _ => return fail(req, bad_request("bad_entry_id")),
    };

    // Deletion is irreversible, so it needs the same explicit confirmation as a
    // vault reset — a missing body is a missing confirmation.
    match content_length(&req) {
        None | Some(0) => {
            log::warn!("http: delete refused, no confirmation");
            return fail(req, bad_request("confirmation_required"));
        }
        Some(_) => {
            let doc = match read_json_body(&mut req) {
                Ok(doc) => doc,
                Err(e) => return fail(req, e),
            };
            if doc.get("confirm").and_then(Value::as_str) != Some("DELETE") {
                return fail(req, bad_request("confirmation_required"));
            }
        }
    }

    match auth_worker::entry_remove(id) {
        Ok(()) => {
            log::info!("http: entry {id} deleted");
            send_json(req, 200, "OK", &json!({"ok": true, "id": id}))
        }
        Err(VaultError::NotFound) => fail(req, not_found("entry_not_found")),
        Err(err) => {
            log::error!("http: vault remove failed: {}", err.to_str());
            fail(req, internal("vault_remove_failed"))
        }
    }
}

fn export_handler(req: Req<'_, '_>) -> anyhow::Result<()> {
    let _guard = RequestGuard::new();
    if let Err(e) = require_session(&req) {
        return fail(req, e);
    }
    let entries = match auth_worker::entries_list() {
        Ok(v) => v,
        Err(err) => {
            log::error!("http: vault load failed: {}", err.to_str());
            return fail(req, internal("vault_load_failed"));
        }
    };

    // Streamed one record per chunk: a whole-document buffer would need ~1 MB at
    // the 1000-entry cap, while this holds a single record.
    let mut resp = req.into_response(
        200,
        Some("OK"),
        &[
            ("Content-Type", "application/json"),
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
            (
                "Content-Disposition",
                "attachment; filename=\"passmanager-export.json\"",
            ),
        ],
    )?;
    resp.write_all(export::export_head(entries.len()).as_bytes())?;
    for (i, e) in entries.iter().enumerate() {
        if i != 0 {
            resp.write_all(b",")?;
        }
        resp.write_all(export::encode_entry(e).as_bytes())?;
    }
    resp.write_all(export::EXPORT_TAIL.as_bytes())?;
    log::info!("http: exported {} entries", entries.len());
    Ok(())
}

fn import_handler(mut req: Req<'_, '_>) -> anyhow::Result<()> {
    let _guard = RequestGuard::new();
    if let Err(e) = require_same_origin(&req) {
        return fail(req, e);
    }
    if let Err(e) = require_session(&req) {
        return fail(req, e);
    }
    let doc = match read_json_body(&mut req) {
        Ok(doc) => doc,
        Err(e) => return fail(req, e),
    };
    // Every record is validated before a single one is written.
    let entries = match export::parse_import(&doc) {
        Ok(v) => v,
        Err(e) => {
            log::warn!("http: import refused: {}", e.code());
            return fail(req, bad_request(e.code()));
        }
    };
    let outcome = auth_worker::import_batch(entries);
    match outcome.error {
        None => {
            log::info!("http: imported {} entries", outcome.added);
            send_json(
                req,
                200,
                "OK",
                &json!({"ok": true, "imported": outcome.added}),
            )
        }
        Some(err) => {
            // Records already added are kept: rolling back good records for a
            // bad one would lose data the client believes landed.
            let he = add_error(err);
            log::error!("http: import stopped at {}: {}", outcome.added, he.code);
            send_json(
                req,
                he.status,
                he.reason,
                &json!({"ok": false, "error": he.code, "imported": outcome.added}),
            )
        }
    }
}

fn static_handler(req: Req<'_, '_>) -> anyhow::Result<()> {
    let _guard = RequestGuard::new();

    // The URI includes the query string; `web::open` strips it.
    let uri = req.uri().to_owned();

    let Some(mut asset) = web::open(&uri) else {
        // httpd's own 404 body is not reproduced; an empty 404 is enough for
        // the SPA to detect a missing asset.
        req.into_status_response(404)?;
        return Ok(());
    };

    let mime = web::mime_for(&asset.name);
    // MIME is taken from the parsed file name, not the request: for "/" the
    // request has no extension and would be served as octet-stream.
    let mut resp = req.into_response(
        200,
        Some("OK"),
        &[
            ("Content-Type", mime),
            // Assets have no content hash yet, so caching would keep serving a
            // stale index.html after an image update.
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
        ],
    )?;

    let mut buf = [0u8; CHUNK];
    loop {
        let got = match asset.file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                log::warn!("http: read {} failed: {e}", asset.name);
                break;
            }
        };
        resp.write(&buf[..got])?;
    }
    Ok(())
}
