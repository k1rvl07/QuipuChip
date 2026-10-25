//! HTTP layer: a picoserve catch-all service that reproduces the reference's
//! `/api/*` contract and serves the embedded SPA.
//!
//! The C++/esp-idf reference registered each route with esp-idf httpd. Here a
//! single [`Dispatcher`] implements [`PathRouterService`] and dispatches on
//! method + path itself. That keeps the route table in one place and lets the
//! auth worker's async client API be awaited directly from the handler.
//!
//! The dispatcher is parameterized by a const `INSTALL` flag. Over TLS
//! (`INSTALL = false`) the full SPA and API are reachable. Over plain HTTP
//! (`INSTALL = true`) only the certificate-install flow is exposed — the install
//! page itself plus the CA download and identity endpoints:
//!
//! - `GET /` , `/index.html` , `/install.html` — certificate-install page
//! - `GET /ca.pem` — root CA, PEM
//! - `GET /ca.crt` — root CA, DER
//! - `GET /api/pki/info` — CA/leaf identity and SHA-256 fingerprint
//!
//! Everything else on HTTP answers 404, so a browser that has not yet trusted
//! the device CA cannot reach the vault API or the SPA bundle.
//!
//! Every response is built from a small [`Outcome`] so the JSON headers
//! (`Cache-Control: no-store`, `X-Content-Type-Options: nosniff`) cannot be
//! forgotten on one path and not another.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use picoserve::ResponseSent;
use picoserve::io::{Read, Write};
use picoserve::request::{Path, Request, RequestBodyConnection, RequestParts};
use picoserve::response::{Connection, Content, Response, ResponseWriter, StatusCode};
use picoserve::routing::PathRouterService;
use pm_core::auth::{Job, JobId, JobResult, KeyfileAction, NO_JOB, SESSION_TOKEN_HEX_LEN};
use pm_core::entry::{Entry, Field};
use pm_core::export;
use pm_core::types::VaultError;
use serde_json::{Value, json};

use crate::authsvc;
use crate::hw::now_ms;
use crate::tls;
use crate::web;

/// JSON request body cap, matching `config::kHttpMaxBody`.
const MAX_BODY: usize = 8192;
/// Matches `config::kHttpMaxSessions`.
pub(crate) const MAX_SESSIONS: usize = 4;
/// The device's own address, used for the `Host`/`Origin` same-origin check.
const DEVICE_IP: [u8; 4] = [192, 168, 7, 1];

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

/// A controlled API error: HTTP status and the JSON `error` code.
struct HttpError {
    status: u16,
    code: &'static str,
}

impl HttpError {
    fn into_outcome(self) -> Outcome {
        if self.status >= 500 {
            log::error!("http: {} {}", self.status, self.code);
        } else {
            log::warn!("http: {} {}", self.status, self.code);
        }
        json_outcome(self.status, json!({"ok": false, "error": self.code}))
    }
}

fn bad_request(code: &'static str) -> HttpError {
    HttpError { status: 400, code }
}

fn conflict(code: &'static str) -> HttpError {
    HttpError { status: 409, code }
}

fn unauthorized() -> HttpError {
    HttpError {
        status: 401,
        code: "session_required",
    }
}

fn not_found(code: &'static str) -> HttpError {
    HttpError { status: 404, code }
}

fn internal(code: &'static str) -> HttpError {
    HttpError { status: 500, code }
}

fn busy() -> HttpError {
    HttpError {
        status: 503,
        code: "busy",
    }
}

fn method_not_allowed() -> HttpError {
    HttpError {
        status: 405,
        code: "method_not_allowed",
    }
}

// ── Response construction ────────────────────────────────────────────────────

/// A response body with an explicit content type.
struct Typed<B> {
    bytes: B,
    content_type: &'static str,
}

impl<B: AsRef<[u8]>> Content for Typed<B> {
    fn content_type(&self) -> &'static str {
        self.content_type
    }

    fn content_length(&self) -> usize {
        self.bytes.as_ref().len()
    }

    async fn write_content<W: Write>(self, mut writer: W) -> Result<(), W::Error> {
        writer.write_all(self.bytes.as_ref()).await
    }
}

const JSON_HEADERS: &[(&str, &str)] = &[
    ("Cache-Control", "no-store"),
    ("X-Content-Type-Options", "nosniff"),
];
const EXPORT_HEADERS: &[(&str, &str)] = &[
    ("Cache-Control", "no-store"),
    ("X-Content-Type-Options", "nosniff"),
    (
        "Content-Disposition",
        "attachment; filename=\"passmanager-export.json\"",
    ),
];

/// A fully-formed response, written after the request body is finalized.
enum Outcome {
    Json {
        status: u16,
        body: Vec<u8>,
    },
    Export(Vec<u8>),
    Static {
        bytes: &'static [u8],
        mime: &'static str,
    },
    Download {
        body: Vec<u8>,
        content_type: &'static str,
        disposition: &'static str,
    },
    Empty {
        status: u16,
    },
}

fn json_outcome(status: u16, value: Value) -> Outcome {
    let body = serde_json::to_vec(&value)
        .unwrap_or_else(|_| b"{\"ok\":false,\"error\":\"serialize_failed\"}".to_vec());
    Outcome::Json { status, body }
}

async fn write_outcome<R, W>(
    writer: W,
    conn: Connection<'_, R>,
    outcome: Outcome,
) -> Result<ResponseSent, W::Error>
where
    R: Read<Error = W::Error>,
    W: ResponseWriter,
{
    match outcome {
        Outcome::Json { status, body } => {
            let resp = Response::new(
                StatusCode::new(status),
                Typed {
                    bytes: body,
                    content_type: "application/json",
                },
            )
            .with_headers(JSON_HEADERS);
            writer.write_response(conn, resp).await
        }
        Outcome::Export(body) => {
            let resp = Response::new(
                StatusCode::OK,
                Typed {
                    bytes: body,
                    content_type: "application/json",
                },
            )
            .with_headers(EXPORT_HEADERS);
            writer.write_response(conn, resp).await
        }
        Outcome::Static { bytes, mime } => {
            let resp = Response::new(
                StatusCode::OK,
                Typed {
                    bytes,
                    content_type: mime,
                },
            )
            .with_headers(JSON_HEADERS);
            writer.write_response(conn, resp).await
        }
        Outcome::Empty { status } => {
            writer
                .write_response(conn, Response::empty(StatusCode::new(status)))
                .await
        }
        Outcome::Download {
            body,
            content_type,
            disposition,
        } => {
            let headers = [
                ("Cache-Control", "no-store"),
                ("X-Content-Type-Options", "nosniff"),
                ("Content-Disposition", disposition),
            ];
            let resp = Response::new(
                StatusCode::OK,
                Typed {
                    bytes: body,
                    content_type,
                },
            )
            .with_headers(&headers[..]);
            writer.write_response(conn, resp).await
        }
    }
}

// ── Routing ──────────────────────────────────────────────────────────────────

/// Forwards every request to [`route`]. Registered with
/// `Router::from_service(Dispatcher::<INSTALL>)`. `INSTALL = true` selects the
/// plain-HTTP certificate-install subset (see the module docs).
pub struct Dispatcher<const INSTALL: bool>;

impl<const INSTALL: bool> PathRouterService for Dispatcher<INSTALL> {
    async fn call_path_router_service<R: Read, W: ResponseWriter<Error = R::Error>>(
        &self,
        _state: &(),
        _current_path_parameters: (),
        path: Path<'_>,
        request: Request<'_, R>,
        response_writer: W,
    ) -> Result<ResponseSent, W::Error> {
        let _guard = RequestGuard::new();
        let parts = request.parts;
        let method = parts.method();
        let path_str = path.encoded();
        let mut body = request.body_connection;

        let outcome = match route::<INSTALL, R>(method, path_str, parts, &mut body).await {
            Ok(o) => o,
            Err(e) => e.into_outcome(),
        };

        let conn = body.finalize().await?;
        write_outcome(response_writer, conn, outcome).await
    }
}

async fn route<const INSTALL: bool, R: Read>(
    method: &str,
    path: &str,
    parts: RequestParts<'_>,
    body: &mut RequestBodyConnection<'_, R>,
) -> Result<Outcome, HttpError> {
    if INSTALL {
        return install_route(method, path);
    }

    match path {
        "/api/health" => {
            method_is(method, "GET")?;
            return Ok(health());
        }
        "/api/pki/info" => {
            method_is(method, "GET")?;
            return pki_info();
        }
        "/ca.pem" => {
            method_is(method, "GET")?;
            return ca_pem();
        }
        "/ca.crt" => {
            method_is(method, "GET")?;
            return ca_der();
        }
        "/api/auth/state" => {
            method_is(method, "GET")?;
            return Ok(auth_state());
        }
        "/api/auth/provision" => {
            method_is(method, "POST")?;
            return provision(parts, body).await;
        }
        "/api/auth/unlock" => {
            method_is(method, "POST")?;
            return unlock(parts, body).await;
        }
        "/api/auth/lock" => {
            method_is(method, "POST")?;
            return lock(parts).await;
        }
        "/api/auth/session" => {
            method_is(method, "GET")?;
            return session(parts);
        }
        "/api/auth/reset" => {
            method_is(method, "POST")?;
            return reset(parts, body).await;
        }
        "/api/auth/rekey" => {
            method_is(method, "POST")?;
            return rekey(parts, body).await;
        }
        "/api/auth/password" => {
            method_is(method, "GET")?;
            return password(parts).await;
        }
        "/api/export" => {
            method_is(method, "GET")?;
            return export(parts).await;
        }
        "/api/import" => {
            method_is(method, "POST")?;
            return import(parts, body).await;
        }
        "/api/entries" => {
            return match method {
                "GET" => entries_list(parts).await,
                "POST" => entries_write(path, parts, body).await,
                _ => Err(method_not_allowed()),
            };
        }
        _ => {}
    }

    if let Some(rest) = path.strip_prefix("/api/auth/job/") {
        let well_formed = !rest.is_empty() && !rest.contains('/');
        if well_formed {
            if method == "GET" {
                return job_poll(path);
            }
            return Err(method_not_allowed());
        }
    }

    if path.starts_with("/api/entries/") {
        match method {
            "GET" => return entries_get(path, parts).await,
            "POST" => return entries_write(path, parts, body).await,
            "DELETE" => return entries_delete(path, parts, body).await,
            _ => return Err(method_not_allowed()),
        }
    }

    // Static SPA: only GET reaches here.
    if method != "GET" {
        return Err(method_not_allowed());
    }
    Ok(static_asset(path))
}

/// Plain-HTTP subset: only the certificate-install flow. Anything outside it is
/// an empty 404 so a browser sees no API surface until the CA is trusted.
fn install_route(method: &str, path: &str) -> Result<Outcome, HttpError> {
    match path {
        "/" | "/index.html" | "/install.html" => {
            method_is(method, "GET")?;
            Ok(install_page())
        }
        "/ca.pem" => {
            method_is(method, "GET")?;
            ca_pem()
        }
        "/ca.crt" => {
            method_is(method, "GET")?;
            ca_der()
        }
        "/api/pki/info" => {
            method_is(method, "GET")?;
            pki_info()
        }
        _ => Ok(Outcome::Empty { status: 404 }),
    }
}

fn install_page() -> Outcome {
    Outcome::Static {
        bytes: web::install_page(),
        mime: "text/html; charset=utf-8",
    }
}

fn method_is(method: &str, expected: &str) -> Result<(), HttpError> {
    if method == expected {
        Ok(())
    } else {
        Err(method_not_allowed())
    }
}

fn static_asset(path: &str) -> Outcome {
    match web::open(path) {
        Some(asset) => Outcome::Static {
            bytes: asset.bytes,
            mime: web::mime_for(asset.name),
        },
        // httpd's own 404 body is not reproduced; an empty 404 is enough for
        // the SPA to detect a missing asset.
        None => Outcome::Empty { status: 404 },
    }
}

// ── Request helpers ──────────────────────────────────────────────────────────

fn header<'a>(parts: RequestParts<'a>, name: &str) -> Option<&'a str> {
    parts.headers().get(name).and_then(|v| v.as_str().ok())
}

fn content_type_is_json(parts: RequestParts<'_>) -> bool {
    let Some(ct) = header(parts, "Content-Type") else {
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

async fn read_json_body<R: Read>(
    parts: RequestParts<'_>,
    body: &mut RequestBodyConnection<'_, R>,
) -> Result<Value, HttpError> {
    if !content_type_is_json(parts) {
        return Err(HttpError {
            status: 415,
            code: "json_content_type_required",
        });
    }
    if header(parts, "Transfer-Encoding").is_some() {
        // picoserve cannot decode chunked bodies and would read the length as 0.
        // The reference rejects unknown-length bodies with 411, so match it.
        return Err(HttpError {
            status: 411,
            code: "content_length_required",
        });
    }
    let len = body.content_length();
    if len == 0 {
        return Err(bad_request("empty_body"));
    }
    if len > MAX_BODY {
        return Err(HttpError {
            status: 413,
            code: "body_too_large",
        });
    }

    let mut buf = vec![0u8; len];
    let mut got = 0;
    {
        let mut reader = body.body().reader();
        while got < len {
            match reader.read(&mut buf[got..]).await {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(_) => {
                    pm_core::crypto::wipe(&mut buf);
                    return Err(HttpError {
                        status: 408,
                        code: "body_read_timeout",
                    });
                }
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
fn require_session(parts: RequestParts<'_>) -> Result<(), HttpError> {
    let Some(tok) = header(parts, "X-PM-Session") else {
        return Err(unauthorized());
    };
    if tok.len() != SESSION_TOKEN_HEX_LEN || !authsvc::session_valid(tok) {
        return Err(unauthorized());
    }
    Ok(())
}

fn require_same_origin(parts: RequestParts<'_>) -> Result<(), HttpError> {
    if !origin_matches_host(parts) {
        return Err(HttpError {
            status: 403,
            code: "cross_origin_refused",
        });
    }
    if !sec_fetch_site_allowed(parts) {
        return Err(HttpError {
            status: 403,
            code: "cross_site_refused",
        });
    }
    if !host_is_device(parts) {
        return Err(HttpError {
            status: 403,
            code: "host_refused",
        });
    }
    Ok(())
}

/// `Origin`, when present, must name the same host as `Host`. Missing `Origin`
/// (curl, tests) is allowed.
fn origin_matches_host(parts: RequestParts<'_>) -> bool {
    let Some(origin) = header(parts, "Origin") else {
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
    let Some(hdr) = header(parts, "Host") else {
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
fn sec_fetch_site_allowed(parts: RequestParts<'_>) -> bool {
    let Some(value) = header(parts, "Sec-Fetch-Site") else {
        return true;
    };
    if value.len() >= 32 {
        return false;
    }
    value.eq_ignore_ascii_case("same-origin") || value.eq_ignore_ascii_case("none")
}

/// `Host` must be a numeric address of this device.
fn host_is_device(parts: RequestParts<'_>) -> bool {
    let Some(hdr) = header(parts, "Host") else {
        return false;
    };
    if hdr.len() >= 80 {
        return false;
    }
    let host = hdr.split(':').next().unwrap_or("");
    if host.is_empty() || host.len() >= 16 {
        return false;
    }
    parse_ipv4(host).is_some_and(|got| got == DEVICE_IP)
}

/// Strict `a.b.c.d` parse: four parts, each 0..=255, no leading junk.
fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut parts = s.split('.');
    for slot in &mut out {
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
    if b64.len() % 4 != 0 {
        return Err(bad_request("keyfile_invalid_base64"));
    }
    if (b64.len() / 4) * 3 > pm_core::config::KEYFILE_MAX_BYTES {
        return Err(bad_request("keyfile_too_large"));
    }
    match pm_core::base64::decode(b64) {
        Some(bytes) if bytes.is_empty() => Ok(Vec::new()),
        Some(bytes) => Ok(bytes),
        None => Err(bad_request("keyfile_invalid_base64")),
    }
}

fn parse_job_id(path: &str) -> Option<JobId> {
    let rest = path.strip_prefix("/api/auth/job/")?;
    let seg = rest.split('/').next().unwrap_or("");
    if seg.len() != 16 {
        return None;
    }
    u64::from_str_radix(seg, 16).ok().filter(|&v| v != NO_JOB)
}

fn job_error_outcome(result: JobResult) -> Outcome {
    let e = match result {
        JobResult::Busy => busy(),
        JobResult::WrongPassword => HttpError {
            status: 401,
            code: "wrong_password",
        },
        JobResult::Refused => conflict("refused"),
        JobResult::Lockout => HttpError {
            status: 429,
            code: "lockout",
        },
        JobResult::Error => internal("worker_error"),
        JobResult::Pending | JobResult::Ok => internal("unknown_result"),
    };
    e.into_outcome()
}

/// 202 Accepted with the job id as 16 hex chars (never a JSON number: 64 bits
/// do not fit a double).
fn job_accepted(id: JobId) -> Outcome {
    json_outcome(202, json!({"ok": true, "job": format!("{id:016x}")}))
}

// ── Entries / export / import helpers ────────────────────────────────────────

/// One of the entry routes encoded by `/api/entries*`.
enum EntryRoute {
    Item(u32),
    Secret(u32),
    Totp(u32),
}

/// Splits `/api/entries/*` into an [`EntryRoute`]. A strict numeric id (never
/// `0`) is required, so a typo cannot silently mean "create".
fn entry_route(path: &str) -> Option<EntryRoute> {
    let rest = path.strip_prefix("/api/entries/")?;
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
fn query_time(query: &str) -> Option<u32> {
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
        Ok(s) => s.to_string(),
        Err(()) => String::new(),
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
    for (key, field) in pm_core::entry::FIELD_KEYS {
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
            .is_some_and(pm_core::totp::is_valid_secret);
        if !ok {
            return Err(bad_request("totp_secret_invalid"));
        }
    }
    if pm_core::totp::resolve_digits(e.get(Field::TotpDigits)).is_none() {
        return Err(bad_request("totp_digits_invalid"));
    }
    if pm_core::totp::resolve_period(e.get(Field::TotpPeriod)).is_none() {
        return Err(bad_request("totp_period_invalid"));
    }
    Ok(())
}

/// `GET /api/entries/{id}` body.
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
        "totpDigits": field_checked(e, Field::TotpDigits)?,
        "totpPeriod": field_checked(e, Field::TotpPeriod)?,
        "hasPassword": !e.get(Field::Password).is_empty(),
        "hasTotp": !e.get(Field::Totp).is_empty(),
    }))
}

// ── Handlers ─────────────────────────────────────────────────────────────────

fn health() -> Outcome {
    let total_kb = web::total_bytes() >> 10;
    json_outcome(
        200,
        json!({
            "ok": true,
            "fw": pm_core::config::FIRMWARE_VERSION,
            "uptime_ms": now_ms(),
            "in_flight": IN_FLIGHT.load(Ordering::Relaxed),
            "max_sessions": MAX_SESSIONS,
            "requests": REQUESTS.load(Ordering::Relaxed),
            "web_used_kb": total_kb,
            "web_total_kb": total_kb,
        }),
    )
}

/// The root CA as PEM, for browser and OS trust imports.
fn ca_pem() -> Result<Outcome, HttpError> {
    let Some(der) = tls::ca_cert_der() else {
        return Err(internal("ca_unavailable"));
    };
    let body = pm_core::pki::pem("CERTIFICATE", &der).into_bytes();
    Ok(Outcome::Download {
        body,
        content_type: "application/x-pem-file",
        disposition: "attachment; filename=\"QuipuChip-CA.pem\"",
    })
}

/// The root CA as DER, for importers that expect a `.crt` binary.
fn ca_der() -> Result<Outcome, HttpError> {
    let Some(der) = tls::ca_cert_der() else {
        return Err(internal("ca_unavailable"));
    };
    Ok(Outcome::Download {
        body: der,
        content_type: "application/x-x509-ca-cert",
        disposition: "attachment; filename=\"QuipuChip-CA.crt\"",
    })
}

/// Formats an IPv4 address as dotted decimal, for the certificate SAN shown to
/// the user.
fn ipv4_dotted(ip: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

/// Identity of the served certificate, for the UI to show and verify.
fn pki_info() -> Result<Outcome, HttpError> {
    let Some(der) = tls::ca_cert_der() else {
        return Err(internal("ca_unavailable"));
    };
    let sha256 = pm_core::hex::encode(&pm_core::crypto::sha256(&der));
    Ok(json_outcome(
        200,
        json!({
            "ok": true,
            "caCommonName": pm_core::config::TLS_CA_CN,
            "leafCommonName": pm_core::config::TLS_LEAF_CN,
            "san": ipv4_dotted(DEVICE_IP),
            "notBeforeUnix": pm_core::config::TLS_VALID_FROM_UNIX,
            "notAfterUnix": pm_core::config::TLS_VALID_UNTIL_UNIX,
            "sha256": sha256,
        }),
    ))
}

fn auth_state() -> Outcome {
    let s = authsvc::state();
    json_outcome(
        200,
        json!({
            "ok": true,
            "provisioned": s.provisioned,
            "unlocked": s.unlocked,
            "busy": s.busy,
            "failCount": s.fail_count,
            "lockoutMsLeft": s.lockout_ms_left,
            "keyfileRequired": authsvc::key_file_required(),
            "masterPasswordChars": pm_core::config::MASTER_PASSWORD_CHARS,
            "maxEntryCount": pm_core::config::MAX_ENTRIES,
            "keyFileMaxBytes": pm_core::config::KEYFILE_MAX_BYTES,
        }),
    )
}

async fn provision<R: Read>(
    parts: RequestParts<'_>,
    body: &mut RequestBodyConnection<'_, R>,
) -> Result<Outcome, HttpError> {
    require_same_origin(parts)?;

    // Refuse before reading the body: a second provisioning over a non-empty
    // partition wipes it.
    let s = authsvc::state();
    if s.provisioned {
        log::warn!("http: provision refused, already provisioned");
        return Err(conflict("already_provisioned"));
    }
    if s.unlocked {
        log::error!("http: provision refused, unprovisioned but unlocked");
        return Err(conflict("inconsistent_state"));
    }

    let (key_file, generate_keyfile) = if body.content_length() > 0 {
        let doc = read_json_body(parts, body).await?;
        let key_file = keyfile_field(&doc, "keyfile")?;
        let generate = match doc.get("generate_keyfile") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => return Err(bad_request("generate_keyfile_not_a_bool")),
        };
        // One source only: a client-supplied file and a device-generated one
        // cannot both define the key.
        if generate && !key_file.is_empty() {
            return Err(bad_request("keyfile_conflict"));
        }
        (key_file, generate)
    } else {
        (Vec::new(), false)
    };

    let id = authsvc::submit_provision(key_file, generate_keyfile).await;
    if id == NO_JOB {
        return Err(busy());
    }
    log::info!("http: provisioning requested");
    Ok(job_accepted(id))
}

async fn unlock<R: Read>(
    parts: RequestParts<'_>,
    body: &mut RequestBodyConnection<'_, R>,
) -> Result<Outcome, HttpError> {
    require_same_origin(parts)?;

    // Refuse before the body: unlocking a vault that was never provisioned is
    // a client mistake, not a password check. Running the KDF against an empty
    // partition would burn the full PBKDF2 time and then fail with a vague 500.
    let s = authsvc::state();
    if !s.provisioned {
        log::warn!("http: unlock refused, unprovisioned");
        return Err(conflict("unprovisioned"));
    }

    let doc = read_json_body(parts, body).await?;
    let Some(password) = doc.get("password").and_then(Value::as_str) else {
        return Err(bad_request("password_required"));
    };
    let n = password.len();
    if !(pm_core::config::MIN_PASS_CHARS..pm_core::config::MAX_PASS_CHARS).contains(&n) {
        log::warn!("http: unlock rejected, password length {n} out of range");
        return Err(bad_request("password_length_out_of_range"));
    }
    let key_file = keyfile_field(&doc, "keyfile")?;

    let id = authsvc::submit_unlock(password.as_bytes().to_vec(), key_file).await;
    if id == NO_JOB {
        return Err(busy());
    }
    log::info!("http: unlock requested");
    Ok(job_accepted(id))
}

fn job_poll(path: &str) -> Result<Outcome, HttpError> {
    let Some(id) = parse_job_id(path) else {
        return Err(bad_request("bad_job_id"));
    };
    let Some(view) = authsvc::poll(id) else {
        return Err(not_found("unknown_job"));
    };

    if view.result == JobResult::Pending {
        return Ok(json_outcome(200, json!({"ok": true, "state": "pending"})));
    }
    if view.result != JobResult::Ok {
        return Ok(job_error_outcome(view.result));
    }

    let mut body = json!({
        "ok": true,
        "result": "ok",
        "job": view.kind.as_str(),
    });
    if view.kind == Job::Provision {
        match core::str::from_utf8(&view.password) {
            Ok(pw) if !pw.is_empty() => body["password"] = Value::String(pw.to_string()),
            _ => {}
        }
    }
    match core::str::from_utf8(&view.session_token) {
        Ok(tok) if !tok.is_empty() => body["session_token"] = Value::String(tok.to_string()),
        _ => {}
    }
    if !view.key_file.is_empty() {
        body["keyfile"] = Value::String(pm_core::base64::encode(&view.key_file));
    }
    Ok(json_outcome(200, body))
}

async fn lock(parts: RequestParts<'_>) -> Result<Outcome, HttpError> {
    require_same_origin(parts)?;
    require_session(parts)?;
    // A session implies an unlocked vault, so this defends against future
    // session-semantics drift rather than today's reachable states.
    if !authsvc::state().unlocked {
        return Err(conflict("not_unlocked"));
    }
    if !authsvc::lock().await {
        return Err(internal("lock_failed"));
    }
    Ok(json_outcome(200, json!({"ok": true, "unlocked": false})))
}

fn session(parts: RequestParts<'_>) -> Result<Outcome, HttpError> {
    require_session(parts)?;
    let Some(token) = authsvc::session_token_hex() else {
        log::error!("http: session valid but token unreadable");
        return Err(internal("token_unavailable"));
    };
    let s = authsvc::state();
    let entry_count = if s.provisioned && s.unlocked {
        authsvc::entry_count()
    } else {
        0
    };
    Ok(json_outcome(
        200,
        json!({
            "ok": true,
            "token": token,
            "expiresInMs": pm_core::config::SESSION_TTL_MS,
            "entryCount": entry_count,
        }),
    ))
}

async fn reset<R: Read>(
    parts: RequestParts<'_>,
    body: &mut RequestBodyConnection<'_, R>,
) -> Result<Outcome, HttpError> {
    require_same_origin(parts)?;
    // Reset is deliberately *not* session-gated: the owner needs a factory
    // reset to work from the locked screen (e.g. a forgotten master password
    // makes a valid session unreachable by design). The remaining barriers are
    // the explicit RESET confirmation and the busy gate. Accepted trade-off:
    // any process with USB/HTTP access to the device can wipe the vault.

    let doc = read_json_body(parts, body).await?;
    if doc.get("confirm").and_then(Value::as_str) != Some("RESET") {
        log::warn!("http: reset refused, no confirmation");
        return Err(bad_request("confirmation_required"));
    }

    let id = authsvc::submit_reset().await;
    if id == NO_JOB {
        return Err(busy());
    }
    log::warn!("http: vault reset requested");
    Ok(job_accepted(id))
}

async fn rekey<R: Read>(
    parts: RequestParts<'_>,
    body: &mut RequestBodyConnection<'_, R>,
) -> Result<Outcome, HttpError> {
    require_same_origin(parts)?;
    require_session(parts)?;
    // A session implies an unlocked vault; kept explicit so the route reads as
    // "re-encrypt an open vault", whatever future session changes do.
    if !authsvc::state().unlocked {
        return Err(conflict("not_unlocked"));
    }

    let doc = read_json_body(parts, body).await?;
    let Some(old) = doc.get("old_password").and_then(Value::as_str) else {
        return Err(bad_request("old_password_required"));
    };
    let old_len = old.len();
    if !(pm_core::config::MIN_PASS_CHARS..pm_core::config::MAX_PASS_CHARS).contains(&old_len) {
        log::warn!("http: rekey rejected, old password length {old_len} out of range");
        return Err(bad_request("old_password_length_out_of_range"));
    }

    let new_password = match doc.get("password") {
        None | Some(Value::Null) => None,
        Some(Value::String(np)) if np.is_empty() => None,
        Some(Value::String(np)) => {
            let n = np.len();
            if !(pm_core::config::MIN_PASS_CHARS..pm_core::config::MAX_PASS_CHARS).contains(&n) {
                return Err(bad_request("password_length_out_of_range"));
            }
            Some(np.as_bytes().to_vec())
        }
        Some(_) => return Err(bad_request("password_not_a_string")),
    };

    let cur_key_file = if authsvc::key_file_required() {
        match keyfile_field(&doc, "keyfile_current") {
            Ok(kf) if !kf.is_empty() => kf,
            Ok(_) => return Err(bad_request("keyfile_current_required")),
            Err(e) => return Err(e),
        }
    } else {
        Vec::new()
    };

    let action = match doc.get("keyfile_action") {
        None | Some(Value::Null) => KeyfileAction::Keep,
        Some(Value::String(a)) if a == "keep" => KeyfileAction::Keep,
        Some(Value::String(a)) if a == "set" => KeyfileAction::Set,
        Some(Value::String(a)) if a == "clear" => KeyfileAction::Clear,
        Some(Value::String(a)) if a == "generate" => KeyfileAction::Generate,
        Some(_) => return Err(bad_request("keyfile_action_invalid")),
    };

    let new_key_file = if action == KeyfileAction::Set {
        match keyfile_field(&doc, "keyfile_new") {
            Ok(kf) if !kf.is_empty() => kf,
            Ok(_) => return Err(bad_request("keyfile_new_required")),
            Err(e) => return Err(e),
        }
    } else {
        Vec::new()
    };

    if new_password.is_none() && action == KeyfileAction::Keep {
        return Err(bad_request("nothing_to_change"));
    }

    let id = authsvc::submit_rekey(
        old.as_bytes().to_vec(),
        new_password,
        cur_key_file,
        new_key_file,
        action,
    )
    .await;
    if id == NO_JOB {
        return Err(busy());
    }
    log::info!("http: master password and/or keyfile change requested");
    Ok(job_accepted(id))
}

async fn password(parts: RequestParts<'_>) -> Result<Outcome, HttpError> {
    require_session(parts)?;
    let password = authsvc::generate_master_password().await;
    Ok(json_outcome(200, json!({"ok": true, "password": password})))
}

async fn entries_list(parts: RequestParts<'_>) -> Result<Outcome, HttpError> {
    require_session(parts)?;
    let entries = match authsvc::entries_list().await {
        Ok(v) => v,
        Err(err) => {
            log::error!("http: vault load failed: {}", err.as_str());
            return Err(internal("vault_load_failed"));
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
                "hasPassword": !e.get(Field::Password).is_empty(),
                "hasTotp": !e.get(Field::Totp).is_empty(),
            })
        })
        .collect();
    Ok(json_outcome(
        200,
        json!({"ok": true, "count": list.len(), "entries": list}),
    ))
}

async fn entries_write<R: Read>(
    path: &str,
    parts: RequestParts<'_>,
    body: &mut RequestBodyConnection<'_, R>,
) -> Result<Outcome, HttpError> {
    require_same_origin(parts)?;
    require_session(parts)?;

    // A path without a numeric tail is a create only on the exact collection
    // path; anything else is a typo, not "id 0".
    let (id, is_create) = match entry_route(path) {
        Some(EntryRoute::Item(id)) => (id, false),
        _ => {
            // `/api/entries` (create) is routed here too, but `entry_route`
            // only matches the `/api/entries/{id}` form; a collection create
            // is signalled by the caller passing `id == 0`.
            if path == "/api/entries" {
                (0u32, true)
            } else {
                return Err(bad_request("bad_entry_id"));
            }
        }
    };

    let doc = read_json_body(parts, body).await?;
    let mut entry = Entry::new();
    entry.id = id;
    fill_entry(&doc, &mut entry)?;

    match authsvc::entry_write(id, &entry).await {
        Ok(new_id) => {
            let status = if is_create { 201 } else { 200 };
            Ok(json_outcome(status, json!({"ok": true, "id": new_id})))
        }
        Err(VaultError::NotFound) => Err(not_found("entry_not_found")),
        Err(e) => {
            log::error!("http: vault add failed: {}", e.as_str());
            Err(add_error(e))
        }
    }
}

async fn entries_get(path: &str, parts: RequestParts<'_>) -> Result<Outcome, HttpError> {
    require_session(parts)?;
    match entry_route(path) {
        Some(EntryRoute::Item(id)) => entry_detail(id).await,
        Some(EntryRoute::Secret(id)) => entry_secret(id).await,
        Some(EntryRoute::Totp(id)) => entry_totp(id, parts).await,
        _ => Err(bad_request("bad_entry_id")),
    }
}

async fn entry_detail(id: u32) -> Result<Outcome, HttpError> {
    let e = match authsvc::entry_get(id).await {
        Ok(e) => e,
        Err(VaultError::NotFound) => return Err(not_found("entry_not_found")),
        Err(err) => {
            log::error!("http: vault get failed: {}", err.as_str());
            return Err(internal("vault_get_failed"));
        }
    };
    if let Ok(body) = detail_body(&e) {
        Ok(json_outcome(200, body))
    } else {
        log::warn!("http: entry {id} has unterminated field");
        Err(internal("entry_field_unterminated"))
    }
}

async fn entry_secret(id: u32) -> Result<Outcome, HttpError> {
    let e = match authsvc::entry_get(id).await {
        Ok(e) => e,
        Err(VaultError::NotFound) => return Err(not_found("entry_not_found")),
        Err(err) => {
            log::error!("http: vault get failed: {}", err.as_str());
            return Err(internal("vault_get_failed"));
        }
    };
    let Ok(password) = field_checked(&e, Field::Password) else {
        log::warn!("http: entry {id} password unterminated");
        return Err(internal("entry_field_unterminated"));
    };
    Ok(json_outcome(
        200,
        json!({"ok": true, "id": e.id, "password": password}),
    ))
}

async fn entry_totp(id: u32, parts: RequestParts<'_>) -> Result<Outcome, HttpError> {
    let Some(query) = parts.query() else {
        return Err(bad_request("time_required"));
    };
    let Some(when) = query_time(query.0) else {
        return Err(bad_request("time_required"));
    };
    let e = match authsvc::entry_get(id).await {
        Ok(e) => e,
        Err(VaultError::NotFound) => return Err(not_found("entry_not_found")),
        Err(err) => {
            log::error!("http: vault get failed: {}", err.as_str());
            return Err(internal("vault_get_failed"));
        }
    };
    if e.get(Field::Totp).is_empty() {
        return Err(conflict("totp_not_configured"));
    }
    let Ok(secret) = core::str::from_utf8(e.get(Field::Totp)) else {
        log::error!("http: entry {id} totp secret unusable");
        return Err(internal("totp_secret_invalid"));
    };
    // Digits/period passed validation at write time; a failure here is
    // corruption, not user error.
    let (Some(digits), Some(period)) = (
        pm_core::totp::resolve_digits(e.get(Field::TotpDigits)),
        pm_core::totp::resolve_period(e.get(Field::TotpPeriod)),
    ) else {
        log::error!("http: entry {id} totp parameters unusable");
        return Err(internal("totp_params_invalid"));
    };
    let Ok(code) = pm_core::totp::compute(secret, u64::from(when), digits, period) else {
        log::error!("http: entry {id} totp secret unusable");
        return Err(internal("totp_secret_invalid"));
    };
    Ok(json_outcome(
        200,
        json!({
            "ok": true,
            "code": code,
            "digits": digits,
            "periodSec": period,
            "expiresInSec": period - (u64::from(when) % period),
        }),
    ))
}

async fn entries_delete<R: Read>(
    path: &str,
    parts: RequestParts<'_>,
    body: &mut RequestBodyConnection<'_, R>,
) -> Result<Outcome, HttpError> {
    require_same_origin(parts)?;
    require_session(parts)?;
    let Some(EntryRoute::Item(id)) = entry_route(path) else {
        return Err(bad_request("bad_entry_id"));
    };

    // Deletion is irreversible, so it needs the same explicit confirmation as a
    // vault reset — a missing body is a missing confirmation.
    if body.content_length() == 0 {
        log::warn!("http: delete refused, no confirmation");
        return Err(bad_request("confirmation_required"));
    }
    let doc = read_json_body(parts, body).await?;
    if doc.get("confirm").and_then(Value::as_str) != Some("DELETE") {
        return Err(bad_request("confirmation_required"));
    }

    match authsvc::entry_remove(id).await {
        Ok(()) => {
            log::info!("http: entry {id} deleted");
            Ok(json_outcome(200, json!({"ok": true, "id": id})))
        }
        Err(VaultError::NotFound) => Err(not_found("entry_not_found")),
        Err(err) => {
            log::error!("http: vault remove failed: {}", err.as_str());
            Err(internal("vault_remove_failed"))
        }
    }
}

async fn export(parts: RequestParts<'_>) -> Result<Outcome, HttpError> {
    require_session(parts)?;
    let entries = match authsvc::entries_list().await {
        Ok(v) => v,
        Err(err) => {
            log::error!("http: vault load failed: {}", err.as_str());
            return Err(internal("vault_load_failed"));
        }
    };
    let document = export::export_document(&entries);
    log::info!("http: exported {} entries", entries.len());
    Ok(Outcome::Export(document.into_bytes()))
}

async fn import<R: Read>(
    parts: RequestParts<'_>,
    body: &mut RequestBodyConnection<'_, R>,
) -> Result<Outcome, HttpError> {
    require_same_origin(parts)?;
    require_session(parts)?;
    let doc = read_json_body(parts, body).await?;
    // Every record is validated before a single one is written.
    let entries = match export::parse_import(&doc) {
        Ok(v) => v,
        Err(e) => {
            log::warn!("http: import refused: {}", e.code());
            return Err(bad_request(e.code()));
        }
    };
    let outcome = authsvc::import_batch(entries).await;
    match outcome.error {
        None => {
            log::info!("http: imported {} entries", outcome.added);
            Ok(json_outcome(
                200,
                json!({"ok": true, "imported": outcome.added}),
            ))
        }
        Some(err) => {
            // Records already added are kept: rolling back good records for a
            // bad one would lose data the client believes landed.
            let he = add_error(err);
            log::error!("http: import stopped at {}: {}", outcome.added, he.code);
            Ok(json_outcome(
                he.status,
                json!({"ok": false, "error": he.code, "imported": outcome.added}),
            ))
        }
    }
}
