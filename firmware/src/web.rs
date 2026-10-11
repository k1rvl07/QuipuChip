//! Read-only access to the static SPA assets stored in the `web` partition.
//!
//! The partition holds a LittleFS image built from `data/` by
//! `scripts/build_webfs.py` (page 256, block 4096). It is mounted through the
//! VFS at [`WEB_BASE`], so files are opened with their full VFS path
//! (`/web/index.html`) rather than the bare partition-relative name.

use std::fs::File;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use esp_idf_svc::fs::littlefs::Littlefs;
use esp_idf_svc::io::vfs::MountedLittlefs;
use esp_idf_svc::sys::EspError;

use crate::static_cell::StaticCell;

/// Partition label, matching `partitions.csv` and `config::kFsWeb`.
const WEB_LABEL: &str = "web";
/// VFS mount point, matching `config::kFsWebBase`.
const WEB_BASE: &str = "/web";
/// File served for the root request, matching `config::kIndexHtml`.
const INDEX_FILE: &str = "index.html";
/// Longest accepted normalized path, matching `config::kWebPathMax`.
const PATH_MAX: usize = 256;

/// The mounted filesystem. The concrete `T` is `Littlefs<()>` (a label-based
/// partition carries no other state).
type Fs = MountedLittlefs<Littlefs<()>>;

/// Holds the mounted filesystem for the lifetime of the program; dropping it
/// would unregister the VFS. Only ever written once, before any reader runs.
static FS: StaticCell<Option<Fs>> = StaticCell::new(None);
static MOUNTED: AtomicBool = AtomicBool::new(false);
static TOTAL_BYTES: AtomicU32 = AtomicU32::new(0);
static USED_BYTES: AtomicU32 = AtomicU32::new(0);

/// Mounts the `web` partition if it is not mounted yet.
///
/// A failure is not fatal: the HTTP server still starts and answers `/api/*`;
/// static requests honestly return 404 until a valid image is flashed.
pub fn mount() -> Result<(), EspError> {
    if MOUNTED.load(Ordering::Acquire) {
        return Ok(());
    }

    // SAFETY: `web` is a valid, dedicated partition and is not touched by any
    // other filesystem while mounted.
    let littlefs = unsafe { Littlefs::<()>::new_partition(WEB_LABEL)? };
    let mounted = MountedLittlefs::mount(littlefs, WEB_BASE)?;

    let (total, used) = match mounted.info() {
        Ok(info) => (info.total_bytes as u32, info.used_bytes as u32),
        Err(e) => {
            log::warn!("web: info unavailable: {e}");
            (0, 0)
        }
    };

    // SAFETY: single-threaded initialisation; the slot is written exactly once
    // (guarded by `MOUNTED`) and never mutated afterwards.
    unsafe { *FS.get() = Some(mounted) };

    TOTAL_BYTES.store(total, Ordering::Relaxed);
    USED_BYTES.store(used, Ordering::Relaxed);
    MOUNTED.store(true, Ordering::Release);

    log::info!(
        "web mounted at {WEB_BASE}, {} KB total, {} KB used",
        total >> 10,
        used >> 10
    );
    Ok(())
}

pub fn mounted() -> bool {
    MOUNTED.load(Ordering::Acquire)
}

pub fn total_bytes() -> u32 {
    TOTAL_BYTES.load(Ordering::Relaxed)
}

pub fn used_bytes() -> u32 {
    USED_BYTES.load(Ordering::Relaxed)
}

/// A single readable asset from the `web` partition.
pub struct Asset {
    pub file: File,
    /// Normalized partition-relative name (no leading slash, no query), used to
    /// pick the MIME type.
    pub name: String,
}

/// Opens `rel` (a request path, with or without a leading slash and query
/// string) as a readable asset, or `None` if it cannot be served.
pub fn open(rel: &str) -> Option<Asset> {
    if !mounted() {
        return None;
    }

    let name = normalize(rel)?;
    let full = format!("{WEB_BASE}/{name}");

    let file = File::open(&full).ok()?;
    if file.metadata().ok()?.is_dir() {
        return None;
    }
    Some(Asset { file, name })
}

/// Maps a normalized path to its Content-Type, by extension.
pub fn mime_for(path: &str) -> &'static str {
    let ext = match path.rsplit_once('.') {
        Some((_, ext)) => ext,
        None => return OCTET_STREAM,
    };

    const MIMES: &[(&str, &str)] = &[
        ("html", "text/html; charset=utf-8"),
        ("htm", "text/html; charset=utf-8"),
        ("js", "application/javascript; charset=utf-8"),
        ("mjs", "application/javascript; charset=utf-8"),
        ("css", "text/css; charset=utf-8"),
        ("json", "application/json"),
        ("svg", "image/svg+xml"),
        ("png", "image/png"),
        ("jpg", "image/jpeg"),
        ("jpeg", "image/jpeg"),
        ("gif", "image/gif"),
        ("ico", "image/vnd.microsoft.icon"),
        ("woff2", "font/woff2"),
        ("woff", "font/woff"),
        ("txt", "text/plain; charset=utf-8"),
        ("map", "application/json"),
    ];

    for (name, ty) in MIMES {
        if ext.eq_ignore_ascii_case(name) {
            return ty;
        }
    }
    OCTET_STREAM
}

const OCTET_STREAM: &str = "application/octet-stream";

/// Turns a request path into a partition-relative file name, or `None` if it
/// must be rejected.
///
/// Rules are intentionally stricter than LittleFS requires: a `..` segment is
/// refused outright instead of being resolved, and control bytes (including
/// NUL) are refused so a shorter prefix cannot pass validation while a longer
/// body slips past it. The query string is dropped first. Percent-encoding is
/// deliberately *not* decoded, so an encoded `%2e%2e` simply fails to name a
/// file rather than becoming a real `..`.
fn normalize(rel: &str) -> Option<String> {
    let path = rel.split('?').next().unwrap_or("");
    let trimmed = path.trim_start_matches('/');
    let path = if trimmed.is_empty() {
        INDEX_FILE
    } else {
        trimmed
    };

    let mut out = String::with_capacity(path.len());
    for seg in path.split('/') {
        if seg == ".." {
            return None;
        }
        // "." and empty segments (from repeated slashes) are dropped.
        if seg.is_empty() || seg == "." {
            continue;
        }
        if !out.is_empty() {
            out.push('/');
        }
        for &byte in seg.as_bytes() {
            if byte < 0x20 || byte == 0x7F {
                return None;
            }
        }
        out.push_str(seg);
        if out.len() + 1 > PATH_MAX {
            return None;
        }
    }

    if out.is_empty() {
        return None;
    }
    Some(out)
}
