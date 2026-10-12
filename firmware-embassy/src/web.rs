//! Static SPA assets, embedded in the firmware image at compile time.
//!
//! The C++/esp-idf reference mounted a LittleFS image from the `web` partition;
//! here the same `data/` bundle is baked in with `include_bytes!`, so there is
//! no filesystem and no mount to fail. Only a handful of well-known names is
//! served, which makes path handling trivial to prove safe: unknown names 404,
//! and `..` segments are refused outright (percent-encoding is deliberately not
//! decoded, so `%2e%2e` simply fails to name a file).

/// One servable asset.
pub struct Asset {
    /// Normalized name, used to pick the MIME type.
    pub name: &'static str,
    pub bytes: &'static [u8],
}

/// The embedded bundle. Mirrors the file set of the reference's `data/`.
const ASSETS: &[(&str, &[u8])] = &[
    ("index.html", include_bytes!("../../data/index.html")),
    ("style.css", include_bytes!("../../data/style.css")),
    ("app.js", include_bytes!("../../data/app.js")),
    ("kdbx-shim.js", include_bytes!("../../data/kdbx-shim.js")),
    (
        "kdbxweb.min.js",
        include_bytes!("../../data/kdbxweb.min.js"),
    ),
];

const INDEX_FILE: &str = "index.html";
/// Longest accepted normalized path, matching `config::kWebPathMax`.
const PATH_MAX: usize = 256;

/// Total embedded asset bytes, for the health probe.
pub fn total_bytes() -> u32 {
    ASSETS.iter().map(|(_, b)| b.len() as u32).sum()
}

/// Opens `rel` (a request path, with or without a leading slash and query
/// string) as an asset, or `None` if it cannot be served.
pub fn open(rel: &str) -> Option<Asset> {
    let name = normalize(rel)?;
    for (n, bytes) in ASSETS {
        if *n == name.as_str() {
            return Some(Asset { name: n, bytes });
        }
    }
    None
}

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

/// Maps a normalized path to its Content-Type, by extension.
pub fn mime_for(path: &str) -> &'static str {
    let Some((_, ext)) = path.rsplit_once('.') else {
        return OCTET_STREAM;
    };

    for (name, ty) in MIMES {
        if ext.eq_ignore_ascii_case(name) {
            return ty;
        }
    }
    OCTET_STREAM
}

const OCTET_STREAM: &str = "application/octet-stream";

/// Turns a request path into a bundle-relative name, or `None` if it must be
/// rejected. Rules match the reference's `normalize`.
fn normalize(rel: &str) -> Option<alloc::string::String> {
    use alloc::string::String;

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
