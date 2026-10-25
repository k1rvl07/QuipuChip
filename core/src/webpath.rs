//! Static path normalization and MIME types for the embedded SPA.
//!
//! Rules match the firmware reference: split on `?`, trim leading `/`, map
//! empty/`/` to `index.html`, drop `.` and `//`, reject `..` and control
//! characters, cap length at 256.

use alloc::string::String;

const INDEX_FILE: &str = "index.html";
/// Longest accepted normalized path.
pub const PATH_MAX: usize = 256;

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

const OCTET_STREAM: &str = "application/octet-stream";

/// Maps a normalized path to its Content-Type, by extension.
#[must_use]
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

/// Turns a request path into a bundle-relative name, or `None` if it must be
/// rejected.
#[must_use]
pub fn normalize(rel: &str) -> Option<String> {
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
        if out.len() > PATH_MAX {
            return None;
        }
    }

    if out.is_empty() {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_maps_root_and_slashes() {
        assert_eq!(normalize("/").as_deref(), Some("index.html"));
        assert_eq!(normalize("").as_deref(), Some("index.html"));
        assert_eq!(normalize("/index.html").as_deref(), Some("index.html"));
        assert_eq!(normalize("app.js").as_deref(), Some("app.js"));
        assert_eq!(normalize("/style.css").as_deref(), Some("style.css"));
    }

    #[test]
    fn normalize_strips_query_and_dots() {
        assert_eq!(normalize("/app.js?v=1").as_deref(), Some("app.js"));
        assert_eq!(normalize("/./app.js").as_deref(), Some("app.js"));
        assert_eq!(normalize("//app.js").as_deref(), Some("app.js"));
        assert_eq!(normalize("/dir/../app.js").as_deref(), None);
        assert_eq!(normalize("..").as_deref(), None);
    }

    #[test]
    fn normalize_rejects_control_chars_and_long_paths() {
        assert_eq!(normalize("/bad\x01.js").as_deref(), None);
        let long = "a".repeat(PATH_MAX);
        assert!(normalize(&format!("/{long}")).is_some());
        let over = "a".repeat(PATH_MAX + 1);
        assert!(normalize(&format!("/{over}")).is_none());
    }

    #[test]
    fn mime_for_known_types() {
        assert_eq!(mime_for("index.html"), "text/html; charset=utf-8");
        assert_eq!(mime_for("app.js"), "application/javascript; charset=utf-8");
        assert_eq!(mime_for("style.css"), "text/css; charset=utf-8");
        assert_eq!(
            mime_for("kdbxweb.min.js"),
            "application/javascript; charset=utf-8"
        );
        assert_eq!(mime_for("unknown.xyz"), "application/octet-stream");
        assert_eq!(mime_for("noext"), "application/octet-stream");
    }
}
