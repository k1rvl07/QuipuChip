//! Framework-agnostic HTTP API contract tests.

#![cfg(feature = "test-utils")]
#![allow(clippy::unwrap_used)]

use pm_core::api::{ApiResponse, JSON_HEADERS};
use pm_core::export;
use pm_core::webpath;

#[test]
fn json_headers_are_stable() {
    assert_eq!(JSON_HEADERS.len(), 2);
    assert_eq!(JSON_HEADERS[0], ("Cache-Control", "no-store"));
    assert_eq!(JSON_HEADERS[1], ("X-Content-Type-Options", "nosniff"));
}

#[test]
fn api_response_json_has_headers() {
    let resp = ApiResponse::json(200, &serde_json::json!({"ok": true}));
    assert_eq!(resp.status, 200);
    assert_eq!(resp.content_type, "application/json");
    assert!(
        resp.headers
            .iter()
            .any(|(k, v)| k == "Cache-Control" && v == "no-store")
    );
}

#[test]
fn api_response_static_asset() {
    let resp = ApiResponse::static_asset(b"hello", "text/plain");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"hello");
}

#[test]
fn webpath_normalize_mirrors_contract() {
    assert_eq!(webpath::normalize("/").as_deref(), Some("index.html"));
    assert_eq!(webpath::normalize("/app.js").as_deref(), Some("app.js"));
    assert_eq!(webpath::normalize("/../x").as_deref(), None);
    assert_eq!(webpath::mime_for("style.css"), "text/css; charset=utf-8");
}

#[test]
fn export_import_contract_via_core() {
    let mut e = pm_core::entry::Entry::new();
    e.set(pm_core::entry::Field::Title, b"t");
    let doc = export::export_document(&[e]);
    let v: serde_json::Value = serde_json::from_str(&doc).unwrap();
    assert_eq!(v["format"], "PMX1");
    assert_eq!(v["version"], 1);
}
