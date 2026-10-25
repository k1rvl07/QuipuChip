//! Request/response DTOs for the framework-agnostic API layer.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use serde_json::Value;

/// A parsed HTTP request, independent of the server framework.
#[derive(Debug, Clone)]
pub struct ApiRequest {
    /// HTTP method (e.g. "GET", "POST").
    pub method: String,
    /// Path without query string.
    pub path: String,
    /// Raw query string, if present.
    pub query: Option<String>,
    /// Header values, lowercased keys recommended by the caller.
    pub headers: Vec<(String, String)>,
    /// Raw request body.
    pub body: Vec<u8>,
}

/// A response produced by the API handler.
#[derive(Debug, Clone)]
pub struct ApiResponse {
    /// HTTP status code.
    pub status: u16,
    /// Content-Type header value.
    pub content_type: String,
    /// Additional response headers.
    pub headers: Vec<(String, String)>,
    /// Response body bytes.
    pub body: Vec<u8>,
}

impl ApiResponse {
    /// Builds a JSON response with the standard JSON headers.
    #[must_use]
    pub fn json(status: u16, value: &Value) -> Self {
        let body = serde_json::to_vec(value)
            .unwrap_or_else(|_| b"{\"ok\":false,\"error\":\"serialize_failed\"}".to_vec());
        Self {
            status,
            content_type: "application/json".into(),
            headers: vec![
                ("Cache-Control".into(), "no-store".into()),
                ("X-Content-Type-Options".into(), "nosniff".into()),
            ],
            body,
        }
    }

    /// Builds a 200 OK static asset response.
    #[must_use]
    pub fn static_asset(bytes: &[u8], mime: &str) -> Self {
        Self {
            status: 200,
            content_type: mime.into(),
            headers: vec![
                ("Cache-Control".into(), "no-store".into()),
                ("X-Content-Type-Options".into(), "nosniff".into()),
            ],
            body: bytes.to_vec(),
        }
    }

    /// Builds an empty response with the given status.
    #[must_use]
    pub fn empty(status: u16) -> Self {
        Self {
            status,
            content_type: "text/plain".into(),
            headers: alloc::vec![],
            body: Vec::new(),
        }
    }
}
