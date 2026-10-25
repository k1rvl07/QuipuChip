//! Response helpers mirroring the firmware's JSON/EXPORT headers.

use alloc::vec::Vec;

/// JSON headers used by API responses (and static assets).
pub const JSON_HEADERS: &[(&str, &str)] = &[
    ("Cache-Control", "no-store"),
    ("X-Content-Type-Options", "nosniff"),
];

/// Headers used for the streamed JSON export attachment.
pub const EXPORT_HEADERS: &[(&str, &str)] = &[
    ("Cache-Control", "no-store"),
    ("X-Content-Type-Options", "nosniff"),
    (
        "Content-Disposition",
        "attachment; filename=\"passmanager-export.json\"",
    ),
];

/// A response outcome, decoupled from any specific HTTP framework.
#[derive(Debug, Clone)]
pub enum Outcome {
    /// JSON response.
    Json {
        /// HTTP status code.
        status: u16,
        /// Response body.
        body: Vec<u8>,
    },
    /// Export attachment.
    Export(Vec<u8>),
    /// Static asset.
    Static {
        /// Asset bytes.
        bytes: &'static [u8],
        /// MIME type.
        mime: &'static str,
    },
    /// Download response.
    Download {
        /// Body bytes.
        body: Vec<u8>,
        /// Content-Type.
        content_type: &'static str,
        /// Content-Disposition.
        disposition: &'static str,
    },
    /// Empty response.
    Empty {
        /// HTTP status code.
        status: u16,
    },
}

/// Body wrapper compatible with content-length based writers.
#[derive(Debug, Clone)]
pub struct TypedBody<B> {
    /// Body bytes/slice.
    pub bytes: B,
    /// Content-Type.
    pub content_type: &'static str,
}

impl<B: AsRef<[u8]>> TypedBody<B> {
    /// Content type.
    #[must_use]
    pub fn content_type(&self) -> &'static str {
        self.content_type
    }

    /// Content length.
    #[must_use]
    pub fn content_length(&self) -> usize {
        self.bytes.as_ref().len()
    }
}
