//! Framework-agnostic HTTP API types and helpers.
//!
//! The firmware's picoserve layer maps `Outcome`/`HttpError` onto concrete
//! responses; `pm-core` owns the contract (paths, JSON shapes, headers) and
//! the pure helpers used by both.

pub mod response;
pub mod types;

pub use response::{EXPORT_HEADERS, JSON_HEADERS, Outcome, TypedBody};
pub use types::{ApiRequest, ApiResponse};
