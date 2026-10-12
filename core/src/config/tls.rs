//! TLS material generation and storage constants.
//!
//! The device mints its own root CA and server (leaf) certificate on first boot
//! and keeps them in a dedicated `tls` partition; these constants fix the
//! identities and the on-flash container layout. Networking constants (the SAN
//! IP, the port) stay in the firmware crate.

/// Subject CN of the generated root CA.
pub const TLS_CA_CN: &str = "PassManager CA";
/// Subject CN of the generated server (leaf) certificate.
pub const TLS_LEAF_CN: &str = "PassManager";
/// Fixed `notBefore` (2020-01-01T00:00:00Z).
///
/// The board has no RTC and never learns the wall clock, so the validity window
/// cannot be "now minus/plus delta". A wide fixed window is the only option
/// that keeps the certificate valid for a browser with a correct clock.
pub const TLS_VALID_FROM_UNIX: u64 = 1_577_836_800;
/// Fixed `notAfter` (2100-01-01T00:00:00Z).
pub const TLS_VALID_UNTIL_UNIX: u64 = 4_102_444_800;
/// ECDSA P-256 private scalar length.
pub const TLS_KEY_BYTES: usize = 32;
/// Entropy draws allowed before key generation reports [`Entropy`].
///
/// With a real TRNG a rejection essentially cannot happen; the bound exists so a
/// substituted test source (e.g. all `0xFF`) fails fast instead of spinning.
///
/// [`Entropy`]: crate::pki::PkiError::Entropy
pub const TLS_ENTROPY_ATTEMPTS: u32 = 64;
/// `id-kp-serverAuth` object identifier (RFC 5280).
pub const TLS_OID_SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";
/// `ecdsa-with-SHA256` signature algorithm identifier (RFC 5758).
pub const TLS_OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";

/// Stored-material container magic (`PMT1`).
pub const TLS_BLOB_MAGIC: [u8; 4] = *b"PMT1";
/// Stored-material container version.
pub const TLS_BLOB_VERSION: u32 = 1;
/// Fixed header: magic, version, three lengths and four reserved words.
pub const TLS_BLOB_HEADER_BYTES: usize = 32;
/// Integrity hash trailer length (SHA-256).
pub const TLS_BLOB_HASH_BYTES: usize = 32;
/// `tls` partition capacity (64 KiB, see `partitions.csv`).
pub const TLS_PARTITION_BYTES: usize = 64 * 1024;
