//! PKI material contract tests.

#![allow(clippy::unwrap_used)]

use pm_core::config::{TLS_BLOB_MAGIC, TLS_BLOB_VERSION};
use pm_core::pki::{IssuerParams, TlsMaterial, generate, pem};
use pm_core::rand::CycleSource;

#[test]
fn generate_and_encode_decode_roundtrip() {
    let mut rng = CycleSource::new(b"pki-test-seed-012345678901234567890123");
    let params = IssuerParams {
        ca_cn: "QuipuChip-CA",
        leaf_cn: "passmanager.local",
        san_ip: [192, 168, 7, 1],
        not_before: 1_700_000_000,
        not_after: 2_000_000_000,
    };
    let m = generate(&params, &mut rng).unwrap();
    assert!(!m.ca_cert_der.is_empty());
    assert!(!m.leaf_cert_der.is_empty());
    assert!(!m.leaf_key_der.is_empty());
    let blob = m.encode();
    assert_eq!(&blob[..4], &TLS_BLOB_MAGIC);
    assert_eq!(
        u32::from_le_bytes(blob[4..8].try_into().unwrap()),
        TLS_BLOB_VERSION
    );
    let m2 = TlsMaterial::decode(&blob).unwrap();
    assert_eq!(m2.ca_cert_der, m.ca_cert_der);
    assert_eq!(m2.leaf_cert_der, m.leaf_cert_der);
    assert_eq!(m2.leaf_key_der, m.leaf_key_der);
}

#[test]
fn pem_wraps_der() {
    let der = b"hello";
    let p = pem("CERTIFICATE", der);
    assert!(p.contains("-----BEGIN CERTIFICATE-----"));
    assert!(p.contains("-----END CERTIFICATE-----"));
}

#[test]
fn decode_rejects_bad_blob() {
    assert!(TlsMaterial::decode(b"bad").is_none());
    let mut bad = vec![0u8; 64];
    bad[..4].copy_from_slice(b"XXXX");
    assert!(TlsMaterial::decode(&bad).is_none());
}
