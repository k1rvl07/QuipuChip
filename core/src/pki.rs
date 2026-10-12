//! On-device X.509 material: a root CA and a server (leaf) certificate.
//!
//! The device signs its own certificates with ECDSA P-256 (RustCrypto `p256` +
//! `x509-cert`); there is no C toolchain and no build-time key. `generate` takes
//! an explicit [`RandomSource`], as everywhere else in `pm-core`, so host tests
//! can drive it deterministically and pin the failure behaviour.
//!
//! Certificates are assembled from the `x509-cert` data types and then signed
//! directly. `x509-cert`'s `CertificateBuilder` is gated behind its `builder`
//! feature, which pulls in `std` and therefore cannot be compiled for the
//! firmware target; the types themselves are `no_std` and are enough.
//!
//! The board has no RTC, so the validity window is the fixed constant range in
//! [`crate::config`] rather than "now +/- delta". The leaf carries an IP SAN
//! (the USB-NCM gateway address) because that is the only name the host uses.
//!
//! The material is persisted by the firmware in the `tls` partition using the
//! [`TlsMaterial::encode`]/[`TlsMaterial::decode`] container (`PMT1`).

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::str::FromStr;
use core::time::Duration;

use p256::FieldBytes;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature, SigningKey, VerifyingKey};
use p256::pkcs8::EncodePrivateKey;
use x509_cert::Version;
use x509_cert::certificate::{Certificate, TbsCertificate};
use x509_cert::der::Encode;
use x509_cert::der::asn1::{BitString, GeneralizedTime, ObjectIdentifier, OctetString};
use x509_cert::der::oid::AssociatedOid;
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName,
};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};

use crate::config::{
    TLS_BLOB_HASH_BYTES, TLS_BLOB_HEADER_BYTES, TLS_BLOB_MAGIC, TLS_BLOB_VERSION,
    TLS_ENTROPY_ATTEMPTS, TLS_KEY_BYTES, TLS_OID_ECDSA_SHA256, TLS_OID_SERVER_AUTH,
    TLS_PARTITION_BYTES,
};
use crate::rand::RandomSource;

/// Errors from minting or decoding TLS material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkiError {
    /// The entropy source never produced a valid P-256 scalar.
    Entropy,
    /// A subject/issuer distinguished name could not be parsed.
    Name,
    /// Building or signing a certificate failed.
    Build,
    /// DER / SPKI / PKCS#8 encoding failed.
    Encode,
    /// The stored container is malformed or too large.
    Blob,
}

impl core::fmt::Display for PkiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            PkiError::Entropy => "entropy source failed",
            PkiError::Name => "invalid certificate name",
            PkiError::Build => "certificate build failed",
            PkiError::Encode => "der encoding failed",
            PkiError::Blob => "invalid tls material",
        })
    }
}

impl core::error::Error for PkiError {}

/// Parameters for one CA/leaf pair.
#[derive(Debug, Clone, Copy)]
pub struct IssuerParams<'a> {
    /// Subject CN of the root CA.
    pub ca_cn: &'a str,
    /// Subject CN of the leaf certificate.
    pub leaf_cn: &'a str,
    /// IPv4 SAN of the leaf certificate, as four octets.
    pub san_ip: [u8; 4],
    /// `notBefore` in seconds since the Unix epoch.
    pub not_before: u64,
    /// `notAfter` in seconds since the Unix epoch.
    pub not_after: u64,
}

/// The minted certificate material, DER-encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsMaterial {
    /// Root CA certificate (DER).
    pub ca_cert_der: Vec<u8>,
    /// Leaf certificate, signed by the CA (DER).
    pub leaf_cert_der: Vec<u8>,
    /// Leaf private key in unencrypted PKCS#8 DER.
    pub leaf_key_der: Vec<u8>,
}

/// Draws a private scalar from `rng`, retrying a bounded number of times.
///
/// P-256 rejects the zero scalar and values at or above the group order; a real
/// TRNG hits that with negligible probability, but a substituted test source
/// must fail fast rather than spin.
fn generate_key(rng: &mut impl RandomSource) -> Result<SigningKey, PkiError> {
    let mut bytes = [0u8; TLS_KEY_BYTES];
    for _ in 0..TLS_ENTROPY_ATTEMPTS {
        rng.fill(&mut bytes);
        if let Ok(key) = SigningKey::from_bytes(FieldBytes::from_slice(&bytes)) {
            crate::crypto::wipe(&mut bytes);
            return Ok(key);
        }
    }
    crate::crypto::wipe(&mut bytes);
    Err(PkiError::Entropy)
}

/// Draws a non-zero 64-bit serial number.
fn serial(rng: &mut impl RandomSource) -> u64 {
    let mut bytes = [0u8; 8];
    rng.fill(&mut bytes);
    match u64::from_le_bytes(bytes) {
        0 => 1,
        v => v,
    }
}

fn parse_name(cn: &str) -> Result<Name, PkiError> {
    Name::from_str(&alloc::format!("CN={cn}")).map_err(|_| PkiError::Name)
}

fn unix_time(secs: u64) -> Result<Time, PkiError> {
    Ok(Time::GeneralTime(
        GeneralizedTime::from_unix_duration(Duration::from_secs(secs))
            .map_err(|_| PkiError::Encode)?,
    ))
}

fn spki(key: &VerifyingKey) -> Result<SubjectPublicKeyInfoOwned, PkiError> {
    SubjectPublicKeyInfoOwned::from_key(*key).map_err(|_| PkiError::Encode)
}

/// `ecdsa-with-SHA256`, the algorithm the signer below uses.
fn signature_algorithm() -> Result<AlgorithmIdentifierOwned, PkiError> {
    Ok(AlgorithmIdentifierOwned {
        oid: ObjectIdentifier::new(TLS_OID_ECDSA_SHA256).map_err(|_| PkiError::Encode)?,
        parameters: None,
    })
}

/// Encodes `value` as a v3 extension with the given criticality.
fn extension<T>(value: &T, critical: bool) -> Result<Extension, PkiError>
where
    T: Encode + AssociatedOid,
{
    let content = OctetString::new(value.to_der().map_err(|_| PkiError::Encode)?)
        .map_err(|_| PkiError::Encode)?;
    Ok(Extension {
        extn_id: T::OID,
        critical,
        extn_value: content,
    })
}

/// Builds a certificate from `tbs` and signs it with `issuer`.
fn sign_tbs(tbs: TbsCertificate, issuer: &SigningKey) -> Result<Certificate, PkiError> {
    let tbs_der = tbs.to_der().map_err(|_| PkiError::Encode)?;
    let signature: DerSignature = issuer.sign(&tbs_der);
    let signature = BitString::from_bytes(&signature.to_der().map_err(|_| PkiError::Encode)?)
        .map_err(|_| PkiError::Encode)?;
    Ok(Certificate {
        tbs_certificate: tbs,
        signature_algorithm: signature_algorithm()?,
        signature,
    })
}

/// Mints a self-signed root CA and a leaf certificate signed by it.
///
/// The CA private key is never returned: the CA only ever issues the single
/// leaf, and re-issuing regenerates the whole pair.
pub fn generate(
    params: &IssuerParams<'_>,
    rng: &mut impl RandomSource,
) -> Result<TlsMaterial, PkiError> {
    let ca_key = generate_key(rng)?;
    let leaf_key = generate_key(rng)?;

    let ca_subject = parse_name(params.ca_cn)?;
    let leaf_subject = parse_name(params.leaf_cn)?;
    let validity = Validity {
        not_before: unix_time(params.not_before)?,
        not_after: unix_time(params.not_after)?,
    };

    // Root: BasicConstraints CA:TRUE, KeyUsage keyCertSign+cRLSign.
    let ca_extensions = vec![
        extension(
            &BasicConstraints {
                ca: true,
                path_len_constraint: None,
            },
            true,
        )?,
        extension(&KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign), true)?,
    ];
    let ca_tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::from(serial(rng)),
        signature: signature_algorithm()?,
        issuer: ca_subject.clone(),
        validity,
        subject: ca_subject.clone(),
        subject_public_key_info: spki(ca_key.verifying_key())?,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(ca_extensions),
    };
    let ca_cert = sign_tbs(ca_tbs, &ca_key)?;

    // Leaf: BasicConstraints CA:FALSE, SAN (IP), EKU serverAuth, KeyUsage DS.
    let san = SubjectAltName(vec![GeneralName::IpAddress(
        OctetString::new(params.san_ip.to_vec()).map_err(|_| PkiError::Encode)?,
    )]);
    let eku = ExtendedKeyUsage(vec![
        ObjectIdentifier::new(TLS_OID_SERVER_AUTH).map_err(|_| PkiError::Encode)?,
    ]);
    let leaf_extensions = vec![
        extension(
            &BasicConstraints {
                ca: false,
                path_len_constraint: None,
            },
            true,
        )?,
        extension(&san, false)?,
        extension(&eku, false)?,
        extension(&KeyUsage(KeyUsages::DigitalSignature.into()), true)?,
    ];
    let leaf_tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::from(serial(rng)),
        signature: signature_algorithm()?,
        issuer: ca_subject,
        validity,
        subject: leaf_subject,
        subject_public_key_info: spki(leaf_key.verifying_key())?,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(leaf_extensions),
    };
    let leaf_cert = sign_tbs(leaf_tbs, &ca_key)?;

    let leaf_key_der = leaf_key
        .to_pkcs8_der()
        .map_err(|_| PkiError::Encode)?
        .as_bytes()
        .to_vec();

    Ok(TlsMaterial {
        ca_cert_der: ca_cert.to_der().map_err(|_| PkiError::Encode)?,
        leaf_cert_der: leaf_cert.to_der().map_err(|_| PkiError::Encode)?,
        leaf_key_der,
    })
}

/// PEM-encodes a DER blob under the given label (e.g. `CERTIFICATE`).
#[must_use]
pub fn pem(label: &str, der: &[u8]) -> String {
    use core::fmt::Write as _;

    let b64 = crate::base64::encode(der);
    let mut out = String::new();
    let _ = writeln!(out, "-----BEGIN {label}-----");
    for chunk in b64.as_bytes().chunks(64) {
        let _ = writeln!(out, "{}", core::str::from_utf8(chunk).unwrap_or(""));
    }
    let _ = writeln!(out, "-----END {label}-----");
    out
}

impl TlsMaterial {
    /// Serializes the material into the `PMT1` container.
    ///
    /// Layout: a fixed 32-byte header (magic, version, three little-endian
    /// lengths, reserved words), the concatenated DER blobs, then a SHA-256
    /// trailer over everything before it.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let ca = self.ca_cert_der.len();
        let leaf = self.leaf_cert_der.len();
        let key = self.leaf_key_der.len();
        let mut out = vec![0u8; TLS_BLOB_HEADER_BYTES + ca + leaf + key + TLS_BLOB_HASH_BYTES];
        out[..4].copy_from_slice(&TLS_BLOB_MAGIC);
        out[4..8].copy_from_slice(&TLS_BLOB_VERSION.to_le_bytes());
        out[8..12].copy_from_slice(&(ca as u32).to_le_bytes());
        out[12..16].copy_from_slice(&(leaf as u32).to_le_bytes());
        out[16..20].copy_from_slice(&(key as u32).to_le_bytes());
        let mut at = TLS_BLOB_HEADER_BYTES;
        out[at..at + ca].copy_from_slice(&self.ca_cert_der);
        at += ca;
        out[at..at + leaf].copy_from_slice(&self.leaf_cert_der);
        at += leaf;
        out[at..at + key].copy_from_slice(&self.leaf_key_der);
        at += key;
        let hash = crate::crypto::sha256(&out[..at]);
        out[at..].copy_from_slice(&hash);
        out
    }

    /// Parses and validates a `PMT1` container. `None` means absent or corrupt;
    /// the caller regenerates in that case.
    #[must_use]
    pub fn decode(buf: &[u8]) -> Option<TlsMaterial> {
        if buf.len() > TLS_PARTITION_BYTES
            || buf.len() < TLS_BLOB_HEADER_BYTES + TLS_BLOB_HASH_BYTES
        {
            return None;
        }
        if buf[..4] != TLS_BLOB_MAGIC {
            return None;
        }
        let version = u32::from_le_bytes(buf[4..8].try_into().ok()?);
        if version != TLS_BLOB_VERSION {
            return None;
        }
        let ca = u32::from_le_bytes(buf[8..12].try_into().ok()?) as usize;
        let leaf = u32::from_le_bytes(buf[12..16].try_into().ok()?) as usize;
        let key = u32::from_le_bytes(buf[16..20].try_into().ok()?) as usize;
        let end = TLS_BLOB_HEADER_BYTES
            .checked_add(ca)?
            .checked_add(leaf)?
            .checked_add(key)?;
        let total = end.checked_add(TLS_BLOB_HASH_BYTES)?;
        // `buf` may be a whole flash partition: bytes past the container are
        // erased `0xFF` and ignored, but a truncated container is rejected.
        if total > buf.len() {
            return None;
        }
        if crate::crypto::sha256(&buf[..end]) != buf[end..total] {
            return None;
        }
        let mut at = TLS_BLOB_HEADER_BYTES;
        let ca_cert_der = buf[at..at + ca].to_vec();
        at += ca;
        let leaf_cert_der = buf[at..at + leaf].to_vec();
        at += leaf;
        let leaf_key_der = buf[at..at + key].to_vec();
        Some(TlsMaterial {
            ca_cert_der,
            leaf_cert_der,
            leaf_key_der,
        })
    }
}

const _: () = assert!(TLS_BLOB_HEADER_BYTES >= 20);
const _: () = assert!(TLS_KEY_BYTES == 32);

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;
    use p256::pkcs8::{DecodePrivateKey, DecodePublicKey};
    use x509_cert::der::Decode;

    /// Deterministic but non-constant source: a 64-bit LCG.
    struct Lcg(u64);

    impl RandomSource for Lcg {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf {
                self.0 = self
                    .0
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                *b = (self.0 >> 33) as u8;
            }
        }
    }

    /// Constant source whose value is never a valid P-256 scalar.
    struct Ones;

    impl RandomSource for Ones {
        fn fill(&mut self, buf: &mut [u8]) {
            buf.fill(0xFF);
        }
    }

    fn params() -> IssuerParams<'static> {
        IssuerParams {
            ca_cn: "PassManager CA",
            leaf_cn: "PassManager",
            san_ip: [192, 168, 7, 1],
            not_before: 1_577_836_800,
            not_after: 4_102_444_800,
        }
    }

    fn find_ext(cert: &Certificate, oid: ObjectIdentifier) -> Option<&Extension> {
        cert.tbs_certificate
            .extensions
            .as_ref()?
            .iter()
            .find(|e| e.extn_id == oid)
    }

    #[test]
    fn mints_a_verifiable_chain() {
        let material = generate(&params(), &mut Lcg(0x1234_5678)).unwrap();

        let ca = Certificate::from_der(&material.ca_cert_der).unwrap();
        let leaf = Certificate::from_der(&material.leaf_cert_der).unwrap();

        // A self-signed root issues a distinct leaf.
        assert_eq!(ca.tbs_certificate.issuer, ca.tbs_certificate.subject);
        assert_eq!(leaf.tbs_certificate.issuer, ca.tbs_certificate.subject);

        // The leaf signature verifies under the CA public key.
        let spki_der = ca.tbs_certificate.subject_public_key_info.to_der().unwrap();
        let ca_key = VerifyingKey::from_public_key_der(&spki_der).unwrap();
        let tbs = leaf.tbs_certificate.to_der().unwrap();
        let sig = DerSignature::from_bytes(leaf.signature.raw_bytes()).unwrap();
        ca_key.verify(&tbs, &sig).unwrap();
    }

    #[test]
    fn leaf_key_matches_the_certificate() {
        let material = generate(&params(), &mut Lcg(7)).unwrap();
        let secret = p256::SecretKey::from_pkcs8_der(&material.leaf_key_der).unwrap();
        let derived = VerifyingKey::from(&SigningKey::from(secret));

        let leaf = Certificate::from_der(&material.leaf_cert_der).unwrap();
        let spki_der = leaf
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap();
        let stored = VerifyingKey::from_public_key_der(&spki_der).unwrap();
        assert_eq!(derived, stored);
    }

    #[test]
    fn carries_the_expected_extensions() {
        let material = generate(&params(), &mut Lcg(42)).unwrap();
        let ca = Certificate::from_der(&material.ca_cert_der).unwrap();
        let leaf = Certificate::from_der(&material.leaf_cert_der).unwrap();

        let ca_bc = BasicConstraints::from_der(
            find_ext(&ca, BasicConstraints::OID)
                .unwrap()
                .extn_value
                .as_bytes(),
        )
        .unwrap();
        assert!(ca_bc.ca);

        let leaf_bc = BasicConstraints::from_der(
            find_ext(&leaf, BasicConstraints::OID)
                .unwrap()
                .extn_value
                .as_bytes(),
        )
        .unwrap();
        assert!(!leaf_bc.ca);

        let san = SubjectAltName::from_der(
            find_ext(&leaf, SubjectAltName::OID)
                .unwrap()
                .extn_value
                .as_bytes(),
        )
        .unwrap();
        assert!(
            san.0.iter().any(
                |n| matches!(n, GeneralName::IpAddress(a) if a.as_bytes() == [192, 168, 7, 1])
            )
        );

        let eku = ExtendedKeyUsage::from_der(
            find_ext(&leaf, ExtendedKeyUsage::OID)
                .unwrap()
                .extn_value
                .as_bytes(),
        )
        .unwrap();
        let server_auth = ObjectIdentifier::new(TLS_OID_SERVER_AUTH).unwrap();
        assert!(eku.0.contains(&server_auth));
    }

    #[test]
    fn entropy_failure_is_reported() {
        assert_eq!(
            generate(&params(), &mut Ones).unwrap_err(),
            PkiError::Entropy
        );
    }

    #[test]
    fn blob_round_trips_and_rejects_damage() {
        let material = generate(&params(), &mut Lcg(7)).unwrap();
        let blob = material.encode();
        assert_eq!(TlsMaterial::decode(&blob).unwrap(), material);

        let mut bad = blob.clone();
        bad[40] ^= 1;
        assert!(TlsMaterial::decode(&bad).is_none());
        assert!(TlsMaterial::decode(&[]).is_none());
        assert!(TlsMaterial::decode(&blob[..blob.len() - 1]).is_none());
        assert!(TlsMaterial::decode(&vec![0xFF; TLS_PARTITION_BYTES + 1]).is_none());

        // A flash partition holds the container plus erased (0xFF) slack.
        let mut padded = blob.clone();
        padded.resize(TLS_PARTITION_BYTES, 0xFF);
        assert_eq!(TlsMaterial::decode(&padded).unwrap(), material);
    }

    #[test]
    fn pem_wraps_at_64_columns() {
        let text = pem("CERTIFICATE", &[0xAB; 130]);
        assert!(text.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(text.ends_with("-----END CERTIFICATE-----\n"));
        for line in text.lines().filter(|l| !l.starts_with("-----")) {
            assert!(line.len() <= 64);
        }
    }
}
