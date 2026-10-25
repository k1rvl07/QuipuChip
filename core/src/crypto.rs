//! Cryptographic primitives, ported from the C++ reference (mbedtls) to RustCrypto.
//!
//! The algorithms are standard, so a byte-identical port is expected:
//! PBKDF2-HMAC-SHA256 (single output block, dkLen = 32), HMAC-SHA256,
//! SHA-256, HMAC-SHA1 (TOTP only) and AES-256-GCM with a 12-byte IV and a
//! 16-byte tag. The public API is allocation-free: callers pass in/out slices,
//! which is what the vault writer needs and what keeps `pm-core` usable on the
//! device without an allocator contract.

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub use crate::config::{AES_KEY_LEN, GCM_IV_LEN, GCM_TAG_LEN};

/// Mirrors `crypto::CipherError` from the C++ reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherError {
    /// No error.
    Ok,
    /// A parameter was rejected as invalid.
    InvalidArg,
    /// The key length was wrong.
    InvalidKeyLen,
    /// The IV/nonce length was wrong.
    InvalidIvLen,
    /// The tag length was wrong.
    InvalidTagLen,
    /// Authentication tag verification failed.
    AuthFail,
    /// Encryption failed.
    EncryptFail,
    /// Decryption failed.
    DecryptFail,
}

impl core::fmt::Display for CipherError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            CipherError::Ok => "ok",
            CipherError::InvalidArg => "invalid argument",
            CipherError::InvalidKeyLen => "invalid key length",
            CipherError::InvalidIvLen => "invalid iv length",
            CipherError::InvalidTagLen => "invalid tag length",
            CipherError::AuthFail => "authentication failed",
            CipherError::EncryptFail => "encrypt failed",
            CipherError::DecryptFail => "decrypt failed",
        })
    }
}

impl core::error::Error for CipherError {}

/// Best-effort secure zeroing that the compiler may not elide.
pub fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid, aligned, non-aliased `u8`.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
}

/// Constant-time comparison. Lengths are part of the compared data.
#[must_use]
pub fn ct_equal(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).unwrap_u8() == 1
}

/// SHA-256 of one buffer.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(data));
    out
}

/// HMAC-SHA256 (any key length).
#[must_use]
#[allow(clippy::expect_used, reason = "HMAC accepts a key of any length")]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// HMAC-SHA1 (TOTP only, RFC 6238).
#[must_use]
#[allow(clippy::expect_used, reason = "HMAC accepts a key of any length")]
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let mut out = [0u8; 20];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// PBKDF2-HMAC-SHA256 with a fixed 32-byte output (one block).
///
/// Rejects the same degenerate inputs as the C++ reference (empty password or
/// salt, zero iterations) instead of silently producing a key.
pub fn pbkdf2_hmac_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<[u8; 32], CipherError> {
    if password.is_empty() || salt.is_empty() || iterations == 0 {
        return Err(CipherError::InvalidArg);
    }
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2::<Hmac<Sha256>>(password, salt, iterations, &mut out)
        .map_err(|_| CipherError::EncryptFail)?;
    Ok(out)
}

/// AES-256-GCM encryption in place: `buf` holds plaintext on entry and
/// ciphertext on return. The 16-byte tag is returned separately.
pub fn aes_gcm_encrypt(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    buf: &mut [u8],
) -> Result<[u8; 16], CipherError> {
    if buf.is_empty() {
        return Err(CipherError::InvalidArg);
    }
    if iv.len() != GCM_IV_LEN {
        return Err(CipherError::InvalidIvLen);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CipherError::InvalidKeyLen)?;
    let nonce = Nonce::from_slice(iv);
    let tag = cipher
        .encrypt_in_place_detached(nonce, aad, buf)
        .map_err(|_| CipherError::EncryptFail)?;
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag);
    Ok(out)
}

/// AES-256-GCM decryption in place: `buf` holds ciphertext on entry and
/// plaintext on return. Any authentication failure yields [`CipherError::AuthFail`].
pub fn aes_gcm_decrypt(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8],
) -> Result<(), CipherError> {
    if buf.is_empty() {
        return Err(CipherError::InvalidArg);
    }
    if iv.len() != GCM_IV_LEN {
        return Err(CipherError::InvalidIvLen);
    }
    if tag.len() != GCM_TAG_LEN {
        return Err(CipherError::InvalidTagLen);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CipherError::InvalidKeyLen)?;
    let nonce = Nonce::from_slice(iv);
    let tag = GenericArray::from_slice(tag);
    cipher
        .decrypt_in_place_detached(nonce, aad, buf, tag)
        .map_err(|_| CipherError::AuthFail)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn sha256_known_answer() {
        let got = sha256(b"abc");
        assert_eq!(
            got.to_vec(),
            unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
    }

    #[test]
    fn hmac_sha256_rfc4231_case1() {
        let key = [0x0bu8; 20];
        let got = hmac_sha256(&key, b"Hi There");
        assert_eq!(
            got.to_vec(),
            unhex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
    }

    #[test]
    fn hmac_sha1_rfc2202_case1() {
        let key = [0x0bu8; 20];
        let got = hmac_sha1(&key, b"Hi There");
        assert_eq!(
            got.to_vec(),
            unhex("b617318655057264e28bc0b6fb378c8ef146be00")
        );
    }

    #[test]
    fn pbkdf2_rfc7914_vectors() {
        // Same table as src/selftest.cpp crypto-kdf gate.
        let vectors: &[(&[u8], &[u8], u32, &str)] = &[
            (
                b"password",
                b"salt",
                1,
                "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
            ),
            (
                b"password",
                b"salt",
                2,
                "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
            ),
            (
                b"password",
                b"salt",
                4096,
                "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
            ),
            (
                b"passwordPASSWORDpassword",
                b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
                4096,
                "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1",
            ),
            (
                b"passwd",
                b"salt",
                1,
                "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc",
            ),
        ];
        for (pass, salt, iters, expect) in vectors {
            let got = pbkdf2_hmac_sha256(pass, salt, *iters).unwrap();
            assert_eq!(got.to_vec(), unhex(expect), "pass={pass:?} iters={iters}");
        }
    }

    #[test]
    fn pbkdf2_rejects_degenerate_inputs() {
        assert_eq!(
            pbkdf2_hmac_sha256(b"", b"salt", 1),
            Err(CipherError::InvalidArg)
        );
        assert_eq!(
            pbkdf2_hmac_sha256(b"pw", b"", 1),
            Err(CipherError::InvalidArg)
        );
        assert_eq!(
            pbkdf2_hmac_sha256(b"pw", b"salt", 0),
            Err(CipherError::InvalidArg)
        );
    }

    #[test]
    fn aes_gcm_roundtrip_and_tamper_rejected() {
        let key: [u8; 32] = core::array::from_fn(|i| (i + 1) as u8);
        let iv = [0xAA, 0xBB, 0xCC, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let aad = [b'h', b'd', b'r', b'v', b'1', 0, 0, 0];
        let msg = b"gate-plaintext-check-0123456789";

        let mut buf = msg.to_vec();
        let tag = aes_gcm_encrypt(&key, &iv, &aad, &mut buf).unwrap();
        assert_ne!(buf, msg.to_vec());

        let mut back = buf.clone();
        aes_gcm_decrypt(&key, &iv, &aad, &mut back, &tag).unwrap();
        assert_eq!(back, msg.to_vec());

        // AAD, ciphertext and tag are all authenticated.
        let mut bad_aad = aad;
        bad_aad[0] ^= 1;
        let mut b = buf.clone();
        assert_eq!(
            aes_gcm_decrypt(&key, &iv, &bad_aad, &mut b, &tag),
            Err(CipherError::AuthFail)
        );

        let mut bad_ct = buf.clone();
        bad_ct[0] ^= 1;
        assert_eq!(
            aes_gcm_decrypt(&key, &iv, &aad, &mut bad_ct, &tag),
            Err(CipherError::AuthFail)
        );

        let mut bad_tag = tag;
        bad_tag[0] ^= 1;
        let mut b = buf.clone();
        assert_eq!(
            aes_gcm_decrypt(&key, &iv, &aad, &mut b, &bad_tag),
            Err(CipherError::AuthFail)
        );
    }

    #[test]
    fn aes_gcm_nist_empty_plaintext_tag() {
        // NIST GCM test vector: all-zero key/iv, empty PT and AAD -> known tag.
        // The reference rejects empty plaintext, so we only check the KAT once
        // the library is fed the empty payload directly.
        let key = [0u8; 32];
        let iv = [0u8; 12];
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let mut empty: [u8; 0] = [];
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&iv), &[], &mut empty)
            .unwrap();
        assert_eq!(tag.to_vec(), unhex("530f8afbc74536b9a963b4f1c4cb738b"));
    }

    #[test]
    fn ct_equal_detects_difference() {
        assert!(!ct_equal(&[1, 2, 3, 4], &[1, 2, 3, 5]));
        assert!(ct_equal(&[1, 2, 3, 4], &[1, 2, 3, 4]));
        assert!(!ct_equal(&[1, 2, 3], &[1, 2, 3, 4]));
    }

    #[test]
    fn ct_equal_on_empty_slices() {
        assert!(ct_equal(&[], &[]));
    }

    #[test]
    fn wipe_zeroes_the_buffer() {
        let mut buf = [0xABu8; 16];
        wipe(&mut buf);
        assert_eq!(buf, [0u8; 16]);
        // Wiping an empty buffer must not panic.
        wipe(&mut []);
    }

    #[test]
    fn cipher_error_messages() {
        let cases = [
            (CipherError::Ok, "ok"),
            (CipherError::InvalidArg, "invalid argument"),
            (CipherError::InvalidKeyLen, "invalid key length"),
            (CipherError::InvalidIvLen, "invalid iv length"),
            (CipherError::InvalidTagLen, "invalid tag length"),
            (CipherError::AuthFail, "authentication failed"),
            (CipherError::EncryptFail, "encrypt failed"),
            (CipherError::DecryptFail, "decrypt failed"),
        ];
        for (err, text) in cases {
            assert_eq!(err.to_string(), text);
        }
    }

    #[test]
    fn aes_gcm_encrypt_rejects_bad_parameters() {
        let key = [0u8; 32];
        let iv = [0u8; 12];
        let mut buf = [0u8; 8];

        // Empty plaintext is refused: the reference has no use for it and a
        // zero-length buffer would make an empty record indistinguishable from
        // a failed write.
        assert_eq!(
            aes_gcm_encrypt(&key, &iv, &[], &mut []),
            Err(CipherError::InvalidArg)
        );
        // Wrong IV length.
        assert_eq!(
            aes_gcm_encrypt(&key, &[0u8; 11], &[], &mut buf),
            Err(CipherError::InvalidIvLen)
        );
        assert_eq!(
            aes_gcm_encrypt(&key, &[0u8; 13], &[], &mut buf),
            Err(CipherError::InvalidIvLen)
        );
        // Wrong key length.
        assert_eq!(
            aes_gcm_encrypt(&[0u8; 16], &iv, &[], &mut buf),
            Err(CipherError::InvalidKeyLen)
        );
    }

    #[test]
    fn aes_gcm_decrypt_rejects_bad_parameters() {
        let key = [0u8; 32];
        let iv = [0u8; 12];
        let tag = [0u8; 16];
        let mut buf = [0u8; 8];

        assert_eq!(
            aes_gcm_decrypt(&key, &iv, &[], &mut [], &tag),
            Err(CipherError::InvalidArg)
        );
        assert_eq!(
            aes_gcm_decrypt(&key, &[0u8; 11], &[], &mut buf, &tag),
            Err(CipherError::InvalidIvLen)
        );
        assert_eq!(
            aes_gcm_decrypt(&key, &iv, &[], &mut buf, &[0u8; 15]),
            Err(CipherError::InvalidTagLen)
        );
        assert_eq!(
            aes_gcm_decrypt(&key, &iv, &[], &mut buf, &[0u8; 17]),
            Err(CipherError::InvalidTagLen)
        );
        assert_eq!(
            aes_gcm_decrypt(&[0u8; 16], &iv, &[], &mut buf, &tag),
            Err(CipherError::InvalidKeyLen)
        );
    }

    #[test]
    fn aes_gcm_rejects_a_truncated_or_extended_key() {
        // 32 bytes is AES-256; anything else must be refused rather than
        // silently padded, because the vault derives a fixed-size key.
        let iv = [0u8; 12];
        let mut buf = [0u8; 8];
        for len in [0usize, 1, 15, 16, 24, 31, 33, 64] {
            let key = vec![0u8; len];
            assert_eq!(
                aes_gcm_encrypt(&key, &iv, &[], &mut buf),
                Err(CipherError::InvalidKeyLen),
                "key length {len}"
            );
        }
    }
}
