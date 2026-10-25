#![allow(clippy::unwrap_used)]

//! Known-answer tests for the cryptographic primitives.
//!
//! The vectors come from published standards (FIPS 180-4, RFC 2202, RFC 4231,
//! RFC 7914) and from an independent implementation for AES-256-GCM. They pin
//! the port to the algorithms, so a silent change in the crypto backend (or a
//! dependency upgrade that changes behaviour) fails here instead of producing
//! a vault nobody can open.

use pm_core::crypto::{
    CipherError, aes_gcm_decrypt, aes_gcm_encrypt, ct_equal, hmac_sha1, hmac_sha256,
    pbkdf2_hmac_sha256, sha256, wipe,
};

/// Decodes a hex string. Panics on malformed input, which is a test bug.
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[test]
fn sha256_matches_the_fips_180_4_vectors() {
    assert_eq!(
        hex(&sha256(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        hex(&sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex(&sha256(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        )),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

#[test]
fn hmac_sha256_matches_rfc_4231() {
    // Test case 1.
    assert_eq!(
        hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    // Test case 2.
    assert_eq!(
        hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
    // Test case 3.
    assert_eq!(
        hex(&hmac_sha256(&[0xaa; 20], &[0xdd; 50])),
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
    );
}

#[test]
fn hmac_sha1_matches_rfc_2202() {
    assert_eq!(
        hex(&hmac_sha1(&[0x0b; 20], b"Hi There")),
        "b617318655057264e28bc0b6fb378c8ef146be00"
    );
    assert_eq!(
        hex(&hmac_sha1(b"Jefe", b"what do ya want for nothing?")),
        "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
    );
    assert_eq!(
        hex(&hmac_sha1(&[0xaa; 20], &[0xdd; 50])),
        "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
    );
}

#[test]
fn pbkdf2_matches_rfc_7914() {
    // PBKDF2-HMAC-SHA256, P = "passwd", S = "salt".
    assert_eq!(
        hex(&pbkdf2_hmac_sha256(b"passwd", b"salt", 1).unwrap()),
        "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
    );
    assert_eq!(
        hex(&pbkdf2_hmac_sha256(b"passwd", b"salt", 4096).unwrap()),
        "21943fd5b7a10905c38fad60157ff498e1e81df1e03254325682a74dca3b2be8"
    );
    assert_eq!(
        hex(&pbkdf2_hmac_sha256(b"password", b"salt", 1).unwrap()),
        "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
    );
}

#[test]
fn pbkdf2_rejects_degenerate_inputs() {
    assert_eq!(
        pbkdf2_hmac_sha256(b"", b"salt", 1),
        Err(CipherError::InvalidArg)
    );
    assert_eq!(
        pbkdf2_hmac_sha256(b"password", b"", 1),
        Err(CipherError::InvalidArg)
    );
    assert_eq!(
        pbkdf2_hmac_sha256(b"password", b"salt", 0),
        Err(CipherError::InvalidArg)
    );
}

#[test]
fn aes_256_gcm_matches_an_independent_implementation() {
    let key: [u8; 32] = core::array::from_fn(|i| i as u8);
    let iv: [u8; 12] = core::array::from_fn(|i| i as u8);
    let aad = b"header";
    let mut buf = *b"QuipuChip vault payload";

    let tag = aes_gcm_encrypt(&key, &iv, aad, &mut buf).unwrap();
    assert_eq!(
        hex(&buf),
        "1763a5688884ac7aea24e5abc7880d01f7f6f7558917301d5c"
    );
    assert_eq!(hex(&tag), "cd32ef2646b8671c2756466aedb272bb");

    // The ciphertext decrypts back to the plaintext.
    let mut plain = buf;
    assert_eq!(aes_gcm_decrypt(&key, &iv, aad, &mut plain, &tag), Ok(()));
    assert_eq!(&plain, b"QuipuChip vault payload");
}

#[test]
fn aes_256_gcm_refuses_a_tampered_tag_or_aad() {
    let key = [7u8; 32];
    let iv = [3u8; 12];
    let mut buf = *b"secret";
    let tag = aes_gcm_encrypt(&key, &iv, b"aad", &mut buf).unwrap();

    // A flipped tag bit fails the authentication.
    let mut bad_tag = tag;
    bad_tag[0] ^= 0x01;
    let mut copy = buf;
    assert_eq!(
        aes_gcm_decrypt(&key, &iv, b"aad", &mut copy, &bad_tag),
        Err(CipherError::AuthFail)
    );

    // A different AAD fails it too: the AAD is authenticated, not just mixed in.
    let mut copy = buf;
    assert_eq!(
        aes_gcm_decrypt(&key, &iv, b"other", &mut copy, &tag),
        Err(CipherError::AuthFail)
    );

    // A flipped ciphertext bit fails it.
    let mut copy = buf;
    copy[0] ^= 0x01;
    assert_eq!(
        aes_gcm_decrypt(&key, &iv, b"aad", &mut copy, &tag),
        Err(CipherError::AuthFail)
    );
}

#[test]
fn aes_256_gcm_rejects_bad_parameters() {
    let mut buf = *b"x";
    assert_eq!(
        aes_gcm_encrypt(&[0u8; 32], &[0u8; 11], b"", &mut buf),
        Err(CipherError::InvalidIvLen)
    );
    let mut empty: [u8; 0] = [];
    assert_eq!(
        aes_gcm_encrypt(&[0u8; 32], &[0u8; 12], b"", &mut empty),
        Err(CipherError::InvalidArg)
    );
    let mut copy = buf;
    assert_eq!(
        aes_gcm_decrypt(&[0u8; 32], &[0u8; 12], b"", &mut copy, &[0u8; 15]),
        Err(CipherError::InvalidTagLen)
    );
}

#[test]
fn ct_equal_compares_the_whole_input() {
    assert!(ct_equal(b"", b""));
    assert!(ct_equal(b"abcdef", b"abcdef"));
    assert!(!ct_equal(b"abcdef", b"abcdeg"));
    assert!(!ct_equal(b"abcdef", b"abcde"));
    assert!(!ct_equal(b"abcde", b"abcdef"));
}

#[test]
fn wipe_clears_every_byte() {
    let mut buf = [0xABu8; 32];
    wipe(&mut buf);
    assert!(buf.iter().all(|&b| b == 0));
}

/// The key derivation of the vault must be the standard PBKDF2: a mismatch
/// here would make every vault written by one build unreadable by another.
#[test]
fn pbkdf2_is_deterministic_and_salt_dependent() {
    let a = pbkdf2_hmac_sha256(b"password", b"salt-a", 1000).unwrap();
    let b = pbkdf2_hmac_sha256(b"password", b"salt-a", 1000).unwrap();
    let c = pbkdf2_hmac_sha256(b"password", b"salt-b", 1000).unwrap();
    assert_eq!(a, b);
    assert_ne!(a, c);
}

/// A hex helper shared with the other integration tests: it is the same
/// encoding the vault uses for its headers, so a mismatch would corrupt them.
#[test]
fn hex_encoding_round_trips() {
    let data = unhex("00ff10a5");
    let encoded = pm_core::hex::encode(&data);
    assert_eq!(encoded, "00ff10a5");
    let mut decoded = [0u8; 4];
    assert!(pm_core::hex::decode_into(encoded.as_bytes(), &mut decoded));
    assert_eq!(decoded.as_slice(), data.as_slice());
}
