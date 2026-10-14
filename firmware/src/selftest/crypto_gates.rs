//! Crypto gates: PBKDF2, AES-GCM, constant-time compare, device factor, TOTP.

use super::*;

pub(super) fn crypto_gates() {
    // PBKDF2 against RFC 7914 vectors.
    const VECTORS: &[(&str, &str, u32, &str)] = &[
        (
            "password",
            "salt",
            1,
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
        ),
        (
            "password",
            "salt",
            2,
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
        ),
        (
            "password",
            "salt",
            4096,
            "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
        ),
        (
            "passwordPASSWORDpassword",
            "saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
            "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1",
        ),
        (
            "passwd",
            "salt",
            1,
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc",
        ),
    ];
    let mut ok_count = 0u32;
    for (pass, salt, iters, expect) in VECTORS {
        let mut want = [0u8; 32];
        if !pm_core::hex::decode_into(expect.as_bytes(), &mut want) {
            continue;
        }
        if crypto::pbkdf2_hmac_sha256(pass.as_bytes(), salt.as_bytes(), *iters)
            .is_ok_and(|got| crypto::ct_equal(&got, &want))
        {
            ok_count += 1;
        }
    }
    report(
        "crypto-kdf",
        ok_count as usize == VECTORS.len(),
        &format!("{}/{} vectors (RFC 7914)", ok_count, VECTORS.len()),
    );

    // AES-256-GCM round-trip, then tag/AAD/ciphertext flips must fail.
    {
        let key: [u8; 32] = core::array::from_fn(|i| (i + 1) as u8);
        let iv: [u8; 12] = [0xAA, 0xBB, 0xCC, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let aad: [u8; 8] = [b'h', b'd', b'r', b'v', b'1', 0, 0, 0];
        let msg = b"gate-plaintext-check-0123456789";
        let mut buf = msg.to_vec();
        let mut ok = false;
        if let Ok(tag) = crypto::aes_gcm_encrypt(&key, &iv, &aad, &mut buf) {
            ok = buf.len() == msg.len();
            if ok {
                let mut back = buf.clone();
                ok = crypto::aes_gcm_decrypt(&key, &iv, &aad, &mut back, &tag).is_ok()
                    && back == msg;
                if ok {
                    let mut bad_aad = aad;
                    bad_aad[0] ^= 0x01;
                    ok = crypto::aes_gcm_decrypt(&key, &iv, &bad_aad, &mut back, &tag)
                        == Err(CipherError::AuthFail);
                }
                if ok {
                    let mut ct = buf.clone();
                    ct[0] ^= 0x01;
                    ok = crypto::aes_gcm_decrypt(&key, &iv, &aad, &mut ct, &tag)
                        == Err(CipherError::AuthFail);
                }
                if ok {
                    let mut t = tag;
                    t[0] ^= 0x01;
                    ok = crypto::aes_gcm_decrypt(&key, &iv, &aad, &mut back, &t)
                        == Err(CipherError::AuthFail);
                }
            }
        }
        crypto::wipe(&mut buf);
        report("crypto-aes-gcm", ok, "roundtrip + ct/aad/tag flip rejected");
    }

    // ct_equal must tell two buffers apart.
    {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 5];
        report(
            "crypto-cteq",
            !crypto::ct_equal(&a, &b) && crypto::ct_equal(&a, &a),
            "",
        );
    }

    // Device factor must be deterministic and salt-dependent.
    {
        let mut s1 = [0u8; 16];
        s1[0] = 1;
        let mut s2 = [0u8; 16];
        s2[0] = 2;
        let ok = match reversed_mac6() {
            Some(mac) => match (
                device::factor(&mac, &s1),
                device::factor(&mac, &s1),
                device::factor(&mac, &s2),
            ) {
                (Ok(f1), Ok(f2), Ok(f3)) => {
                    crypto::ct_equal(&f1, &f2) && !crypto::ct_equal(&f1, &f3)
                }
                _ => false,
            },
            None => false,
        };
        report("device-factor", ok, "stable, salt-dependent");
    }

    // TOTP against RFC 6238 (SHA-1). T = 20000000000 does not fit a u32, and
    // device time is 32-bit.
    {
        const VECTORS: &[(u32, &str)] = &[
            (59, "287082"),
            (1111111109, "081804"),
            (1111111111, "050471"),
            (1234567890, "005924"),
            (2000000000, "279037"),
        ];
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let digits = config::TOTP_DIGITS;
        let period = config::TOTP_PERIOD_SEC;
        let mut ok_count = 0u32;
        for (t, expect) in VECTORS {
            if totp::compute(secret, *t as u64, digits, period).is_ok_and(|code| code == *expect) {
                ok_count += 1;
            }
        }
        let rejects = !totp::is_valid_secret("abc")
            && !totp::is_valid_secret("ABCDEFGH1IJKLMNOP")
            && !totp::is_valid_secret("")
            && totp::compute("too-short", 59, digits, period).is_err();
        report(
            "crypto-totp-rfc6238",
            ok_count == 5 && rejects,
            &format!("{ok_count}/5 vectors, invalid rejected: {rejects}"),
        );
    }
}
