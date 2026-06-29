#![cfg(sm2)]

mod common;

#[cfg(any(all(random, ecc_import, ecc_export, sm2_sign, sm2_verify), random))]
use std::fs;
#[cfg(all(random, sm2_dh))]
use std::rc::Rc;
#[cfg(random)]
use wolfssl_wolfcrypt::random::RNG;
use wolfssl_wolfcrypt::sm2::SM2;
#[cfg(any(
    all(random, ecc_import, ecc_export, sm2_sign, sm2_verify),
    all(random, sm2_dh),
    ecc_import
))]
use wolfssl_wolfcrypt::sys;

#[test]
#[cfg(random)]
fn test_sm2_generate() {
    common::setup();

    let rng = RNG::new().expect("Failed to create RNG");
    let mut sm2 = SM2::generate(&rng, SM2::FLAG_NONE, None, None).expect("Error with generate()");
    sm2.check().expect("Error with check()");
}

#[test]
#[cfg(all(random, ecc_import, ecc_export))]
fn test_sm2_import_x963() {
    common::setup();

    let rng = RNG::new().expect("Failed to create RNG");
    let mut sm2 = SM2::generate(&rng, SM2::FLAG_NONE, None, None).expect("Error with generate()");
    sm2.check().expect("Error with check()");

    let mut x963 = [0u8; 128];
    let x963_size = sm2
        .export_x963(&mut x963)
        .expect("Error with export_x963()");
    let x963 = &x963[..x963_size];
    let mut key2 = SM2::import_x963(x963, None, None).expect("Error with import_x963()");
    key2.check().expect("Error with check()");
}

#[test]
#[cfg(all(random, ecc_import, ecc_export, sm2_sign, sm2_verify))]
fn test_sm2_import_export_sign_verify() {
    common::setup();

    let rng = RNG::new().expect("Failed to create RNG");
    let key_path = "../../../certs/sm2/client-sm2-priv.der";
    let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    let mut sm2 = SM2::import_der(&der, None, None).expect("Error with import_der()");
    let mut hash = [0x42u8; 32];
    let mut signature = [0u8; 73];
    let signature_len = sm2
        .sign_hash(&hash, &mut signature, &rng)
        .expect("Error with sign_hash()");
    assert!(signature_len > 0 && signature_len <= signature.len());

    let mut too_small_buffer = [0u8; 1];
    assert_eq!(
        sm2.sign_hash(&hash, &mut too_small_buffer, &rng),
        Err(sys::wolfCrypt_ErrorCodes_BUFFER_E)
    );

    let signature = &signature[..signature_len];
    let key_path = "../../../certs/sm2/client-sm2-key.der";
    let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    let mut sm2 = SM2::import_public_der(&der, None, None).expect("Error with import_public_der()");
    let valid = sm2
        .verify_hash(&signature, &hash)
        .expect("Error with verify_hash()");
    assert_eq!(valid, true);

    let mut x963 = [0u8; 128];
    let x963_size = sm2
        .export_x963(&mut x963)
        .expect("Error with export_x963()");
    let x963 = &x963[..x963_size];
    let mut sm2 = SM2::import_x963(x963, None, None).expect("Error with import_x963");
    let valid = sm2
        .verify_hash(&signature, &hash)
        .expect("Error with verify_hash()");
    assert_eq!(valid, true);

    #[cfg(ecc_comp_key)]
    {
        let mut x963 = [0u8; 128];
        let x963_size = sm2
            .export_x963_compressed(&mut x963)
            .expect("Error with export_x963_compressed()");
        let x963 = &x963[..x963_size];
        let mut sm2 = SM2::import_x963(x963, None, None).expect("Error with import_x963");
        let valid = sm2
            .verify_hash(&signature, &hash)
            .expect("Error with verify_hash()");
        assert_eq!(valid, true);
    }

    hash[0] ^= 0x01;
    let valid = sm2
        .verify_hash(&signature, &hash)
        .expect("Error with verify_hash()");
    assert_eq!(valid, false);

    sm2.set_rng(rng).expect("Error with set_rng()");
}

#[test]
#[cfg(all(random, sm2_dh))]
fn test_sm2_shared_secret() {
    common::setup();

    let rng = Rc::new(RNG::new().expect("Failed to create RNG"));
    let mut alice = SM2::generate(&rng, SM2::FLAG_NONE, None, None).expect("Error with generate()");
    let mut bob = SM2::generate(&rng, SM2::FLAG_NONE, None, None).expect("Error with generate()");
    alice
        .set_shared_rng(Rc::clone(&rng))
        .expect("Error with set_shared_rng()");
    bob.set_shared_rng(Rc::clone(&rng))
        .expect("Error with set_shared_rng()");
    let mut alice_secret = [0u8; SM2::KEY_SIZE];
    let mut bob_secret = [0u8; SM2::KEY_SIZE];
    let alice_len = alice
        .shared_secret(&mut bob, &mut alice_secret)
        .expect("Error with shared_secret()");
    let bob_len = bob
        .shared_secret(&mut alice, &mut bob_secret)
        .expect("Error with shared_secret()");
    assert!(alice_len > 0 && alice_len <= SM2::KEY_SIZE);
    assert!(bob_len > 0 && bob_len <= SM2::KEY_SIZE);
    assert_eq!(alice_len, bob_len);
    assert_eq!(alice_secret[..alice_len], bob_secret[..bob_len]);

    let mut too_small_buffer = [0u8; 1];
    assert_eq!(
        alice.shared_secret(&mut bob, &mut too_small_buffer),
        Err(sys::wolfCrypt_ErrorCodes_BUFFER_E)
    )
}

#[test]
#[cfg(all(random, ecc_export))]
fn test_sm2_export() {
    common::setup();

    let rng = RNG::new().expect("Failed to create RNG");
    let mut sm2 = SM2::generate(&rng, SM2::FLAG_NONE, None, None).expect("Error with generate()");
    let mut qx = [0u8; 32];
    let mut qx_len = 0u32;
    let mut qy = [0u8; 32];
    let mut qy_len = 0u32;
    let mut d = [0u8; 32];
    let mut d_len = 0u32;
    sm2.export(
        &mut qx,
        &mut qx_len,
        &mut qy,
        &mut qy_len,
        &mut d,
        &mut d_len,
    )
    .expect("Error with export()");
}

#[test]
#[cfg(all(random, ecc_export))]
fn test_sm2_export_ex() {
    common::setup();

    let rng = RNG::new().expect("Failed to create RNG");
    let mut sm2 = SM2::generate(&rng, SM2::FLAG_NONE, None, None).expect("Error with generate()");
    let mut qx = [0u8; 32];
    let mut qx_len = 0u32;
    let mut qy = [0u8; 32];
    let mut qy_len = 0u32;
    let mut d = [0u8; 32];
    let mut d_len = 0u32;
    sm2.export_ex(
        &mut qx,
        &mut qx_len,
        &mut qy,
        &mut qy_len,
        &mut d,
        &mut d_len,
        false,
    )
    .expect("Error with export_ex()");
}

#[test]
#[cfg(all(random, ecc_import, ecc_export, sm2_sign, sm2_verify))]
fn test_sm2_import_export_private() {
    common::setup();

    let rng = RNG::new().expect("Failed to create RNG");
    let mut sm2 = SM2::generate(&rng, SM2::FLAG_NONE, None, None).expect("Error with generate()");
    let hash = [0x42u8; 32];
    let mut signature = [0u8; 73];
    let signature_len = sm2
        .sign_hash(&hash, &mut signature, &rng)
        .expect("Error with sign_hash()");
    let signature = &signature[..signature_len];

    let mut d = [0u8; 32];
    let d_size = sm2
        .export_private(&mut d)
        .expect("Error with export_private()");
    assert_eq!(d_size, 32);
    let mut x963 = [0u8; 128];
    let x963_size = sm2
        .export_x963(&mut x963)
        .expect("Error with export_x963()");
    let x963 = &x963[..x963_size];

    let mut key2 =
        SM2::import_private_key(&d, x963, None, None).expect("Error with import_private_key()");
    let valid = key2
        .verify_hash(&signature, &hash)
        .expect("Error with verify_hash()");
    assert_eq!(valid, true);

    SM2::import_private_key(&d, &[], None, None).expect("Error with import_private_key()");
}

#[test]
#[cfg(all(random, ecc_export))]
fn test_sm2_export_public() {
    common::setup();

    let rng = RNG::new().expect("Failed to create RNG");
    let mut sm2 = SM2::generate(&rng, SM2::FLAG_NONE, None, None).expect("Error with generate()");
    let mut qx = [0u8; 32];
    let mut qx_len = 0u32;
    let mut qy = [0u8; 32];
    let mut qy_len = 0u32;
    sm2.export_public(&mut qx, &mut qx_len, &mut qy, &mut qy_len)
        .expect("Error with export_public()");
}

#[test]
#[cfg(all(random, ecc_import, ecc_export, sm2_sign, sm2_verify))]
fn test_sm2_import_unsigned() {
    common::setup();

    let rng = RNG::new().expect("Failed to create RNG");
    let mut sm2 = SM2::generate(&rng, SM2::FLAG_NONE, None, None).expect("Error with generate()");
    let mut qx = [0u8; 32];
    let mut qx_len = 0u32;
    let mut qy = [0u8; 32];
    let mut qy_len = 0u32;
    let mut d = [0u8; 32];
    let mut d_len = 0u32;
    sm2.export_ex(
        &mut qx,
        &mut qx_len,
        &mut qy,
        &mut qy_len,
        &mut d,
        &mut d_len,
        false,
    )
    .expect("Error with export_ex()");

    let mut key2 =
        SM2::import_unsigned(&qx, &qy, &d, None, None).expect("Error with import_unsigned()");

    let hash = [0x42u8; 32];
    let mut signature = [0u8; 73];
    let signature_length = sm2
        .sign_hash(&hash, &mut signature, &rng)
        .expect("Error with sign_hash()");
    let signature = &signature[..signature_length];
    let valid = key2
        .verify_hash(signature, &hash)
        .expect("Error with verify_hash()");
    assert_eq!(valid, true);
}

#[test]
#[cfg(ecc_import)]
fn test_sm2_import_unsigned_short_slices() {
    common::setup();

    let qx = [0u8; 32];
    let qy = [0u8; 32];
    let d = [0u8; 32];
    let empty: [u8; 0] = [];

    let cases: [(&[u8], &[u8], &[u8]); 6] = [
        (&qx[..31], &qy, &d),
        (&qx, &qy[..31], &d),
        (&qx, &qy, &d[..31]),
        (&empty, &qy, &d),
        (&qx, &empty, &d),
        (&qx, &qy, &empty),
    ];
    for (qx, qy, d) in cases {
        match SM2::import_unsigned(qx, qy, d, None, None) {
            Ok(_) => panic!("import_unsigned() should fail with short slice"),
            Err(rc) => assert_eq!(rc, sys::wolfCrypt_ErrorCodes_BAD_FUNC_ARG),
        }
    }
}

#[test]
#[cfg(random)]
fn test_sm2_make_pub() {
    common::setup();

    let rng = RNG::new().expect("Failed to create RNG");
    let key_path = "../../../certs/sm2/client-sm2-priv.der";
    let der: Vec<u8> = fs::read(key_path).expect("Error reading key file");
    let mut sm2 = SM2::import_der(&der, None, None).expect("Error with import_der()");
    sm2.make_pub(Some(&rng)).expect("Error with make_pub()");
    sm2.make_pub(None).expect("Error with make_pub()");
}

#[test]
#[cfg(ecc_import)]
fn test_sm2_import() {
    common::setup();

    // ECC key
    let qx = b"7a4e287890a1a47ad3457e52f2f76a83ce46cbc947616d0cbaa82323818a793d\0";
    let qy = b"eec4084f5b29ebf29c44cce3b3059610922f8b30ea6e8811742ac7238fe87308\0";
    let d = b"8c14b793cb19137e323a6d2e2a870bca2e7a493ec1153b3a95feb8a4873f8d08\0";
    let mut key = SM2::import_raw(qx, qy, d, None, None).expect("Error with import_raw()");
    assert_eq!(key.check(), Err(sys::wolfCrypt_ErrorCodes_MP_VAL));

    // SM2 key from `certs/sm2/client-sm2-priv.pem`.
    let qx = b"3a1de8cb4bd32e3f4b073fb021fec59ed9ca3a939395761d30d90bf556ed1960\0";
    let qy = b"ed014cf6671df1aca8740db277c84938e4ff4cef8d6d87f64ec7f839747070b5\0";
    let d = b"d0a2df497a2ddf02c9ceb7f237020dddfc08b8de14937a532649d5fe02d9f371\0";
    let mut key = SM2::import_raw(qx, qy, d, None, None).expect("Error with import_raw()");
    key.check().expect("Error with check()");
}

#[test]
#[cfg(ecc_import)]
fn test_sm2_import_raw_not_null_terminated() {
    common::setup();

    let qx = b"3a1de8cb4bd32e3f4b073fb021fec59ed9ca3a939395761d30d90bf556ed1960\0";
    let qy = b"ed014cf6671df1aca8740db277c84938e4ff4cef8d6d87f64ec7f839747070b5\0";
    let d = b"d0a2df497a2ddf02c9ceb7f237020dddfc08b8de14937a532649d5fe02d9f371\0";
    let qx_no_nul: &[u8] = &qx[..qx.len() - 1];
    let qy_no_nul: &[u8] = &qy[..qy.len() - 1];
    let d_no_nul: &[u8] = &d[..d.len() - 1];
    let empty: &[u8] = b"";

    assert!(SM2::import_raw(qx_no_nul, qy, d, None, None).is_err());
    assert!(SM2::import_raw(qx, qy_no_nul, d, None, None).is_err());
    assert!(SM2::import_raw(qx, qy, d_no_nul, None, None).is_err());
    assert!(SM2::import_raw(empty, qy, d, None, None).is_err());
    assert!(SM2::import_raw(qx, empty, d, None, None).is_err());
    assert!(SM2::import_raw(qx, qy, empty, None, None).is_err());
}

#[test]
#[cfg(all(random, sm2_digest, sm3))]
fn test_sm2_create_digest_with_sm3() {
    common::setup();

    let rng = RNG::new().expect("Failed to create RNG");
    let mut key =
        SM2::generate(&rng, SM2::FLAG_NONE, None, None).expect("Error generating SM2 key");
    let mut digest = [0u8; 32];
    key.create_digest(
        SM2::CERT_SIG_ID,
        b"message digest",
        SM2::HASH_TYPE_SM3,
        &mut digest,
    )
    .expect("Error with create_digest()");
    assert_ne!(digest, [0u8; 32]);

    let mut digest2 = [0u8; 31];
    let is_err = key
        .create_digest(
            SM2::CERT_SIG_ID,
            b"message digest",
            SM2::HASH_TYPE_SM3,
            &mut digest2,
        )
        .is_err();
    assert_eq!(is_err, true);
}
