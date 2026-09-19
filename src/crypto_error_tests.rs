use super::*;
use crate::crypto::{open, seal};
use argon2::Params;
use hkdf::{Hkdf, InvalidLength};
use x25519_dalek::{PublicKey, StaticSecret};

/// A deterministic identity built without running Argon2.
fn test_secret() -> StaticSecret {
    StaticSecret::from([7u8; 32])
}

/// The identity element. Has order 1, so `r · P` is all-zero for every `r`.
const SMALL_ORDER_POINT: [u8; 32] = [0u8; 32];

// --- From conversions: the `?` in seal/open/encrypt relies on these ---

#[test]
fn argon2_error_converts() {
    // m_cost below the 8 KiB minimum.
    let raw = Params::new(1, 1, 1, None).unwrap_err();
    let err: CryptoError = raw.into();

    assert!(matches!(err, CryptoError::Argon2(_)));
}

#[test]
fn hkdf_error_converts() {
    // HKDF-Expand tops out at 255 * HashLen = 8160 bytes for SHA-256.
    let hk = Hkdf::<Sha256>::new(None, &[0u8; 32]);
    let mut too_long = vec![0u8; 255 * 32 + 1];
    let raw = hk.expand(b"test", &mut too_long).unwrap_err();
    let err: CryptoError = raw.into();

    assert!(matches!(err, CryptoError::Hkdf(_)));
}

// --- Malformed: length checks in `open` ---

#[test]
fn open_rejects_messages_shorter_than_key_plus_tag() {
    let secret = test_secret();

    for len in [0, 1, 31, 32, 33, 47] {
        let short = vec![1u8; len];
        assert!(
            matches!(open(&secret, &short), Err(CryptoError::Malformed)),
            "expected Malformed for a {len}-byte message"
        );
    }
}

#[test]
fn open_accepts_minimum_length_without_malformed() {
    // Exactly 48 bytes clears the length check, so any failure past this
    // point must be a crypto failure rather than a framing one.
    let secret = test_secret();
    let msg = vec![1u8; EPHEMERAL_PUBLIC_KEY_LEN + TAG_LEN];

    assert!(!matches!(open(&secret, &msg), Err(CryptoError::Malformed)));
}

// --- WeakPublicKey: the was_contributory checks ---

#[test]
fn seal_rejects_small_order_recipient() {
    let weak = PublicKey::from(SMALL_ORDER_POINT);

    assert!(matches!(
        seal(&weak, b"secret"),
        Err(CryptoError::WeakPublicKey)
    ));
}

#[test]
fn open_rejects_small_order_ephemeral_key() {
    let secret = test_secret();

    // Long enough to pass the length check, ephemeral key is the identity point.
    let mut msg = vec![0u8; EPHEMERAL_PUBLIC_KEY_LEN + TAG_LEN];
    msg[..EPHEMERAL_PUBLIC_KEY_LEN].copy_from_slice(&SMALL_ORDER_POINT);

    assert!(matches!(
        open(&secret, &msg),
        Err(CryptoError::WeakPublicKey)
    ));
}

// --- Aead: authentication actually rejects modified input ---

#[test]
fn seal_open_round_trip() {
    let secret = test_secret();
    let public = PublicKey::from(&secret);

    let sealed = seal(&public, b"correct horse battery staple").unwrap();
    let opened = open(&secret, &sealed).unwrap();

    assert_eq!(opened, b"correct horse battery staple");
}

#[test]
fn seal_is_randomized_across_calls() {
    let secret = test_secret();
    let public = PublicKey::from(&secret);

    let a = seal(&public, b"same plaintext").unwrap();
    let b = seal(&public, b"same plaintext").unwrap();

    // Fresh ephemeral key per call => different key, nonce and ciphertext.
    assert_ne!(a, b, "two seals of the same plaintext must differ");
    assert_eq!(open(&secret, &a).unwrap(), open(&secret, &b).unwrap());
}

#[test]
fn open_rejects_tampered_ciphertext() {
    let secret = test_secret();
    let public = PublicKey::from(&secret);
    let sealed = seal(&public, b"vault entry").unwrap();

    for index in [EPHEMERAL_PUBLIC_KEY_LEN, sealed.len() - 1] {
        let mut corrupted = sealed.clone();
        corrupted[index] ^= 1;

        assert!(
            matches!(open(&secret, &corrupted), Err(CryptoError::Aead)),
            "flipping a bit at index {index} should fail authentication"
        );
    }
}

#[test]
fn open_rejects_substituted_ephemeral_key() {
    let secret = test_secret();
    let public = PublicKey::from(&secret);
    let sealed = seal(&public, b"vault entry").unwrap();

    // Swap in a different, valid ephemeral key: the shared secret changes.
    let other = PublicKey::from(&StaticSecret::from([3u8; 32]));
    let mut swapped = sealed.clone();
    swapped[..EPHEMERAL_PUBLIC_KEY_LEN].copy_from_slice(other.as_bytes());

    assert!(matches!(open(&secret, &swapped), Err(CryptoError::Aead)));
}

#[test]
fn open_rejects_wrong_identity() {
    let public = PublicKey::from(&test_secret());
    let sealed = seal(&public, b"vault entry").unwrap();

    let attacker = StaticSecret::from([9u8; 32]);

    assert!(matches!(open(&attacker, &sealed), Err(CryptoError::Aead)));
}

#[test]
fn open_rejects_truncated_message() {
    let secret = test_secret();
    let public = PublicKey::from(&secret);
    let sealed = seal(&public, b"a longer vault entry to truncate").unwrap();

    let truncated = &sealed[..sealed.len() - 1];

    assert!(matches!(open(&secret, truncated), Err(CryptoError::Aead)));
}

// --- Display ---

#[test]
fn display_does_not_leak_why_decryption_failed() {
    assert_eq!(
        CryptoError::Aead.to_string(),
        "message could not be encrypted or decrypted"
    );
    assert_eq!(
        CryptoError::Malformed.to_string(),
        "sealed message is malformed"
    );
    assert_eq!(
        CryptoError::WeakPublicKey.to_string(),
        "peer public key is not contributory"
    );
}

#[test]
fn wrapped_errors_include_the_source_message() {
    let err: CryptoError = Params::new(1, 1, 1, None).unwrap_err().into();
    let text = err.to_string();

    assert!(
        text.starts_with("argon2 key derivation failed: "),
        "unexpected Display output: {text}"
    );
    assert!(text.len() > "argon2 key derivation failed: ".len());
}
