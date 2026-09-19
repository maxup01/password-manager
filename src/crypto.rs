use crate::crypto_error::CryptoError;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, aead::Aead};
use core::result;
use hkdf::{Hkdf, InvalidLength};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Length of the ephemeral public key prefixed to every sealed message.
const EPHEMERAL_PUBLIC_KEY_LEN: usize = 32;

/// Poly1305 authentication tag.
const TAG_LEN: usize = 16;

pub type Result<T> = result::Result<T, CryptoError>;

fn salt_from_nickname(nickname: &str) -> [u8; 16] {
    let norm = nickname.trim().nfkc().collect::<String>();

    let mut h = Sha256::new();
    h.update(b"/salt/");
    h.update(b"password-manager");
    h.update(norm.as_bytes());

    let mut salt = [0u8; 16];
    salt.copy_from_slice(&h.finalize()[..16]);
    salt
}

fn seed(nickname: &str, password: &str) -> argon2::Result<Zeroizing<[u8; 32]>> {
    let salt = salt_from_nickname(nickname);

    let params = Params::new(46 * 1024 * 1024, 1, 1, None)?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut seed = Zeroizing::new([0u8; 32]);

    argon.hash_password_into(password.as_bytes(), &salt, seed.as_mut())?;

    Ok(seed)
}

fn identity_key(seed: &[u8; 32]) -> result::Result<StaticSecret, InvalidLength> {
    let hk = Hkdf::<Sha256>::new(None, seed);

    let mut sk = Zeroizing::new([0u8; 32]);

    hk.expand(b"password-manager x25519-identity", sk.as_mut())?;

    let secret = StaticSecret::from(*sk);

    Ok(secret)
}

/// Derive the per-message AEAD key and nonce from a raw ECDH output.
fn message_keys(
    shared: &[u8; 32],
    epk: &PublicKey,
    recipient: &PublicKey,
) -> Result<(Zeroizing<[u8; 32]>, [u8; 24])> {
    let hk = Hkdf::<Sha256>::new(None, shared);

    let mut okm = Zeroizing::new([0u8; 56]); // 32-byte key ‖ 24-byte nonce

    hk.expand_multi_info(
        &[
            b"password-manager seal",
            epk.as_bytes(),
            recipient.as_bytes(),
        ],
        okm.as_mut(),
    )?;

    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&okm[..32]);

    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&okm[32..]);

    Ok((key, nonce))
}

pub(crate) fn seal(recipient: &PublicKey, data: &[u8]) -> Result<Vec<u8>> {
    let ephemeral = EphemeralSecret::random();
    let ephemeral_public_key = PublicKey::from(&ephemeral);

    let shared = ephemeral.diffie_hellman(recipient);
    if !shared.was_contributory() {
        return Err(CryptoError::WeakPublicKey);
    }

    let (key, nonce) = message_keys(shared.as_bytes(), &ephemeral_public_key, recipient)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&*key).map_err(|_| CryptoError::Aead)?;
    let ct = cipher
        .encrypt(&nonce.into(), data)
        .map_err(|_| CryptoError::Aead)?;

    let mut out = Vec::with_capacity(EPHEMERAL_PUBLIC_KEY_LEN + ct.len());
    out.extend_from_slice(ephemeral_public_key.as_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a message produced by [`seal`].
pub(crate) fn open(secret: &StaticSecret, encryption: &[u8]) -> Result<Vec<u8>> {
    if encryption.len() < EPHEMERAL_PUBLIC_KEY_LEN + TAG_LEN {
        return Err(CryptoError::Malformed);
    }
    let (epk_bytes, ct) = encryption.split_at(EPHEMERAL_PUBLIC_KEY_LEN);

    let mut raw = [0u8; 32];
    raw.copy_from_slice(epk_bytes);

    let epk = PublicKey::from(raw);

    let recipient = PublicKey::from(secret);

    let shared = secret.diffie_hellman(&epk);
    if !shared.was_contributory() {
        return Err(CryptoError::WeakPublicKey);
    }

    let (key, nonce) = message_keys(shared.as_bytes(), &epk, &recipient)?;

    let cipher = XChaCha20Poly1305::new_from_slice(&*key).map_err(|_| CryptoError::Aead)?;
    cipher
        .decrypt(&nonce.into(), ct)
        .map_err(|_| CryptoError::Aead)
}

fn encrypt(nickname: &str, password: &str, data: &[u8]) -> Result<(Vec<u8>, PublicKey)> {
    let seed = seed(nickname, password)?;

    let secret = identity_key(&seed)?;

    let public_key = PublicKey::from(&secret);

    let encrypted_data = seal(&public_key, data)?;

    Ok((encrypted_data, public_key))
}

pub(crate) fn decrypt(nickname: &str, password: &str, sealed: &[u8]) -> Result<Vec<u8>> {
    let seed = seed(nickname, password)?;
    let secret = identity_key(&seed)?;
    open(&secret, sealed)
}
