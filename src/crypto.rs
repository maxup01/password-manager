use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, aead::Aead};
use core::result;
use hkdf::{Hkdf, InvalidLength};
use sha2::{Digest, Sha256};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Length of the ephemeral public key prefixed to every sealed message.
const EPHEMERAL_PUBLIC_KEY_LEN: usize = 32;

/// Anything that can go wrong while deriving keys.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Argon2 parameters were out of range,
    /// or hashing could not allocate bytes of memory.
    #[error("argon2 key derivation failed: {0}")]
    Argon2(#[from] argon2::Error),

    /// Requested more HKDF output than `255 * 32` bytes.
    #[error("hkdf expand failed: {0}")]
    Hkdf(#[from] InvalidLength),

    /// AEAD refused the key, or the ciphertext failed authentication.
    #[error("message could not be encrypted or decrypted")]
    Aead,

    /// Sealed message too short to contain an ephemeral key and a tag.
    #[error("sealed message is malformed")]
    Malformed,

    /// Peer public key had small order — shared secret would be all-zero.
    #[error("peer public key is not contributory")]
    WeakPublicKey,
}

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

/// Encrypt `data` to `recipient`. Needs no secret — only the public key.
pub(crate) fn seal(
    recipient: &PublicKey,
    ephemeral: EphemeralSecret,
    ephemeral_public_key: &PublicKey,
    data: &[u8],
) -> Result<Vec<u8>> {
    let shared = ephemeral.diffie_hellman(recipient);
    if !shared.was_contributory() {
        return Err(CryptoError::WeakPublicKey);
    }

    let (key, nonce) = message_keys(shared.as_bytes(), ephemeral_public_key, recipient)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&*key).map_err(|_| CryptoError::Aead)?;
    let ct = cipher
        .encrypt(&nonce.into(), data)
        .map_err(|_| CryptoError::Aead)?;

    let mut out = Vec::with_capacity(EPHEMERAL_PUBLIC_KEY_LEN + ct.len());
    out.extend_from_slice(ephemeral_public_key.as_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

fn encrypt(nickname: &str, password: &str, data: &[u8]) -> Result<(Vec<u8>, PublicKey)> {
    let seed = seed(nickname, password)?;

    let secret = identity_key(&seed)?;

    let public_key = PublicKey::from(&secret);

    let ephemeral = EphemeralSecret::random();
    let epk = PublicKey::from(&ephemeral);

    let encrypted_data = seal(&public_key, ephemeral, &epk, data)?;

    Ok((encrypted_data, public_key))
}
