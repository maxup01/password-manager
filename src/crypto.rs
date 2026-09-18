use argon2::{Algorithm, Argon2, Params, Version};
use core::result;
use hkdf::{Hkdf, InvalidLength};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

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

fn identity_key(seed: &[u8; 32]) -> result::Result<(StaticSecret, PublicKey), InvalidLength> {
    let hk = Hkdf::<Sha256>::new(None, seed);

    let mut sk = Zeroizing::new([0u8; 32]);

    hk.expand(b"password-manager x25519-identity", sk.as_mut())?;

    let secret = StaticSecret::from(*sk);

    let public = PublicKey::from(&secret);

    Ok((secret, public))
}
