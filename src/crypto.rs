use argon2::{Algorithm, Argon2, Params, Version};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

fn salt_from_nickname(nickname: &str) -> [u8; 16] {
    let norm = nickname.trim().nfkc().collect::<String>();

    let mut h = Sha256::new();
    h.update(norm.as_bytes());

    let mut salt = [0u8; 16];
    salt.copy_from_slice(&h.finalize()[..16]);
    salt
}

fn seed(nickname: &str, password: &str) -> Zeroizing<[u8; 32]> {
    let salt = salt_from_nickname(nickname);

    let params = Params::new(256 * 1024, 3, 1, Some(32)).unwrap();

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut seed = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password.as_bytes(), &salt, seed.as_mut())
        .unwrap();
    seed
}
