use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

fn salt_from_nickname(nickname: &str) -> [u8; 16] {
    let norm = nickname.trim().nfkc().collect::<String>();

    let mut h = Sha256::new();
    h.update(norm.as_bytes());

    let mut salt = [0u8; 16];
    salt.copy_from_slice(&h.finalize()[..16]);
    salt
}
