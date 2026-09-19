use hkdf::InvalidLength;
use thiserror::Error;

/// Anything that can go wrong while deriving keys.
#[derive(Debug, Error)]
pub(crate) enum CryptoError {
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

#[cfg(test)]
#[path = "crypto_error_tests.rs"]
mod tests;
