use super::*;

#[test]
fn salt_is_stable_across_calls() {
    assert_eq!(salt_from_nickname("maks"), salt_from_nickname("maks"));
}

#[test]
fn salt_matches_known_vector() {
    let expected = [
        0x5a, 0x2b, 0x43, 0xcf, 0xd1, 0x7b, 0xeb, 0xc0, 0x30, 0x5c, 0xd0, 0x5f, 0xf3, 0x31, 0x68,
        0xe4,
    ];

    assert_eq!(salt_from_nickname("maks"), expected);
}

#[test]
fn salt_is_independent_of_unicode_normalization() {
    let composed = "caf\u{e9}"; // é as one code point
    let decomposed = "cafe\u{301}"; // e + combining acute

    assert_ne!(
        composed.as_bytes(),
        decomposed.as_bytes(),
        "inputs must differ, or this test proves nothing"
    );
    assert_eq!(salt_from_nickname(composed), salt_from_nickname(decomposed));
}

#[test]
fn different_nicknames_give_different_salts() {
    let salts = ["maks", "maksy", "Maks", "", "aks m"].map(salt_from_nickname);

    for (i, a) in salts.iter().enumerate() {
        for b in &salts[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

// --- seed ---

const NICKNAME: &str = "maks";
const PASSWORD: &str = "correct horse battery staple";

#[test]
fn seed_is_deterministic() {
    let first = seed(NICKNAME, PASSWORD).unwrap();
    let second = seed(NICKNAME, PASSWORD).unwrap();

    assert_eq!(*first, *second);
}

#[test]
fn seed_depends_on_the_password() {
    let a = seed(NICKNAME, PASSWORD).unwrap();
    let b = seed(NICKNAME, "a different password").unwrap();

    assert_ne!(*a, *b);
}

#[test]
fn seed_depends_on_the_nickname() {
    let a = seed(NICKNAME, PASSWORD).unwrap();
    let b = seed("someone-else", PASSWORD).unwrap();

    assert_ne!(*a, *b);
}

#[test]
fn seed_treats_the_password_literally() {
    let plain = seed(NICKNAME, "hunter2").unwrap();

    for variant in ["hunter2 ", " hunter2", "Hunter2", "hunter2\n"] {
        let other = seed(NICKNAME, variant).unwrap();
        assert_ne!(*plain, *other, "{variant:?} must not collide with hunter2");
    }
}

#[test]
fn seed_is_case_sensitive_in_the_nickname() {
    let lower = seed("maks", PASSWORD).unwrap();
    let upper = seed("Maks", PASSWORD).unwrap();

    assert_ne!(*lower, *upper);
}

#[test]
fn seed_fills_the_whole_buffer() {
    let derived = seed(NICKNAME, PASSWORD).unwrap();

    assert_ne!(*derived, [0u8; 32], "seed was left uninitialized");
}

#[test]
fn seed_accepts_empty_inputs() {
    let empty_password = seed(NICKNAME, "").unwrap();
    let empty_nickname = seed("", PASSWORD).unwrap();

    assert_ne!(*empty_password, *empty_nickname);
}

// --- identity_key ---

fn public_of(seed: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&identity_key(seed).unwrap()).to_bytes()
}

#[test]
fn identity_key_is_deterministic() {
    let seed = [42u8; 32];

    assert_eq!(public_of(&seed), public_of(&seed));
}

#[test]
fn identity_key_depends_on_the_seed() {
    assert_ne!(public_of(&[1u8; 32]), public_of(&[2u8; 32]));
}

#[test]
fn identity_key_is_not_the_raw_seed() {
    let seed = [42u8; 32];
    let secret = identity_key(&seed).unwrap();

    assert_ne!(secret.to_bytes(), seed);
}

#[test]
fn identity_key_avalanches() {
    let mut seed = [42u8; 32];
    let before = identity_key(&seed).unwrap().to_bytes();

    seed[0] ^= 1;
    let after = identity_key(&seed).unwrap().to_bytes();

    let shared_bytes = before.iter().zip(&after).filter(|(a, b)| a == b).count();

    assert_ne!(before, after);
    assert!(
        shared_bytes < 8,
        "{shared_bytes} of 32 bytes unchanged after a one-bit seed change"
    );
}

#[test]
fn same_credentials_reproduce_the_same_identity() {
    let first = public_of(&seed(NICKNAME, PASSWORD).unwrap());
    let second = public_of(&seed(NICKNAME, PASSWORD).unwrap());

    assert_eq!(first, second);
}

#[test]
fn different_credentials_give_different_identities() {
    let mine = public_of(&seed(NICKNAME, PASSWORD).unwrap());
    let other_password = public_of(&seed(NICKNAME, "another password").unwrap());
    let other_nickname = public_of(&seed("someone-else", PASSWORD).unwrap());

    assert_ne!(mine, other_password);
    assert_ne!(mine, other_nickname);
    assert_ne!(other_password, other_nickname);
}

// --- message_keys ---

fn public_key(byte: u8) -> PublicKey {
    PublicKey::from(&StaticSecret::from([byte; 32]))
}

fn derived(shared: &[u8; 32], epk: &PublicKey, recipient: &PublicKey) -> [u8; 56] {
    let (key, nonce) = message_keys(shared, epk, recipient).unwrap();

    let mut all = [0u8; 56];
    all[..32].copy_from_slice(&*key);
    all[32..].copy_from_slice(&nonce);
    all
}

#[test]
fn message_keys_are_deterministic() {
    let (epk, recipient) = (public_key(1), public_key(2));

    assert_eq!(
        derived(&[9u8; 32], &epk, &recipient),
        derived(&[9u8; 32], &epk, &recipient)
    );
}

#[test]
fn message_keys_depend_on_the_shared_secret() {
    let (epk, recipient) = (public_key(1), public_key(2));

    assert_ne!(
        derived(&[9u8; 32], &epk, &recipient),
        derived(&[10u8; 32], &epk, &recipient)
    );
}

#[test]
fn message_keys_are_bound_to_both_public_keys() {
    let shared = [9u8; 32];
    let baseline = derived(&shared, &public_key(1), &public_key(2));

    assert_ne!(
        baseline,
        derived(&shared, &public_key(3), &public_key(2)),
        "swapping the ephemeral key must change the derived key"
    );
    assert_ne!(
        baseline,
        derived(&shared, &public_key(1), &public_key(3)),
        "swapping the recipient must change the derived key"
    );
}

#[test]
fn message_keys_are_order_sensitive() {
    let shared = [9u8; 32];
    let (a, b) = (public_key(1), public_key(2));

    assert_ne!(derived(&shared, &a, &b), derived(&shared, &b, &a));
}

#[test]
fn key_and_nonce_are_different_slices_of_the_output() {
    let (key, nonce) = message_keys(&[9u8; 32], &public_key(1), &public_key(2)).unwrap();

    assert_ne!(&key[..24], &nonce[..], "nonce must not repeat key bytes");
}

#[test]
fn key_is_not_the_raw_shared_secret() {
    let shared = [9u8; 32];
    let (key, _) = message_keys(&shared, &public_key(1), &public_key(2)).unwrap();

    assert_ne!(*key, shared);
}

#[test]
fn message_keys_avalanche() {
    let (epk, recipient) = (public_key(1), public_key(2));

    let mut shared = [9u8; 32];
    let before = derived(&shared, &epk, &recipient);

    shared[0] ^= 1;
    let after = derived(&shared, &epk, &recipient);

    let unchanged = before.iter().zip(&after).filter(|(a, b)| a == b).count();

    assert!(
        unchanged < 14,
        "{unchanged} of 56 bytes unchanged after a one-bit change"
    );
}
