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
