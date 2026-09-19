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
