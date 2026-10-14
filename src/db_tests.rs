use super::*;
use std::path::Path;
use tempfile::TempDir;

fn vault_at(path: &Path) -> DbManager {
    DbManager {
        db: Database::create(path).expect("create vault"),
    }
}

fn temp_vault() -> (DbManager, TempDir) {
    let dir = TempDir::new().expect("temp dir");
    let db = vault_at(&dir.path().join("vault.redb"));

    // The TempDir is returned so the caller keeps it alive; dropping it
    // deletes the database file out from under the open handle.
    (db, dir)
}

// --- store / retrieve -------------------------------------------------------

#[test]
fn store_then_retrieve_round_trips() {
    let (mut db, _dir) = temp_vault();

    db.store("github.com", b"octocat", b"hunter2").unwrap();

    assert_eq!(
        db.retrieve_credentials("github.com").unwrap(),
        Some((b"octocat".to_vec(), b"hunter2".to_vec()))
    );
}

#[test]
fn retrieve_credentials_is_none_for_a_missing_key() {
    let (mut db, _dir) = temp_vault();

    db.store("github.com", b"octocat", b"hunter2").unwrap();

    assert_eq!(db.retrieve_credentials("gitlab.com").unwrap(), None);
}

#[test]
fn store_overwrites_an_existing_key() {
    let (mut db, _dir) = temp_vault();

    db.store("github.com", b"old-login", b"old-password")
        .unwrap();
    db.store("github.com", b"new-login", b"new-password")
        .unwrap();

    assert_eq!(
        db.retrieve_credentials("github.com").unwrap(),
        Some((b"new-login".to_vec(), b"new-password".to_vec()))
    );
    assert_eq!(db.retrieve_keys().unwrap().len(), 1, "no duplicate key");
}

#[test]
fn store_preserves_arbitrary_binary_values() {
    let (mut db, _dir) = temp_vault();

    let login: Vec<u8> = (0u8..=255).collect();
    let password = vec![0u8; 64];

    db.store("binary", &login, &password).unwrap();

    assert_eq!(
        db.retrieve_credentials("binary").unwrap(),
        Some((login, password))
    );
}

#[test]
fn store_accepts_empty_values_and_keys() {
    let (mut db, _dir) = temp_vault();

    db.store("no-login", b"", b"password-only").unwrap();
    db.store("", b"login", b"password").unwrap();

    assert_eq!(
        db.retrieve_credentials("no-login").unwrap(),
        Some((Vec::new(), b"password-only".to_vec()))
    );
    assert_eq!(
        db.retrieve_credentials("").unwrap(),
        Some((b"login".to_vec(), b"password".to_vec()))
    );
}

// --- retrieve_keys ----------------------------------------------------------

#[test]
fn retrieve_keys_lists_every_stored_key() {
    let (mut db, _dir) = temp_vault();

    for name in ["github.com", "chase-bank", "work-vpn"] {
        db.store(name, b"login", b"password").unwrap();
    }

    let mut keys = db.retrieve_keys().unwrap();
    keys.sort();

    assert_eq!(keys, ["chase-bank", "github.com", "work-vpn"]);
}

// --- the fresh-vault behaviour app.rs depends on ----------------------------

#[test]
fn retrieve_keys_on_an_untouched_vault_reports_table_does_not_exist() {
    let (db, _dir) = temp_vault();

    assert!(matches!(
        db.retrieve_keys(),
        Err(redb::Error::TableDoesNotExist(_))
    ));
}

#[test]
fn retrieve_credentials_on_an_untouched_vault_reports_table_does_not_exist() {
    let (db, _dir) = temp_vault();

    assert!(matches!(
        db.retrieve_credentials("anything"),
        Err(redb::Error::TableDoesNotExist(_))
    ));
}

#[test]
fn the_table_exists_after_the_first_write() {
    let (mut db, _dir) = temp_vault();

    db.store("first", b"login", b"password").unwrap();

    assert_eq!(db.retrieve_keys().unwrap(), ["first"]);
    assert_eq!(db.retrieve_credentials("missing").unwrap(), None);
}

// --- delete -----------------------------------------------------------------

#[test]
fn delete_removes_the_entry_and_reports_true() {
    let (mut db, _dir) = temp_vault();

    db.store("github.com", b"octocat", b"hunter2").unwrap();

    assert!(db.delete("github.com").unwrap());
    assert_eq!(db.retrieve_credentials("github.com").unwrap(), None);
    assert!(db.retrieve_keys().unwrap().is_empty());
}

#[test]
fn delete_reports_false_for_a_key_that_was_not_there() {
    let (mut db, _dir) = temp_vault();

    db.store("github.com", b"octocat", b"hunter2").unwrap();

    assert!(!db.delete("gitlab.com").unwrap());
    assert_eq!(db.retrieve_keys().unwrap().len(), 1, "nothing else removed");
}

#[test]
fn delete_leaves_other_entries_alone() {
    let (mut db, _dir) = temp_vault();

    for name in ["one", "two", "three"] {
        db.store(name, b"login", b"password").unwrap();
    }

    assert!(db.delete("two").unwrap());

    let mut keys = db.retrieve_keys().unwrap();
    keys.sort();

    assert_eq!(keys, ["one", "three"]);
}

// --- durability -------------------------------------------------------------

#[test]
fn data_survives_reopening_the_vault() {
    let dir = TempDir::new().expect("temp dir");
    let path = dir.path().join("vault.redb");

    {
        let mut db = vault_at(&path);
        db.store("github.com", b"octocat", b"hunter2").unwrap();
        db.store("doomed", b"login", b"password").unwrap();
        assert!(db.delete("doomed").unwrap());
    }

    let db = vault_at(&path);

    assert_eq!(
        db.retrieve_credentials("github.com").unwrap(),
        Some((b"octocat".to_vec(), b"hunter2".to_vec()))
    );
    assert_eq!(db.retrieve_keys().unwrap(), ["github.com"]);
    assert_eq!(
        db.retrieve_credentials("doomed").unwrap(),
        None,
        "the delete must have been committed too"
    );
}
