use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use std::fs;

const TABLE_NAME: &str = "passwords";
const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new(TABLE_NAME);

pub(crate) struct DbManager {
    db: Database,
}

impl DbManager {
    pub fn init() -> Result<Self, redb::Error> {
        const DATABASE_DIRECTORY: &str = ".password-manager";
        const DATABASE_FILE_NAME: &str = "vault.redb";

        let directory = dirs::home_dir()
            .unwrap_or_else(std::env::temp_dir)
            .join(DATABASE_DIRECTORY);

        let _ = fs::create_dir_all(&directory);

        let db = Database::create(directory.join(DATABASE_FILE_NAME))?;

        Ok(Self { db })
    }

    pub fn retrieve_keys(&self) -> Result<Vec<String>, redb::Error> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(TABLE)?;

        table
            .iter()?
            .map(|row| {
                let (key, _) = row?;
                Ok(key.value().to_string())
            })
            .collect()
    }

    pub fn retrieve_password(&self, key: &str) -> Result<Option<Vec<u8>>, redb::Error> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(TABLE)?;

        Ok(table.get(key)?.map(|guard| guard.value().to_vec()))
    }

    pub fn store(&mut self, key: &str, value: &[u8]) -> Result<(), redb::Error> {
        let write_txn = self.db.begin_write()?;

        {
            let mut table = write_txn.open_table(TABLE)?;
            table.insert(key, value)?;
        }

        write_txn.commit()?;

        Ok(())
    }

    pub fn delete(&self, key: &str) -> Result<bool, redb::Error> {
        let write_txn = self.db.begin_write()?;

        let existed = {
            let mut table = write_txn.open_table(TABLE)?;
            table.remove(key)?.is_some()
        };

        write_txn.commit()?;

        Ok(existed)
    }
}
