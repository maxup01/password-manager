use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

const TABLE_NAME: &str = "passwords";
const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new(TABLE_NAME);

pub(crate) struct DbManager {
    db: Database,
}

impl DbManager {
    pub fn init() -> Result<Self, redb::Error> {
        const PASSWORD_MANAGER_DATABASE_PATH: &str = "~/password-manager";

        let db = Database::create(PASSWORD_MANAGER_DATABASE_PATH)?;

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

    pub fn insert(&mut self, key: &str, value: &[u8]) -> Result<(), redb::Error> {
        let write_txn = self.db.begin_write()?;

        {
            let mut table = write_txn.open_table(TABLE)?;
            table.insert(key, value)?;
        }

        write_txn.commit()?;

        Ok(())
    }
}
