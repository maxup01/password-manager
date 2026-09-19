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
}
