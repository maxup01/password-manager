use redb::{Database, TableDefinition};

const TABLE_NAME: &str = "passwords";

pub(crate) struct DbManager {
    db: Database,
}

impl DbManager {
    pub async fn init() -> Result<Self, redb::Error> {
        const TABLE: TableDefinition<u64, u64> = TableDefinition::new(TABLE_NAME);
        const PASSWORD_MANAGER_DATABASE_PATH: &str = "~/password-manager";

        let db = Database::create(PASSWORD_MANAGER_DATABASE_PATH)?;

        Ok(Self { db })
    }
}
