use rusqlite::{Connection, Result};
use std::path::Path;
use anyhow::{Context, Result as AnyResult};

pub struct StorageEngine {
    conn: Connection,
}

impl StorageEngine {
    pub fn open<P: AsRef<Path>>(path: P, key: &str) -> AnyResult<Self> {
        let mut conn = Connection::open(path).context("Failed to open DB")?;
        
        // SQLCipher encryption
        // Note: 'key' pragma syntax might vary by binding version, usually pragma_update works.
        conn.pragma_update(None, "key", &key).context("Failed to set DB key")?;
        
        // Performance settings
        conn.pragma_update(None, "journal_mode", &"WAL").context("Failed to set WAL")?;
        conn.pragma_update(None, "synchronous", &"NORMAL").context("Failed to set synchronous")?;
        conn.pragma_update(None, "mmap_size", &268435456).context("Failed to set mmap_size")?; // 256MB
        
        // Enforce validations
        conn.pragma_update(None, "foreign_keys", &"ON")?;
        
        Self::migrate(&conn)?;
        
        Ok(Self { conn })
    }

    fn migrate(conn: &Connection) -> AnyResult<()> {
        // Table for entire MlsGroup serialization
        conn.execute(
            "CREATE TABLE IF NOT EXISTS mls_groups (
                group_id BLOB PRIMARY KEY,
                state BLOB NOT NULL,
                updated_at INTEGER DEFAULT (unixepoch())
            )",
            [],
        ).context("Failed to create mls_groups")?;
        
        // message_log stores compressed blobs
        conn.execute(
            "CREATE TABLE IF NOT EXISTS message_log (
                group_id TEXT,
                epoch INTEGER,
                content BLOB,
                received_at INTEGER DEFAULT (unixepoch()),
                PRIMARY KEY (group_id, epoch)
            )",
            [],
        ).context("Failed to create message_log")?;
        
        Ok(())
    }
    
    pub fn save_group_state(&self, group_id: &[u8], state: &[u8]) -> AnyResult<()> {
         self.conn.execute(
             "INSERT INTO mls_groups (group_id, state, updated_at) VALUES (?1, ?2, unixepoch())
              ON CONFLICT(group_id) DO UPDATE SET state = excluded.state, updated_at = unixepoch()",
             (group_id, state),
         ).context("Failed to save group state")?;
         Ok(())
    }
    
    pub fn load_group_state(&self, group_id: &[u8]) -> AnyResult<Option<Vec<u8>>> {
        let mut stmt = self.conn.prepare("SELECT state FROM mls_groups WHERE group_id = ?1")?;
        let mut rows = stmt.query([group_id])?;
        
        if let Some(row) = rows.next()? {
            let state: Vec<u8> = row.get(0)?;
            Ok(Some(state))
        } else {
            Ok(None)
        }
    }
}
