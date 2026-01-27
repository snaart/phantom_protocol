use deadpool_postgres::{Pool, Manager, ManagerConfig, RecyclingMethod};
use tokio_postgres::{NoTls, Config};
use anyhow::Result;
use std::str::FromStr;

#[derive(Clone)]
pub struct Db {
    pool: Pool,
}

impl Db {
    pub async fn new(dsn: &str) -> Result<Self> {
        // Parse DSN to tokio_postgres::Config
        let pg_config = Config::from_str(dsn)?;
        
        // Create Manager
        let mgr = Manager::from_config(pg_config, NoTls, ManagerConfig {
            recycling_method: RecyclingMethod::Fast
        });
        
        let pool = Pool::builder(mgr).max_size(16).build()?;
        
        let client = pool.get().await?;
        client.batch_execute("
            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                group_id BYTEA NOT NULL,
                epoch BIGINT NOT NULL,
                payload BYTEA NOT NULL,
                created_at TIMESTAMP DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_group_epoch ON messages(group_id, epoch);
            
            CREATE TABLE IF NOT EXISTS key_packages (
                identity_hash BYTEA PRIMARY KEY,
                key_package BYTEA NOT NULL,
                created_at TIMESTAMP DEFAULT NOW()
            );
        ").await?;
        
        Ok(Self { pool })
    }

    pub async fn insert_message(&self, group_id: &[u8], epoch: u64, payload: &[u8]) -> Result<()> {
        let client = self.pool.get().await?;
        client.execute(
            "INSERT INTO messages (group_id, epoch, payload) VALUES ($1, $2, $3)",
            &[&group_id, &(epoch as i64), &payload],
        ).await?;
        Ok(())
    }
    
    pub async fn upload_key_package(&self, identity: &[u8], key_package: &[u8]) -> Result<()> {
        let client = self.pool.get().await?;
        // Use hash of identity as PK? Or identity directly? 
        // Identity is usually a public key or hash. Let's assume passed `identity` is unique.
        client.execute(
            "INSERT INTO key_packages (identity_hash, key_package) VALUES ($1, $2)
             ON CONFLICT (identity_hash) DO UPDATE SET key_package = $2, created_at = NOW()",
            &[&identity, &key_package],
        ).await?;
        Ok(())
    }
    
    pub async fn fetch_key_package(&self, identity: &[u8]) -> Result<Option<Vec<u8>>> {
        let client = self.pool.get().await?;
        let row = client.query_opt("SELECT key_package FROM key_packages WHERE identity_hash = $1", &[&identity]).await?;
        match row {
            Some(r) => Ok(Some(r.get(0))),
            None => Ok(None)
        }
    }
}
