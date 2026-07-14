#![allow(missing_docs)]

use piquel_repository::{Database, DatabaseConfig};
use std::{env, time::Duration};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = env::var("DATABASE_URL")?;
    let database =
        Database::connect(DatabaseConfig::new(&url, 1, Duration::from_secs(10))?).await?;
    database.run_migrations().await?;
    Ok(())
}
