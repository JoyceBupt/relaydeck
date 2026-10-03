use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
use std::{path::Path, str::FromStr};

pub async fn connect(path: &Path) -> anyhow::Result<SqlitePool> {
    tokio::task::spawn_blocking({
        let path = path.to_path_buf();
        move || -> anyhow::Result<()> {
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                let mut builder = std::fs::DirBuilder::new();
                builder.recursive(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    builder.mode(0o700);
                }
                builder.create(parent)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::{MetadataExt, PermissionsExt};
                    let metadata = std::fs::metadata(parent)?;
                    anyhow::ensure!(
                        metadata.uid() == unsafe { libc::geteuid() } || metadata.uid() == 0,
                        "database directory must be owned by the current user or root"
                    );
                    anyhow::ensure!(
                        metadata.permissions().mode() & 0o022 == 0,
                        "database directory must not be writable by other users"
                    );
                }
            }
            if let Ok(metadata) = std::fs::symlink_metadata(&path) {
                anyhow::ensure!(
                    metadata.is_file() && !metadata.file_type().is_symlink(),
                    "database path must be a regular file"
                );
            }
            let mut options = std::fs::OpenOptions::new();
            options.read(true).write(true).create(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
            }
            let file = options.open(&path)?;
            anyhow::ensure!(
                file.metadata()?.is_file(),
                "database must be a regular file"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                // geteuid has no preconditions and only reads process identity.
                anyhow::ensure!(
                    file.metadata()?.uid() == unsafe { libc::geteuid() },
                    "database must be owned by the current user"
                );
                anyhow::ensure!(
                    file.metadata()?.nlink() == 1,
                    "database must not have hard links"
                );
                file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            Ok(())
        }
    })
    .await??;
    let options = SqliteConnectOptions::from_str("sqlite:")?
        .filename(path)
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal)
        .pragma("trusted_schema", "OFF")
        .pragma("temp_store", "MEMORY")
        .busy_timeout(std::time::Duration::from_secs(5));
    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .connect_with(options)
        .await?;
    sqlx::migrate!().run(&pool).await?;
    Ok(pool)
}

pub async fn close(pool: &SqlitePool) -> anyhow::Result<()> {
    let checkpoint: Result<(i64, i64, i64), _> = sqlx::query_as("PRAGMA wal_checkpoint(TRUNCATE)")
        .fetch_one(pool)
        .await;
    pool.close().await;
    let (busy, _, _) = checkpoint?;
    anyhow::ensure!(
        busy == 0,
        "WAL checkpoint was busy; preserve the database and its sidecars"
    );
    Ok(())
}

pub async fn backup(pool: &SqlitePool, key: &Path, destination: &Path) -> anyhow::Result<()> {
    crate::mfa::MfaService::from_key_file(key)?;
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(destination)?;
    let database = destination.join("relaydeck.db");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(&database)?;
    sqlx::query("VACUUM INTO ?")
        .bind(
            database
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("backup path must be UTF-8"))?,
        )
        .execute(pool)
        .await?;
    file.sync_all()?;
    let bytes = zeroize::Zeroizing::new(std::fs::read(key)?);
    let mut file = options.open(destination.join("mfa.key"))?;
    use std::io::Write;
    file.write_all(&bytes)?;
    file.sync_all()?;
    #[cfg(unix)]
    {
        std::fs::File::open(destination)?.sync_all()?;
    }
    Ok(())
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock precedes Unix epoch")
        .as_secs() as i64
}
