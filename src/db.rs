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
        .busy_timeout(std::time::Duration::from_secs(5));
    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .connect_with(options)
        .await?;
    sqlx::migrate!().run(&pool).await?;
    Ok(pool)
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock precedes Unix epoch")
        .as_secs() as i64
}
