use std::path::Path;

/// Runs inside the broker's systemd unit after all privileges were dropped.
/// Check the absolute deadline after systemd's own startup work has finished.
pub async fn run(realm: &Path, config: &Path, expires_at: i64, uid: u32) -> anyhow::Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (realm, config, expires_at, uid);
        anyhow::bail!("the tenant runner requires Linux");
    }
    #[cfg(target_os = "linux")]
    {
        use anyhow::{Context, ensure};
        use std::{
            process::Stdio,
            time::{Duration, SystemTime, UNIX_EPOCH},
        };
        use tokio::{process::Command, time::Instant};
        ensure!(uid >= 60000, "invalid tenant identity");
        ensure!(
            unsafe { libc::geteuid() } == uid && unsafe { libc::getegid() } == uid,
            "tenant runner must already have its dedicated UID and GID"
        );
        ensure!(expires_at >= 0, "invalid absolute expiry");
        validate_root_file(realm)?;
        validate_root_file(config)?;
        let deadline = if expires_at == 0 {
            None
        } else {
            let expiry = UNIX_EPOCH
                .checked_add(Duration::from_secs(expires_at as u64))
                .context("expiry is out of range")?;
            let remaining = expiry
                .duration_since(SystemTime::now())
                .context("account has expired")?;
            Some(
                Instant::now()
                    .checked_add(remaining)
                    .context("expiry is out of range")?,
            )
        };
        let mut child = Command::new(realm)
            .args(["-c", config.to_str().context("invalid configuration path")?])
            .env_clear()
            .env("LANG", "C")
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .context("cannot start realm")?;
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let mut clock_check = tokio::time::interval(Duration::from_millis(250));
        clock_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                status = child.wait() => {
                    ensure!(status?.success(), "realm exited unsuccessfully");
                    return Ok(());
                }
                _ = async {
                    if let Some(deadline) = deadline { tokio::time::sleep_until(deadline).await; }
                    else { std::future::pending::<()>().await; }
                } => break,
                _ = clock_check.tick() => {
                    // A forward wall-clock adjustment must also revoke promptly.
                    if expires_at != 0 && crate::db::now() >= expires_at { break; }
                }
                _ = terminate.recv() => break,
                _ = tokio::signal::ctrl_c() => break,
            }
        }
        child.kill().await.context("cannot stop expired realm")?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn validate_root_file(path: &Path) -> anyhow::Result<()> {
    use anyhow::ensure;
    use std::{
        fs::OpenOptions,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::{Component, PathBuf},
    };
    ensure!(
        path.is_absolute()
            && path
                .components()
                .all(|component| matches!(component, Component::RootDir | Component::Normal(_))),
        "tenant paths must be absolute without parent traversal"
    );
    let mut current = PathBuf::from("/");
    for component in path.components().skip(1) {
        current.push(component.as_os_str());
        let metadata = std::fs::symlink_metadata(&current)?;
        ensure!(
            metadata.uid() == 0
                && metadata.mode() & 0o022 == 0
                && !metadata.file_type().is_symlink(),
            "tenant paths must be immutable root-owned objects"
        );
        ensure!(
            if current == path {
                metadata.is_file() && metadata.nlink() == 1
            } else {
                metadata.is_dir()
            },
            "invalid tenant path type"
        );
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.nlink() == 1
            && metadata.mode() & 0o022 == 0,
        "invalid tenant file"
    );
    Ok(())
}
