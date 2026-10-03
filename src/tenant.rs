use std::path::Path;

/// Runs inside the broker's systemd unit after all privileges were dropped.
/// Check the absolute deadline after systemd's own startup work has finished.
pub async fn run(realm: &Path, config: &Path, expires_at: i64, uid: u32) -> anyhow::Result<()> {
    run_checked(realm, config, expires_at, uid, None).await
}

pub async fn run_checked(
    realm: &Path,
    config: &Path,
    expires_at: i64,
    uid: u32,
    revision: Option<i64>,
) -> anyhow::Result<()> {
    run_inner(realm, config, expires_at, uid, revision, false).await
}

pub async fn run_plan(
    realm: &Path,
    config: &Path,
    expires_at: i64,
    uid: u32,
    revision: i64,
) -> anyhow::Result<()> {
    run_inner(realm, config, expires_at, uid, Some(revision), true).await
}

async fn run_inner(
    realm: &Path,
    config: &Path,
    expires_at: i64,
    uid: u32,
    revision: Option<i64>,
    supervisor: bool,
) -> anyhow::Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (realm, config, expires_at, uid, revision, supervisor);
        anyhow::bail!("the tenant runner requires Linux");
    }
    #[cfg(target_os = "linux")]
    {
        use anyhow::{Context, ensure};
        use std::time::{Duration, SystemTime, UNIX_EPOCH};
        use tokio::time::Instant;
        ensure!(uid >= 60000, "invalid tenant identity");
        ensure!(
            unsafe { libc::geteuid() } == uid && unsafe { libc::getegid() } == uid,
            "tenant runner must already have its dedicated UID and GID"
        );
        ensure!(expires_at >= 0, "invalid absolute expiry");
        validate_root_file(realm)?;
        validate_root_file(config)?;
        let authorization = config
            .parent()
            .context("missing runtime directory")?
            .join("authorization");
        validate_root_file(&authorization)?;
        let mut authorized_until: i64 = std::fs::read_to_string(&authorization)?.parse()?;
        ensure!(
            authorized_until > crate::db::now() && authorized_until - crate::db::now() <= 300,
            "invalid runtime authorization"
        );
        let mut authorization_deadline = Instant::now()
            + Duration::from_secs((authorized_until - crate::db::now()).max(0) as u64);
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
        let ready = config
            .parent()
            .context("missing runtime directory")?
            .join("bind-ready");
        let wait_until = Instant::now() + Duration::from_secs(10);
        loop {
            if ready.try_exists()? {
                validate_root_file(&ready)?;
                let value: i64 = std::fs::read_to_string(&ready)?.parse()?;
                if value > 0 && revision.is_none_or(|revision| value == revision) {
                    break;
                }
            }
            ensure!(
                Instant::now() < wait_until,
                "bind guard did not become ready"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        ensure!(
            (expires_at == 0 || expires_at > crate::db::now())
                && authorized_until > crate::db::now()
                && Instant::now() < authorization_deadline,
            "runtime authorization expired during bind-guard startup"
        );
        let mut children = Children::default();
        let mut applied = 0;
        if supervisor {
            applied = children
                .apply(realm, config, expires_at, uid, revision.unwrap())
                .await?;
        } else {
            children.legacy = Some(spawn(realm, config)?);
        }
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let mut clock_check = tokio::time::interval(Duration::from_millis(250));
        clock_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = async {
                    if let Some(deadline) = deadline { tokio::time::sleep_until(deadline).await; }
                    else { std::future::pending::<()>().await; }
                } => break,
                _ = clock_check.tick() => {
                    // A forward wall-clock adjustment must also revoke promptly.
                    if expires_at != 0 && crate::db::now() >= expires_at { break; }
                    let renewed = (|| -> anyhow::Result<i64> {
                        validate_root_file(&authorization)?;
                        let value: i64=std::fs::read_to_string(&authorization)?.parse()?;
                        ensure!(value-crate::db::now()<=300,"invalid authorization deadline");
                        Ok(value)
                    })();
                    let Ok(until)=renewed else { break; };
                    if until>authorized_until {
                        authorized_until=until;
                        authorization_deadline=Instant::now()+Duration::from_secs((until-crate::db::now()).max(0) as u64);
                    }
                    if until<=crate::db::now() || Instant::now()>=authorization_deadline { break; }
                    children.check()?;
                    if supervisor { applied=children.apply(realm,config,expires_at,uid,applied).await?; }
                }
                _ = terminate.recv() => break,
                _ = tokio::signal::ctrl_c() => break,
            }
        }
        children
            .stop_all()
            .await
            .context("cannot stop expired realm")?;
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

#[cfg(target_os = "linux")]
fn spawn(realm: &Path, config: &Path) -> anyhow::Result<tokio::process::Child> {
    use anyhow::Context;
    validate_root_file(config)?;
    tokio::process::Command::new(realm)
        .args(["-c", config.to_str().context("invalid config path")?])
        .env_clear()
        .env("LANG", "C")
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("cannot start realm")
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct Children {
    rules: std::collections::BTreeMap<i64, (crate::executor::DesiredRule, tokio::process::Child)>,
    legacy: Option<tokio::process::Child>,
}

#[cfg(target_os = "linux")]
impl Children {
    fn check(&mut self) -> anyhow::Result<()> {
        for child in self
            .legacy
            .iter_mut()
            .chain(self.rules.values_mut().map(|(_, child)| child))
        {
            anyhow::ensure!(child.try_wait()?.is_none(), "realm child exited");
        }
        Ok(())
    }
    async fn stop_all(&mut self) -> anyhow::Result<()> {
        let mut error = None;
        for child in self
            .legacy
            .iter_mut()
            .chain(self.rules.values_mut().map(|(_, child)| child))
        {
            if let Err(failure) = child.kill().await {
                error = Some(failure);
            }
        }
        if let Some(error) = error {
            return Err(error.into());
        }
        Ok(())
    }
    async fn apply(
        &mut self,
        realm: &Path,
        path: &Path,
        expiry: i64,
        uid: u32,
        applied: i64,
    ) -> anyhow::Result<i64> {
        use anyhow::{Context, ensure};
        validate_root_file(path)?;
        ensure!(
            std::fs::metadata(path)?.len() <= 128 * 1024,
            "runtime plan too large"
        );
        let plan: crate::executor::RuntimePlan = serde_json::from_slice(&std::fs::read(path)?)?;
        ensure!(
            plan.expires_at().unwrap_or(0) == expiry
                && !plan.stopped()
                && plan.revision() >= applied,
            "invalid supervisor plan"
        );
        if plan.revision() == applied && !self.rules.is_empty() {
            return Ok(applied);
        }
        let directory = path.parent().context("missing plan directory")?;
        let changed: Vec<_> = self
            .rules
            .iter()
            .filter(|(id, (old, _))| {
                !plan.rules().iter().any(|new| {
                    new.id == **id
                        && old.listen_port == new.listen_port
                        && old.target_ip == new.target_ip
                        && old.target_port == new.target_port
                        && old.protocol == new.protocol
                })
            })
            .map(|(id, _)| *id)
            .collect();
        for id in changed {
            let (_, mut child) = self.rules.remove(&id).unwrap();
            child
                .kill()
                .await
                .context("cannot stop changed realm child")?;
        }
        for rule in plan.rules() {
            if let std::collections::btree_map::Entry::Vacant(entry) = self.rules.entry(rule.id) {
                let config = directory.join(format!("rule-{}.json", rule.id));
                entry.insert((rule.clone(), spawn(realm, &config)?));
            }
        }
        // Only this fixed, pre-created file is tenant-writable. The directory,
        // plans, executables and child configurations stay immutable to tenants.
        use std::{
            io::Write,
            os::unix::fs::{MetadataExt, OpenOptionsExt},
        };
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(directory.join("applied-revision"))?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.uid() == uid
                && metadata.nlink() == 1
                && metadata.mode() & 0o077 == 0,
            "invalid supervisor acknowledgement"
        );
        file.set_len(0)?;
        write!(file, "{}", plan.revision())?;
        Ok(plan.revision())
    }
}
