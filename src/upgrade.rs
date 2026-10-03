use crate::error::ApiError;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{future::Future, path::PathBuf, pin::Pin, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone)]
pub struct UpgradeConfig {
    pub owner_id: i64,
    pub socket: PathBuf,
    pub maintenance: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerPolicy {
    owner_id: i64,
    web_uid: u32,
    web_gid: u32,
}

pub fn installed_config() -> anyhow::Result<Option<UpgradeConfig>> {
    let path = PathBuf::from("/etc/relaydeck/upgrade.json");
    if !path.try_exists()? {
        return Ok(None);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        for item in path.ancestors() {
            let info = std::fs::symlink_metadata(item)?;
            anyhow::ensure!(
                info.uid() == 0 && info.mode() & 0o022 == 0 && !info.is_symlink(),
                "upgrade owner policy must be root-owned and immutable to the web user"
            );
        }
        let info = std::fs::metadata(&path)?;
        anyhow::ensure!(
            info.is_file() && info.nlink() == 1 && info.len() <= 4096,
            "invalid owner policy file"
        );
        let policy: OwnerPolicy = serde_json::from_slice(&std::fs::read(path)?)?;
        anyhow::ensure!(
            policy.owner_id > 0 && policy.web_uid > 0 && policy.web_gid > 0,
            "invalid owner policy identity"
        );
        anyhow::ensure!(
            unsafe { libc::geteuid() } == policy.web_uid,
            "upgrade policy web UID must match the service identity"
        );
        Ok(Some(UpgradeConfig {
            owner_id: policy.owner_id,
            socket: "/run/relaydeck-upgrade/control.sock".into(),
            maintenance: "/var/lib/relaydeck/upgrade-transaction.json".into(),
        }))
    }
    #[cfg(not(unix))]
    anyhow::bail!("panel upgrades require Unix sockets")
}

pub type UpgradeFuture<'a> = Pin<Box<dyn Future<Output = Result<Value, ApiError>> + Send + 'a>>;
pub trait UpgradeChannel: Send + Sync {
    fn request(&self, request: Value) -> UpgradeFuture<'_>;
}

pub struct SocketChannel(pub PathBuf);
impl UpgradeChannel for SocketChannel {
    fn request(&self, request: Value) -> UpgradeFuture<'_> {
        Box::pin(async move {
            #[cfg(unix)]
            {
                let exchange = async {
                    let mut stream = tokio::net::UnixStream::connect(&self.0).await?;
                    anyhow::ensure!(stream.peer_cred()?.uid() == 0, "upgrader peer must be root");
                    let payload = serde_json::to_vec(&request)?;
                    anyhow::ensure!(payload.len() <= 4096, "upgrade request exceeds limit");
                    stream.write_u32(payload.len() as u32).await?;
                    stream.write_all(&payload).await?;
                    let size = stream.read_u32().await? as usize;
                    anyhow::ensure!(size > 0 && size <= 32768, "upgrade response exceeds limit");
                    let mut data = vec![0; size];
                    stream.read_exact(&mut data).await?;
                    Ok::<Value, anyhow::Error>(serde_json::from_slice(&data)?)
                };
                let reply = match tokio::time::timeout(Duration::from_secs(25), exchange).await {
                    Ok(Ok(reply)) => reply,
                    other => {
                        tracing::warn!(?other, "upgrade service unavailable");
                        return Err(ApiError::unavailable());
                    }
                };
                if reply.get("error").is_some() {
                    return Err(match reply["error"].as_str() {
                        Some("busy") => ApiError::conflict("升级正在进行"),
                        Some("expired") => ApiError::conflict("请重新检查更新"),
                        Some("recovery_required") => ApiError::conflict("升级恢复尚未完成"),
                        Some("invalid") => ApiError::bad_request("升级请求无效"),
                        _ => ApiError::unavailable(),
                    });
                }
                reply.get("data").cloned().ok_or_else(ApiError::unavailable)
            }
            #[cfg(not(unix))]
            Err(ApiError::unavailable())
        })
    }
}

pub fn status_request() -> Value {
    json!({"op":"status"})
}
