use crate::executor::{DriverError, DriverFuture, ExecutorDriver, RuntimePlan};
use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

const MAX_FRAME: usize = 128 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(
    tag = "op",
    content = "data",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum Request {
    Apply(RuntimePlan),
    Stop(i64),
    Inspect,
    Acknowledge(Vec<(i64, i64)>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Failure {
    pub owner: i64,
    pub revision: i64,
    pub message: String,
    pub retryable: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    error: Option<String>,
    events: Vec<Failure>,
}

#[cfg(unix)]
async fn read_frame<T: serde::de::DeserializeOwned>(
    stream: &mut tokio::net::UnixStream,
) -> anyhow::Result<T> {
    use tokio::io::AsyncReadExt;
    let length = stream.read_u32().await? as usize;
    ensure!(
        length > 0 && length <= MAX_FRAME,
        "invalid broker frame size"
    );
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(unix)]
async fn write_frame<T: Serialize>(
    stream: &mut tokio::net::UnixStream,
    value: &T,
) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= MAX_FRAME, "broker frame too large");
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    Ok(())
}

pub struct SocketDriver {
    path: PathBuf,
}
impl SocketDriver {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
    #[cfg(unix)]
    async fn request(&self, request: Request) -> anyhow::Result<Reply> {
        let operation = async {
            let mut stream = tokio::net::UnixStream::connect(&self.path)
                .await
                .context("connect to root broker")?;
            ensure!(stream.peer_cred()?.uid() == 0, "broker peer must be root");
            write_frame(&mut stream, &request).await?;
            let reply: Reply = read_frame(&mut stream).await?;
            if let Some(error) = &reply.error {
                anyhow::bail!("root broker: {error}");
            }
            Ok(reply)
        };
        tokio::time::timeout(Duration::from_secs(35), operation)
            .await
            .context("broker request timed out")?
    }
    #[cfg(not(unix))]
    async fn request(&self, _request: Request) -> anyhow::Result<Reply> {
        anyhow::bail!("Unix sockets are required")
    }
    pub async fn inspect(&self) -> anyhow::Result<Vec<Failure>> {
        Ok(self.request(Request::Inspect).await?.events)
    }
    pub async fn acknowledge(&self, events: &[(i64, i64)]) -> anyhow::Result<()> {
        self.request(Request::Acknowledge(events.to_vec())).await?;
        Ok(())
    }
}

impl ExecutorDriver for SocketDriver {
    fn apply<'a>(&'a self, plan: &'a RuntimePlan) -> DriverFuture<'a> {
        Box::pin(async move {
            self.request(Request::Apply(plan.clone()))
                .await
                .map(|_| ())
                .map_err(|e| DriverError::new(e.to_string()))
        })
    }
    fn stop(&self, owner: i64) -> DriverFuture<'_> {
        Box::pin(async move {
            self.request(Request::Stop(owner))
                .await
                .map(|_| ())
                .map_err(|e| DriverError::new(e.to_string()))
        })
    }
}

impl ExecutorDriver for std::sync::Arc<SocketDriver> {
    fn apply<'a>(&'a self, plan: &'a RuntimePlan) -> DriverFuture<'a> {
        self.as_ref().apply(plan)
    }
    fn stop(&self, owner: i64) -> DriverFuture<'_> {
        self.as_ref().stop(owner)
    }
}

pub async fn run(policy_path: &Path) -> anyhow::Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = policy_path;
        anyhow::bail!("the root broker requires Linux");
    }
    #[cfg(target_os = "linux")]
    {
        use crate::linux::{BrokerPolicy, LinuxDriver, secure_root_path};
        use std::{
            collections::BTreeMap,
            os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
        };
        ensure!(unsafe { libc::geteuid() } == 0, "broker requires root");
        secure_root_path(policy_path, false)?;
        ensure!(
            std::fs::metadata(policy_path)?.len() <= 16 * 1024,
            "broker policy too large"
        );
        let policy: BrokerPolicy = serde_json::from_slice(&std::fs::read(policy_path)?)?;
        policy.validate()?;
        let parent = policy
            .socket_path
            .parent()
            .context("missing socket parent")?;
        secure_root_path(parent, true)?;
        if let Ok(meta) = std::fs::symlink_metadata(&policy.socket_path) {
            ensure!(
                meta.file_type().is_socket() && meta.uid() == 0 && meta.nlink() == 1,
                "unexpected broker socket object"
            );
            ensure!(
                tokio::net::UnixStream::connect(&policy.socket_path)
                    .await
                    .is_err(),
                "broker is already running"
            );
            std::fs::remove_file(&policy.socket_path)?;
        }
        let listener = tokio::net::UnixListener::bind(&policy.socket_path)?;
        let path = std::ffi::CString::new(policy.socket_path.as_os_str().as_encoded_bytes())?;
        ensure!(
            unsafe { libc::chown(path.as_ptr(), 0, policy.web_gid.unwrap_or(policy.web_uid)) } == 0,
            "cannot assign broker socket group"
        );
        std::fs::set_permissions(&policy.socket_path, std::fs::Permissions::from_mode(0o660))?;
        let driver = LinuxDriver::new(policy.clone()).await?;
        let mut leases: BTreeMap<i64, (i64, i64)> = BTreeMap::new();
        let mut events: BTreeMap<i64, Failure> = BTreeMap::new();
        let mut blocked: BTreeMap<i64, i64> = BTreeMap::new();
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let result = async {
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (mut stream,_) = accepted?;
                        if stream.peer_cred()?.uid() != policy.web_uid { continue; }
                        let request = match tokio::time::timeout(Duration::from_secs(3),read_frame::<Request>(&mut stream)).await {
                            Ok(Ok(request)) => request,
                            _ => continue,
                        };
                        let mut reply = Reply::default();
                        let handled = async {
                            match request {
                                Request::Apply(plan) => {
                                    ensure!(!plan.stopped(),"empty plans must use the stop operation");
                                    ensure!(blocked.get(&plan.owner_id()).is_none_or(|revision| plan.revision() > *revision), "runtime requires a fresh authorized revision");
                                    if let Err(error) = driver.apply(&plan).await {
                                        let cleanup = driver.stop(plan.owner_id()).await;
                                        leases.remove(&plan.owner_id());
                                        cleanup.context("failed apply cleanup")?;
                                        return Err(anyhow::anyhow!(error));
                                    }
                                    driver.renew_authorization(&plan)?;
                                    leases.insert(plan.owner_id(),(plan.revision(),crate::db::now()+policy.authorization_ttl_secs as i64));
                                    blocked.remove(&plan.owner_id());
                                    events.remove(&plan.owner_id());
                                }
                                Request::Stop(owner) => { driver.stop(owner).await?; leases.remove(&owner); }
                                Request::Inspect => { reply.events = events.values().cloned().collect(); }
                                Request::Acknowledge(ack) => {
                                    ensure!(ack.len() <= policy.max_owners as usize,"too many acknowledgements");
                                    for (owner,revision) in ack { if events.get(&owner).is_some_and(|event|event.revision==revision) { events.remove(&owner); } }
                                }
                            }
                            Ok::<_,anyhow::Error>(())
                        }.await;
                        if let Err(error) = handled { reply.error=Some(error.to_string().chars().filter(|c|!c.is_control()).take(240).collect()); }
                        let _ = tokio::time::timeout(Duration::from_secs(3),write_frame(&mut stream,&reply)).await;
                    }
                    _ = interval.tick() => {
                        let expired: Vec<_> = leases.iter().filter(|(_,(_,until))|*until<=crate::db::now()).map(|(owner,(revision,_))|(*owner,*revision)).collect();
                        for (owner,revision) in expired {
                            driver.stop(owner).await.context("cannot stop stale authorization")?;
                            leases.remove(&owner); blocked.insert(owner,revision);
                            events.insert(owner,Failure{owner,revision,message:"运行授权已过期".into(),retryable:false});
                        }
                        for (owner,revision,message,retryable) in driver.unhealthy_owners().await {
                            driver.stop(owner).await.context("cannot stop unhealthy runtime")?;
                            leases.remove(&owner);
                            if !retryable { blocked.insert(owner,revision); }
                            events.insert(owner,Failure{owner,revision,message,retryable});
                        }
                    }
                    _ = terminate.recv() => break,
                    _ = tokio::signal::ctrl_c() => break,
                }
            }
            Ok::<_,anyhow::Error>(())
        }.await;
        let shutdown = driver.shutdown().await;
        drop(listener);
        std::fs::remove_file(&policy.socket_path)?;
        result?;
        shutdown
    }
}
