use crate::executor::{DriverError, DriverFuture, ExecutorDriver, RuntimePlan};
use anyhow::Context;
use anyhow::ensure;
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
    Rules(Vec<i64>),
    Renew(Vec<(i64, i64)>),
    Acknowledge(Vec<(i64, i64)>),
    Check(crate::connectivity::CheckRequest),
    Traffic(Vec<crate::traffic::TrafficGrant>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Failure {
    pub owner: i64,
    pub revision: i64,
    pub message: String,
    pub retryable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleStatus {
    pub owner: i64,
    pub revision: i64,
    pub rule_id: i64,
    pub active: bool,
    pub observed_at: i64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    error: Option<String>,
    #[serde(default)]
    retryable: bool,
    events: Vec<Failure>,
    check: Option<crate::connectivity::RuleCheck>,
    traffic: Option<Vec<crate::traffic::TrafficSnapshot>>,
    #[serde(default)]
    rules: Vec<RuleStatus>,
}

impl crate::connectivity::CheckChannel for SocketDriver {
    fn check(
        &self,
        request: crate::connectivity::CheckRequest,
    ) -> crate::connectivity::CheckFuture<'_> {
        Box::pin(async move {
            self.request(Request::Check(request))
                .await?
                .check
                .context("broker omitted connectivity result")
        })
    }
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

#[derive(Debug, thiserror::Error)]
#[error("broker temporarily unavailable: {0}")]
pub struct BrokerUnavailable(pub String);

fn transport(error: std::io::Error) -> anyhow::Error {
    BrokerUnavailable(error.to_string()).into()
}
fn driver_error(error: anyhow::Error) -> DriverError {
    if error.downcast_ref::<BrokerUnavailable>().is_some() {
        DriverError::temporary(error.to_string())
    } else {
        DriverError::new(error.to_string())
    }
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
        let path = if matches!(request, Request::Renew(_)) {
            self.path.with_file_name("renew.sock")
        } else {
            self.path.clone()
        };
        let operation = async {
            let mut stream = tokio::net::UnixStream::connect(&path)
                .await
                .map_err(transport)?;
            ensure!(stream.peer_cred()?.uid() == 0, "broker peer must be root");
            write_frame(&mut stream, &request).await.map_err(|error| {
                if error.downcast_ref::<std::io::Error>().is_some() {
                    BrokerUnavailable(error.to_string()).into()
                } else {
                    error
                }
            })?;
            let reply: Reply = read_frame(&mut stream).await.map_err(|error| {
                if error.downcast_ref::<std::io::Error>().is_some() {
                    BrokerUnavailable(error.to_string()).into()
                } else {
                    error
                }
            })?;
            if let Some(error) = &reply.error {
                if reply.retryable {
                    return Err(BrokerUnavailable(error.clone()).into());
                }
                anyhow::bail!("root broker: {error}");
            }
            Ok(reply)
        };
        tokio::time::timeout(Duration::from_secs(35), operation)
            .await
            .map_err(|_| BrokerUnavailable("request timed out".into()))?
    }
    #[cfg(not(unix))]
    async fn request(&self, _request: Request) -> anyhow::Result<Reply> {
        anyhow::bail!("Unix sockets are required")
    }
    pub async fn renew(&self, revisions: Vec<(i64, i64)>) -> anyhow::Result<()> {
        self.request(Request::Renew(revisions)).await?;
        Ok(())
    }
    pub async fn rule_states(&self, owners: Vec<i64>) -> anyhow::Result<Vec<RuleStatus>> {
        Ok(self.request(Request::Rules(owners)).await?.rules)
    }
    pub async fn inspect(&self) -> anyhow::Result<Vec<Failure>> {
        Ok(self.request(Request::Inspect).await?.events)
    }
    pub async fn acknowledge(&self, events: &[(i64, i64)]) -> anyhow::Result<()> {
        self.request(Request::Acknowledge(events.to_vec())).await?;
        Ok(())
    }
    pub async fn traffic(
        &self,
        grants: Vec<crate::traffic::TrafficGrant>,
    ) -> anyhow::Result<Vec<crate::traffic::TrafficSnapshot>> {
        self.request(Request::Traffic(grants))
            .await?
            .traffic
            .context("broker omitted traffic state")
    }
}

impl ExecutorDriver for SocketDriver {
    fn apply<'a>(&'a self, plan: &'a RuntimePlan) -> DriverFuture<'a> {
        Box::pin(async move {
            self.request(Request::Apply(plan.clone()))
                .await
                .map(|_| ())
                .map_err(driver_error)
        })
    }
    fn stop(&self, owner: i64) -> DriverFuture<'_> {
        Box::pin(async move {
            self.request(Request::Stop(owner))
                .await
                .map(|_| ())
                .map_err(driver_error)
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
        let driver = std::sync::Arc::new(LinuxDriver::new(policy.clone()).await?);
        let leases = std::sync::Arc::new(std::sync::Mutex::new(
            BTreeMap::<i64, (RuntimePlan, i64)>::new(),
        ));
        let renew_path = policy.socket_path.with_file_name("renew.sock");
        if let Ok(meta) = std::fs::symlink_metadata(&renew_path) {
            ensure!(
                meta.file_type().is_socket() && meta.uid() == 0 && meta.nlink() == 1,
                "unexpected renewal socket object"
            );
            ensure!(
                tokio::net::UnixStream::connect(&renew_path).await.is_err(),
                "renewal service is already running"
            );
            std::fs::remove_file(&renew_path)?;
        }
        let renew_listener = tokio::net::UnixListener::bind(&renew_path)?;
        let path = std::ffi::CString::new(renew_path.as_os_str().as_encoded_bytes())?;
        ensure!(
            unsafe { libc::chown(path.as_ptr(), 0, policy.web_gid.unwrap_or(policy.web_uid)) } == 0,
            "cannot assign renewal socket group"
        );
        std::fs::set_permissions(&renew_path, std::fs::Permissions::from_mode(0o660))?;
        let renewal_driver = driver.clone();
        let renewal_leases = leases.clone();
        let renewal_policy = policy.clone();
        let mut renewer = tokio::spawn(async move {
            loop {
                let (mut stream, _) = renew_listener.accept().await?;
                if stream.peer_cred()?.uid() != renewal_policy.web_uid {
                    continue;
                }
                // This dedicated socket never queues behind systemd, nft, DNS,
                // connectivity probes or reconciliation. No plan can be created here.
                let request = tokio::time::timeout(
                    Duration::from_secs(1),
                    read_frame::<Request>(&mut stream),
                )
                .await;
                let mut reply = Reply::default();
                let result = (|| -> anyhow::Result<()> {
                    let Ok(Ok(Request::Renew(revisions))) = request else {
                        anyhow::bail!("expected renewal");
                    };
                    ensure!(revisions.len() <= 64, "too many renewals");
                    let mut active = renewal_leases.lock().unwrap();
                    for (owner, revision) in revisions {
                        if let Some((plan, until)) = active.get_mut(&owner)
                            && plan.revision() == revision
                            && *until > crate::db::now()
                            && plan
                                .expires_at()
                                .is_none_or(|expiry| expiry > crate::db::now())
                        {
                            renewal_driver.renew_authorization(plan)?;
                            *until =
                                crate::db::now() + renewal_policy.authorization_ttl_secs as i64;
                        }
                    }
                    Ok(())
                })();
                if let Err(error) = result {
                    reply.error = Some(error.to_string());
                    reply.retryable = true;
                }
                let _ =
                    tokio::time::timeout(Duration::from_secs(1), write_frame(&mut stream, &reply))
                        .await;
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        });
        let mut events: BTreeMap<i64, Failure> = BTreeMap::new();
        let mut blocked: BTreeMap<i64, i64> = BTreeMap::new();
        let mut stopping = std::collections::BTreeSet::new();
        let mut last_check: Option<std::time::Instant> = None;
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        let mut traffic_clock = tokio::time::interval(Duration::from_secs(1));
        traffic_clock.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
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
                                    if stopping.contains(&plan.owner_id()) {
                                        if let Err(error) = driver.stop(plan.owner_id()).await { reply.retryable=true; return Err(error.into()); }
                                        stopping.remove(&plan.owner_id());
                                    }
                                    if let Err(error) = driver.apply(&plan).await {
                                        reply.retryable=error.retryable;
                                        if error.crashed {events.insert(plan.owner_id(),Failure{owner:plan.owner_id(),revision:plan.revision(),message:error.message.clone(),retryable:true});}
                                        leases.lock().unwrap().remove(&plan.owner_id());
                                        let cleanup = driver.stop(plan.owner_id()).await;
                                        if let Err(cleanup) = cleanup { stopping.insert(plan.owner_id()); reply.retryable=true; return Err(anyhow::anyhow!(cleanup).context("failed apply cleanup")); }
                                        return Err(anyhow::anyhow!(error));
                                    }
                                    driver.renew_authorization(&plan)?;
                                    leases.lock().unwrap().insert(plan.owner_id(),(plan.clone(),crate::db::now()+policy.authorization_ttl_secs as i64));
                                    blocked.remove(&plan.owner_id());
                                    events.remove(&plan.owner_id());
                                }
                                Request::Stop(owner) => { leases.lock().unwrap().remove(&owner); if let Err(error)=driver.stop(owner).await { stopping.insert(owner); reply.retryable=true; return Err(error.into()); } stopping.remove(&owner); }
                                Request::Renew(_) => anyhow::bail!("renewals require the dedicated socket"),
                                Request::Rules(owners) => {reply.rules=driver.rule_states(&owners).await?;},
                                Request::Inspect => { reply.events = events.values().cloned().collect(); }
                                Request::Traffic(grants) => {reply.retryable=true;reply.traffic=Some(driver.traffic(&grants).await?);}
                                Request::Check(check) => {
                                    ensure!(leases.lock().unwrap().get(&check.owner_id).is_some_and(|(plan,until)|plan.revision() == check.revision && *until > crate::db::now()), "connectivity authorization is stale");
                                    ensure!(last_check.is_none_or(|time| time.elapsed() >= Duration::from_secs(5)), "connectivity checks are rate limited");
                                    last_check = Some(std::time::Instant::now());
                                    reply.check = Some(driver.check_rule(&check).await?);
                                }
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
                        for owner in stopping.clone() {
                            match driver.stop(owner).await {
                                Ok(()) => { stopping.remove(&owner); }
                                Err(error) => tracing::warn!(owner,%error,"tenant stop remains pending"),
                            }
                        }
                        let expired: Vec<_> = {
                            let mut active=leases.lock().unwrap();
                            let expired:Vec<_>=active.iter().filter(|(_,(_,until))|*until<=crate::db::now()).map(|(owner,(plan,_))|(*owner,plan.revision())).collect();
                            for (owner,_) in &expired {active.remove(owner);}
                            expired
                        };
                        for (owner,revision) in expired {
                            if let Err(error)=driver.stop(owner).await { tracing::error!(owner,%error,"stale tenant isolated; stop will be retried"); stopping.insert(owner); }
                            events.insert(owner,Failure{owner,revision,message:"运行授权已过期".into(),retryable:true});
                        }
                        for (owner,revision,message,retryable) in driver.unhealthy_owners().await {
                            tracing::warn!(owner_id=owner,revision,retryable,%message,"tenant runtime unhealthy");
                            leases.lock().unwrap().remove(&owner);
                            if let Err(error)=driver.stop(owner).await { tracing::error!(owner,%error,"unhealthy tenant isolated; stop will be retried"); stopping.insert(owner); }
                            if !retryable { blocked.insert(owner,revision); }
                            events.insert(owner,Failure{owner,revision,message,retryable});
                        }
                    }
                    _ = traffic_clock.tick() => {
                        if let Err(error)=driver.traffic_month().await {tracing::error!(%error,"traffic period transition deferred");}
                    }
                    result = &mut renewer => { result??; anyhow::bail!("renewal service stopped"); },
                    _ = terminate.recv() => break,
                    _ = tokio::signal::ctrl_c() => break,
                }
            }
            Ok::<_,anyhow::Error>(())
        }.await;
        let renewal_finished = renewer.is_finished();
        renewer.abort();
        if !renewal_finished {
            let _ = renewer.await;
        }
        leases.lock().unwrap().clear();
        let shutdown = driver.shutdown().await;
        std::fs::remove_file(&renew_path)?;
        drop(listener);
        std::fs::remove_file(&policy.socket_path)?;
        result?;
        shutdown
    }
}
