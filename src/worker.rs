#[cfg(target_os = "linux")]
use crate::broker::SocketDriver;
use crate::{
    db::now,
    executor::{ExecutorDriver, ReconcileError, Reconciler},
};
#[cfg(target_os = "linux")]
use anyhow::Context;
use sqlx::SqlitePool;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::{sync::Arc, time::Duration};

pub fn transient_database(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::PoolTimedOut)
        || error
            .as_database_error()
            .and_then(|error| error.code())
            .and_then(|code| code.parse::<i32>().ok())
            .is_some_and(|code| matches!(code & 255, 5 | 6))
}

pub async fn reconcile_tick<D: ExecutorDriver>(
    pool: &SqlitePool,
    reconciler: &Reconciler<D>,
) -> anyhow::Result<()> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    sqlx::query("UPDATE apply_jobs SET status='pending' WHERE EXISTS(SELECT 1 FROM runtime_states s JOIN users u ON u.id=s.owner_id WHERE s.owner_id=apply_jobs.owner_id AND s.revision=apply_jobs.revision AND s.revision=u.desired_revision AND s.status='failed' AND s.retry_at<=? AND s.retry_count<=3 AND u.enabled=1 AND (u.expires_at IS NULL OR u.expires_at>?))")
        .bind(now()).bind(now()).execute(&mut *tx).await?;
    sqlx::query("UPDATE runtime_states SET retry_at=NULL WHERE retry_at<=?")
        .bind(now())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let mut owners = reconciler.pending_owners().await?;
    let renewals:Vec<i64>=sqlx::query_scalar("SELECT s.owner_id FROM runtime_states s JOIN users u ON u.id=s.owner_id WHERE s.status='active' AND s.revision=u.desired_revision AND u.enabled=1 AND (u.expires_at IS NULL OR u.expires_at>?) AND s.updated_at<=?").bind(now()).bind(now()-5).fetch_all(pool).await?;
    for owner in renewals {
        if !owners.contains(&owner) {
            owners.push(owner);
        }
    }
    for owner in owners {
        if let Err(error) = reconciler.reconcile_owner(owner).await {
            tracing::error!(owner_id=owner,%error,"account reconciliation failed");
            match &error {
                ReconcileError::Temporary(_) | ReconcileError::Stop(_) => continue,
                ReconcileError::Database(error) if transient_database(error) => continue,
                _ => return Err(error.into()),
            }
        }
    }
    sqlx::query("INSERT INTO executor_status(id,last_seen,status) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen,status=excluded.status")
        .bind(now()).bind("running").execute(pool).await?;
    Ok(())
}

pub async fn record_traffic(
    pool: &SqlitePool,
    snapshots: &[crate::traffic::TrafficSnapshot],
) -> anyhow::Result<()> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    for snapshot in snapshots {
        let previous:Option<(i64,bool,Option<i64>,bool)>=sqlx::query_as("SELECT id,traffic_blocked,traffic_period_start,traffic_ready FROM users WHERE COALESCE(runtime_slot,id)=? AND traffic_limit_bytes IS ? AND traffic_mode=? AND subscription_id=? AND subscription_started_at=? AND COALESCE(expires_at,9223372036854775807)=? AND deletion_requested_at IS NULL AND (traffic_observed_at IS NULL OR traffic_observed_at<=?)")
            .bind(snapshot.owner_id).bind(snapshot.budget.limit_bytes).bind(snapshot.budget.mode.as_str()).bind(snapshot.period_id).bind(snapshot.period_start).bind(snapshot.reset_at).bind(snapshot.observed_at).fetch_optional(&mut *tx).await?;
        let Some((owner_id, blocked, period, ready)) = previous else {
            continue;
        };
        let signed = |value: u64| value.min(i64::MAX as u64) as i64;
        sqlx::query("UPDATE users SET traffic_in_bytes=?,traffic_out_bytes=?,traffic_used_bytes=?,traffic_period_start=?,traffic_reset_at=?,traffic_blocked=?,traffic_ready=?,traffic_error=?,traffic_observed_at=? WHERE id=?")
            .bind(signed(snapshot.in_bytes)).bind(signed(snapshot.out_bytes)).bind(signed(snapshot.used_bytes)).bind(snapshot.period_start).bind(snapshot.reset_at).bind(snapshot.blocked).bind(snapshot.ready).bind(&snapshot.error).bind(snapshot.observed_at).bind(owner_id).execute(&mut *tx).await?;
        if blocked != snapshot.blocked
            || period != Some(snapshot.period_start)
            || ready != snapshot.ready
        {
            crate::api::enqueue_apply(&mut tx, owner_id).await?;
            if blocked != snapshot.blocked {
                crate::api::record_system_user_audit(
                    &mut tx,
                    if snapshot.blocked {
                        "user_traffic_blocked"
                    } else {
                        "user_traffic_restored"
                    },
                    owner_id,
                )
                .await?;
            }
        }
    }
    tx.commit().await?;
    Ok(())
}

#[cfg(target_os = "linux")]
async fn refresh_traffic(pool: &SqlitePool, driver: &SocketDriver) -> anyhow::Result<()> {
    let rows: Vec<(i64, Option<i64>, String, i64, i64, i64)> =
        sqlx::query_as("SELECT COALESCE(runtime_slot,id),traffic_limit_bytes,traffic_mode,subscription_id,COALESCE(subscription_started_at,created_at),COALESCE(expires_at,9223372036854775807) FROM users ORDER BY id")
            .fetch_all(pool)
            .await?;
    let mut grants = Vec::with_capacity(rows.len());
    for (owner_id, limit_bytes, mode, id, start, end) in rows {
        grants.push(crate::traffic::TrafficGrant {
            period: Some(crate::traffic::TrafficPeriod { id, start, end }),
            owner_id,
            budget: crate::traffic::TrafficBudget {
                limit_bytes,
                mode: serde_json::from_value(mode.into())?,
            },
        });
    }
    for batch in grants.chunks(64) {
        record_traffic(pool, &driver.traffic(batch.to_vec()).await?).await?;
    }
    Ok(())
}

pub async fn refresh_dns<F, Fut>(
    pool: &SqlitePool,
    local_ips: &[std::net::IpAddr],
    resolve: F,
) -> anyhow::Result<()>
where
    F: Fn(String, u16) -> Fut,
    Fut: std::future::Future<Output = Result<String, crate::error::ApiError>>,
{
    let rows:Vec<(i64,i64,String,String,i64,i64,bool)>=sqlx::query_as("SELECT r.id,r.owner_id,r.target_host,r.target_ip,r.target_port,r.dns_resolved_at,r.dns_blocked FROM rules r JOIN users u ON u.id=r.owner_id WHERE r.enabled=1 AND r.deleted_at IS NULL AND u.enabled=1 AND (u.expires_at IS NULL OR u.expires_at>?) AND r.dns_checked_at<? ORDER BY r.dns_checked_at,r.id LIMIT 4")
        .bind(now()).bind(now()-60).fetch_all(pool).await?;
    for (id, owner, host, old_ip, port, resolved_at, was_blocked) in rows {
        if host.parse::<std::net::IpAddr>().is_ok() {
            sqlx::query("UPDATE rules SET dns_checked_at=? WHERE id=?")
                .bind(now())
                .bind(id)
                .execute(pool)
                .await?;
            continue;
        }
        let answer = resolve(host.clone(), port as u16).await.and_then(|ip| {
            let parsed = ip
                .parse()
                .map_err(|_| crate::error::ApiError::bad_request("目标解析无效"))?;
            crate::policy::validate_target_ip(parsed, local_ips).map_err(|error| {
                crate::error::ApiError {
                    status: axum::http::StatusCode::BAD_REQUEST,
                    code: "target_denied",
                    message: error.to_string(),
                }
            })?;
            Ok(ip)
        });
        let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
        let (changed, action) = match answer {
            Ok(ip) => {
                let result=sqlx::query("UPDATE rules SET target_ip=?,dns_checked_at=?,dns_resolved_at=?,dns_error=NULL,dns_blocked=0 WHERE id=? AND target_host=? AND target_ip=? AND target_port=? AND deleted_at IS NULL AND enabled=1")
                    .bind(&ip).bind(now()).bind(now()).bind(id).bind(&host).bind(&old_ip).bind(port).execute(&mut *tx).await?;
                (
                    result.rows_affected() > 0 && (ip != old_ip || was_blocked),
                    if was_blocked {
                        "rule_dns_restored"
                    } else {
                        "rule_dns_updated"
                    },
                )
            }
            Err(error) => {
                let stop = error.code == "target_denied" || now().saturating_sub(resolved_at) > 900;
                let result=sqlx::query("UPDATE rules SET dns_checked_at=?,dns_error=?,dns_blocked=CASE WHEN ? THEN 1 ELSE dns_blocked END WHERE id=? AND target_host=? AND target_ip=? AND target_port=? AND deleted_at IS NULL AND enabled=1")
                    .bind(now()).bind(error.message).bind(stop).bind(id).bind(&host).bind(&old_ip).bind(port).execute(&mut *tx).await?;
                (
                    result.rows_affected() > 0 && stop && !was_blocked,
                    "rule_dns_blocked",
                )
            }
        };
        if changed {
            crate::api::enqueue_apply(&mut tx, owner).await?;
            crate::api::record_system_audit(&mut tx, action, id).await?;
        }
        tx.commit().await?;
    }
    Ok(())
}

pub async fn record_rule_states(
    pool: &SqlitePool,
    states: &[crate::broker::RuleStatus],
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    for state in states {
        sqlx::query("INSERT INTO rule_runtime_states(rule_id,revision,active,observed_at) SELECT r.id,?,?,? FROM rules r JOIN users u ON u.id=r.owner_id WHERE r.id=? AND COALESCE(u.runtime_slot,u.id)=? AND u.desired_revision=? AND r.deleted_at IS NULL ON CONFLICT(rule_id) DO UPDATE SET revision=excluded.revision,active=excluded.active,observed_at=excluded.observed_at WHERE rule_runtime_states.observed_at<=excluded.observed_at")
            .bind(state.revision).bind(state.active).bind(state.observed_at).bind(state.rule_id).bind(state.owner).bind(state.revision).execute(&mut *tx).await?;
    }
    tx.commit().await
}

#[cfg(target_os = "linux")]
async fn observe_rules(pool: &SqlitePool, driver: &SocketDriver) -> anyhow::Result<()> {
    let slots:Vec<i64>=sqlx::query_scalar("SELECT COALESCE(runtime_slot,id) FROM users WHERE enabled=1 AND deletion_requested_at IS NULL").fetch_all(pool).await?;
    for batch in slots.chunks(16) {
        record_rule_states(pool, &driver.rule_states(batch.to_vec()).await?).await?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn receive_failures(pool: &SqlitePool, driver: &SocketDriver) -> anyhow::Result<()> {
    let events = driver.inspect().await?;
    if events.is_empty() {
        return Ok(());
    }
    record_runtime_failures(pool, &events).await?;
    driver
        .acknowledge(
            &events
                .iter()
                .map(|event| (event.owner, event.revision))
                .collect::<Vec<_>>(),
        )
        .await
}

/// Persist broker failures separately from transport outages; backoff is scoped
/// to consecutive crashes of the currently authorized revision.
pub async fn record_runtime_failures(
    pool: &SqlitePool,
    events: &[crate::broker::Failure],
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    for event in events {
        let owner_id: Option<i64> = sqlx::query_scalar(
            "SELECT id FROM users WHERE COALESCE(runtime_slot,id)=? AND desired_revision=?",
        )
        .bind(event.owner)
        .bind(event.revision)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(owner_id) = owner_id else {
            continue;
        };
        let existing: Option<(i64,String)> = sqlx::query_as("SELECT retry_count,status FROM runtime_states WHERE owner_id=? AND revision=? AND revision=(SELECT desired_revision FROM users WHERE id=?)")
            .bind(owner_id).bind(event.revision).bind(owner_id).fetch_optional(&mut *tx).await?;
        let Some((retries, status)) = existing else {
            continue;
        };
        if status == "failed" {
            continue;
        }
        let retry_at = (event.retryable && retries < 3).then(|| now() + (10_i64 << retries.min(3)));
        sqlx::query("UPDATE runtime_states SET status='failed',healthy_since=NULL,last_error=?,updated_at=?,retry_count=?,retry_at=? WHERE owner_id=? AND revision=?")
            .bind(&event.message).bind(now()).bind(retries+ i64::from(retry_at.is_some())).bind(retry_at).bind(owner_id).bind(event.revision).execute(&mut *tx).await?;
        sqlx::query("UPDATE apply_jobs SET status='failed' WHERE owner_id=? AND revision=?")
            .bind(owner_id)
            .bind(event.revision)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

#[cfg(target_os = "linux")]
async fn renewal_loop(pool: SqlitePool, driver: Arc<SocketDriver>) {
    let mut clock = tokio::time::interval(Duration::from_secs(5));
    clock.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        clock.tick().await;
        let renewed=async {
            let revisions:Vec<(i64,i64)>=sqlx::query_as("SELECT COALESCE(u.runtime_slot,u.id),s.revision FROM users u JOIN runtime_states s ON s.owner_id=u.id WHERE u.enabled=1 AND u.deletion_requested_at IS NULL AND u.traffic_blocked=0 AND (u.expires_at IS NULL OR u.expires_at>?) AND s.status='active' AND s.revision=u.desired_revision AND u.applied_revision=u.desired_revision")
                .bind(now()).fetch_all(&pool).await?;
            // An empty renewal is also a broker liveness check.
            if revisions.is_empty() { driver.renew(Vec::new()).await?; }
            for batch in revisions.chunks(64) {driver.renew(batch.to_vec()).await?;}
            sqlx::query("INSERT INTO executor_status(id,last_seen,status) VALUES(1,?,'running') ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen,status=excluded.status").bind(now()).execute(&pool).await?;
            Ok::<(),anyhow::Error>(())
        }.await;
        if let Err(error) = renewed {
            tracing::warn!(%error,"independent runtime renewal deferred");
        }
    }
}

pub async fn run(policy_path: &Path) -> anyhow::Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = policy_path;
        anyhow::bail!("the database worker requires Linux");
    }
    #[cfg(target_os = "linux")]
    {
        crate::linux::secure_root_path(policy_path, false)?;
        anyhow::ensure!(
            std::fs::metadata(policy_path)?.len() <= 16 * 1024,
            "broker policy too large"
        );
        let policy: crate::linux::BrokerPolicy =
            serde_json::from_slice(&std::fs::read(policy_path)?)?;
        policy.validate()?;
        anyhow::ensure!(
            unsafe { libc::geteuid() } == policy.web_uid,
            "database worker must run as web_uid, never root"
        );
        let config = crate::config::Config::from_env()?;
        anyhow::ensure!(
            config.database == policy.database,
            "worker database differs from root policy"
        );
        let pool = crate::db::connect(&config.database).await?;
        let driver = Arc::new(SocketDriver::new(policy.socket_path.clone()));
        let local_ips = config.local_ips.clone();
        let reconciler = Reconciler::new(
            pool.clone(),
            policy.boundary(config.local_ips),
            driver.clone(),
            Duration::from_secs(35),
        )?;
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let mut renewal = tokio::spawn(renewal_loop(pool.clone(), driver.clone()));
        let result = async {
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let tick = async {
                            if let Err(error)=refresh_traffic(&pool,&driver).await {tracing::error!(%error,"traffic synchronization deferred; existing authorizations continue independently");}
                            receive_failures(&pool,&driver).await?;
                            reconcile_tick(&pool,&reconciler).await?;
                            observe_rules(&pool,&driver).await?;
                            refresh_dns(&pool,&local_ips,|host,port| {let ips=local_ips.clone();async move {crate::rules::resolve_host(&host,port,&ips).await}}).await
                        }.await;
                        if let Err(error) = tick {
                            if error.downcast_ref::<crate::broker::BrokerUnavailable>().is_some() {
                                // An outage breaks the observed healthy window,
                                // even when the DB still says the last plan was active.
                                if let Err(database)=sqlx::query("UPDATE runtime_states SET healthy_since=NULL WHERE status='active' AND healthy_since IS NOT NULL").execute(&pool).await {
                                    tracing::warn!(%database,"cannot clear stability window during broker outage");
                                }
                            }
                            let transient = error.downcast_ref::<crate::broker::BrokerUnavailable>().is_some()
                                || error.downcast_ref::<sqlx::Error>().is_some_and(transient_database)
                                || matches!(error.downcast_ref::<ReconcileError>(),Some(ReconcileError::Database(error)) if transient_database(error))
                                || error.downcast_ref::<crate::error::ApiError>().is_some_and(|error|error.code=="busy");
                            if !transient { return Err(error.context("database worker failed")); }
                            tracing::warn!(%error,"database temporarily busy; retrying without stopping unrelated accounts");
                        }
                    }
                    result = &mut renewal => {result?;anyhow::bail!("renewal worker stopped");},
                    _ = terminate.recv() => break,
                    _ = tokio::signal::ctrl_c() => break,
                }
            }
            Ok::<_,anyhow::Error>(())
        }.await;
        let renewal_finished = renewal.is_finished();
        renewal.abort();
        if !renewal_finished {
            let _ = renewal.await;
        }
        crate::db::close(&pool)
            .await
            .context("close worker database")?;
        result
    }
}
