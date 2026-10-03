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
    let mut failed = false;
    let mut owners = reconciler.pending_owners().await?;
    let renewals:Vec<i64>=sqlx::query_scalar("SELECT s.owner_id FROM runtime_states s JOIN users u ON u.id=s.owner_id WHERE s.status='active' AND s.revision=u.desired_revision AND u.enabled=1 AND (u.expires_at IS NULL OR u.expires_at>?) AND s.updated_at<=?").bind(now()).bind(now()-5).fetch_all(pool).await?;
    for owner in renewals {
        if !owners.contains(&owner) {
            owners.push(owner);
        }
    }
    for owner in owners {
        if let Err(error) = reconciler.reconcile_owner(owner).await {
            failed = true;
            tracing::error!(owner_id=owner,%error,"account reconciliation failed");
            match &error {
                ReconcileError::Database(error) if transient_database(error) => continue,
                _ => return Err(error.into()),
            }
        }
    }
    sqlx::query("INSERT INTO executor_status(id,last_seen,status) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen,status=excluded.status")
        .bind(now()).bind(if failed {"failed"} else {"running"}).execute(pool).await?;
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
    let rows:Vec<(i64,i64,String,String,i64,i64)>=sqlx::query_as("SELECT r.id,r.owner_id,r.target_host,r.target_ip,r.target_port,r.dns_resolved_at FROM rules r JOIN users u ON u.id=r.owner_id WHERE r.enabled=1 AND r.deleted_at IS NULL AND u.enabled=1 AND (u.expires_at IS NULL OR u.expires_at>?) AND r.dns_checked_at<? ORDER BY r.dns_checked_at,r.id LIMIT 4")
        .bind(now()).bind(now()-60).fetch_all(pool).await?;
    for (id, owner, host, old_ip, port, resolved_at) in rows {
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
                let result=sqlx::query("UPDATE rules SET target_ip=?,dns_checked_at=?,dns_resolved_at=?,dns_error=NULL WHERE id=? AND target_host=? AND target_ip=? AND target_port=? AND deleted_at IS NULL AND enabled=1")
                    .bind(&ip).bind(now()).bind(now()).bind(id).bind(&host).bind(&old_ip).bind(port).execute(&mut *tx).await?;
                (
                    result.rows_affected() > 0 && ip != old_ip,
                    "rule_dns_updated",
                )
            }
            Err(error) => {
                let stop = error.code == "target_denied" || now().saturating_sub(resolved_at) > 900;
                let result=sqlx::query("UPDATE rules SET dns_checked_at=?,dns_error=?,enabled=CASE WHEN ? THEN 0 ELSE enabled END WHERE id=? AND target_host=? AND target_ip=? AND target_port=? AND deleted_at IS NULL AND enabled=1")
                    .bind(now()).bind(error.message).bind(stop).bind(id).bind(&host).bind(&old_ip).bind(port).execute(&mut *tx).await?;
                (result.rows_affected() > 0 && stop, "rule_dns_blocked")
            }
        };
        if changed {
            crate::api::enqueue_apply(&mut tx, owner).await?;
            let user: crate::models::DbUser = sqlx::query_as("SELECT * FROM users WHERE id=?")
                .bind(owner)
                .fetch_one(&mut *tx)
                .await?;
            crate::api::record_audit(&mut tx, &user, action, Some(id)).await?;
        }
        tx.commit().await?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn receive_failures(pool: &SqlitePool, driver: &SocketDriver) -> anyhow::Result<()> {
    let events = driver.inspect().await?;
    if events.is_empty() {
        return Ok(());
    }
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    for event in &events {
        let existing: Option<(i64,String)> = sqlx::query_as("SELECT retry_count,status FROM runtime_states WHERE owner_id=? AND revision=? AND revision=(SELECT desired_revision FROM users WHERE id=?)")
            .bind(event.owner).bind(event.revision).bind(event.owner).fetch_optional(&mut *tx).await?;
        let Some((retries, status)) = existing else {
            continue;
        };
        if status == "failed" {
            continue;
        }
        let retry_at = (event.retryable && retries < 3).then(|| now() + (10_i64 << retries.min(3)));
        sqlx::query("UPDATE runtime_states SET status='failed',last_error=?,updated_at=?,retry_count=?,retry_at=? WHERE owner_id=? AND revision=?")
            .bind(&event.message).bind(now()).bind(retries+ i64::from(retry_at.is_some())).bind(retry_at).bind(event.owner).bind(event.revision).execute(&mut *tx).await?;
        sqlx::query("UPDATE apply_jobs SET status='failed' WHERE owner_id=? AND revision=?")
            .bind(event.owner)
            .bind(event.revision)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    driver
        .acknowledge(
            &events
                .iter()
                .map(|event| (event.owner, event.revision))
                .collect::<Vec<_>>(),
        )
        .await
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
        let result = async {
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let tick = async {
                            receive_failures(&pool,&driver).await?;
                            reconcile_tick(&pool,&reconciler).await?;
                            refresh_dns(&pool,&local_ips,|host,port| {let ips=local_ips.clone();async move {crate::rules::resolve_host(&host,port,&ips).await}}).await
                        }.await;
                        if let Err(error) = tick {
                            let transient = error.downcast_ref::<sqlx::Error>().is_some_and(transient_database)
                                || matches!(error.downcast_ref::<ReconcileError>(),Some(ReconcileError::Database(error)) if transient_database(error))
                                || error.downcast_ref::<crate::error::ApiError>().is_some_and(|error|error.code=="busy");
                            if !transient { return Err(error.context("database worker failed")); }
                            tracing::warn!(%error,"database temporarily busy; retrying without stopping unrelated accounts");
                        }
                    }
                    _ = terminate.recv() => break,
                    _ = tokio::signal::ctrl_c() => break,
                }
            }
            Ok::<_,anyhow::Error>(())
        }.await;
        crate::db::close(&pool)
            .await
            .context("close worker database")?;
        result
    }
}
