use std::{sync::Arc, time::Duration};

use relaydeck::{
    db,
    executor::{
        DesiredPlan, DesiredRule, DriverError, DriverFuture, ExecutorDriver, ExecutorPolicy,
        Protocol, ReconcileOutcome, Reconciler, RuntimePlan,
    },
};
use serde_json::{Value, json};
use sqlx::SqlitePool;
use tokio::sync::{Mutex, Notify};

fn desired() -> DesiredPlan {
    DesiredPlan {
        traffic: None,
        owner_id: 1,
        revision: 1,
        enabled: true,
        expires_at: None,
        port_start: 41000,
        port_end: 41009,
        max_rules: 3,
        rules: vec![DesiredRule {
            id: 1,
            listen_port: 41000,
            target_ip: "8.8.8.8".parse().unwrap(),
            target_port: 443,
            protocol: Protocol::Both,
            source_cidrs: vec!["203.0.113.7/24".into()],
            enabled: true,
        }],
    }
}

#[test]
fn realm_json_contains_only_numeric_addresses_and_fixed_protocol_options() {
    let mut desired = desired();
    for (protocol, no_tcp, use_udp) in [
        (Protocol::Tcp, false, false),
        (Protocol::Udp, true, true),
        (Protocol::Both, false, true),
    ] {
        desired.rules[0].protocol = protocol;
        desired.rules[0].target_ip = "2606:4700:4700::1111".parse().unwrap();
        let plan = desired.validate(&ExecutorPolicy::default(), 100).unwrap();
        let config: Value = serde_json::from_slice(&plan.realm_json().unwrap()).unwrap();
        assert_eq!(
            config,
            json!({"endpoints":[{
                "listen":"[::]:41000",
                "remote":"[2606:4700:4700::1111]:443",
                "network":{"no_tcp":no_tcp,"use_udp":use_udp,"ipv6_only":false}
            }]})
        );
        assert_eq!(plan.rules()[0].source_cidrs, ["203.0.113.0/24"]);
    }
}

#[test]
fn executor_rechecks_grants_network_policy_cidr_syntax_and_duplicate_ports() {
    let boundary = ExecutorPolicy {
        reserved_ports: vec![41001],
        local_ips: vec!["8.8.4.4".parse().unwrap()],
    };
    for target in ["127.0.0.1", "169.254.169.254", "::ffff:8.8.8.8", "8.8.4.4"] {
        let mut plan = desired();
        plan.rules[0].target_ip = target.parse().unwrap();
        assert!(plan.validate(&boundary, 100).is_err(), "{target}");
    }
    for port in [22, 41001, 41100] {
        let mut plan = desired();
        plan.rules[0].listen_port = port;
        assert!(plan.validate(&boundary, 100).is_err(), "{port}");
    }
    let mut plan = desired();
    plan.rules[0].source_cidrs = vec!["0.0.0.0/0; accept".into()];
    assert!(plan.validate(&boundary, 100).is_err());
    plan = desired();
    let mut other = plan.rules[0].clone();
    other.id = 2;
    plan.rules.push(other);
    assert!(plan.validate(&boundary, 100).is_err());
    plan = desired();
    plan.max_rules = 0;
    assert!(plan.validate(&boundary, 100).is_err());
    plan = desired();
    plan.rules[0].target_port = 0;
    assert!(plan.validate(&boundary, 100).is_err());
}

#[test]
fn expired_or_disabled_accounts_produce_stop_even_with_old_invalid_rules() {
    let mut plan = desired();
    plan.rules[0].target_ip = "127.0.0.1".parse().unwrap();
    plan.rules[0].source_cidrs = vec!["bad-cidr".into()];
    plan.enabled = false;
    assert!(
        plan.validate(&ExecutorPolicy::default(), 100)
            .unwrap()
            .stopped()
    );
    plan.enabled = true;
    plan.expires_at = Some(100);
    assert!(
        plan.validate(&ExecutorPolicy::default(), 100)
            .unwrap()
            .stopped()
    );
    assert!(plan.validate(&ExecutorPolicy::default(), 99).is_err());
    plan.expires_at = None;
    plan.rules[0].enabled = false;
    plan.port_start = 42000;
    plan.port_end = 42009;
    assert!(
        plan.validate(&ExecutorPolicy::default(), 100)
            .unwrap()
            .stopped()
    );
}

#[test]
fn wire_plans_reject_arbitrary_configuration_and_revalidate_recovery_snapshots() {
    let mut encoded = serde_json::to_value(desired()).unwrap();
    encoded["command"] = json!("/bin/sh");
    assert!(serde_json::from_value::<DesiredPlan>(encoded).is_err());
    let mut encoded = serde_json::to_value(desired()).unwrap();
    encoded["rules"][0]["remote_transport"] = json!("tls");
    assert!(serde_json::from_value::<DesiredPlan>(encoded).is_err());
    let runtime = desired().validate(&ExecutorPolicy::default(), 100).unwrap();
    let mut encoded = serde_json::to_value(runtime).unwrap();
    encoded["rules"][0]["target_ip"] = json!("127.0.0.1");
    let recovered: RuntimePlan = serde_json::from_value(encoded).unwrap();
    assert!(
        recovered
            .validate_again(&ExecutorPolicy::default(), 100)
            .is_err()
    );
}

#[derive(Clone, Default)]
struct TestDriver {
    actions: Arc<Mutex<Vec<String>>>,
    block_apply: bool,
    started: Arc<Notify>,
    resume: Arc<Notify>,
    fail_apply: bool,
    temporary_apply: bool,
    fail_stop: bool,
}

impl ExecutorDriver for TestDriver {
    fn apply<'a>(&'a self, plan: &'a RuntimePlan) -> DriverFuture<'a> {
        Box::pin(async move {
            self.actions.lock().await.push(format!(
                "apply:{}:{}",
                plan.owner_id(),
                plan.revision()
            ));
            if self.block_apply {
                self.started.notify_one();
                self.resume.notified().await;
            }
            if self.temporary_apply {
                return Err(DriverError::temporary("broker restarting"));
            }
            if self.fail_apply {
                return Err(DriverError::new("listener\nverification failed"));
            }
            Ok(())
        })
    }

    fn stop(&self, owner_id: i64) -> DriverFuture<'_> {
        Box::pin(async move {
            self.actions.lock().await.push(format!("stop:{owner_id}"));
            if self.fail_stop {
                return Err(DriverError::new("unit stop failed"));
            }
            Ok(())
        })
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    pool: SqlitePool,
}

impl Fixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let pool = db::connect(&directory.path().join("data/relaydeck.db"))
            .await
            .unwrap();
        sqlx::query("CREATE TABLE IF NOT EXISTS runtime_states (owner_id INTEGER PRIMARY KEY REFERENCES users(id),revision INTEGER NOT NULL,status TEXT NOT NULL CHECK(status IN('active','stopped','failed')),last_error TEXT,updated_at INTEGER NOT NULL)")
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO users(id,username,password_hash,role,port_start,port_end,max_rules,desired_revision,created_at) VALUES(1,'alice','not-used','user',41000,41009,3,1,?)")
            .bind(db::now()).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO rules(id,owner_id,name,listen_port,target_host,target_ip,target_port,protocol,source_cidrs,created_at,updated_at) VALUES(1,1,'test',41000,'8.8.8.8','8.8.8.8',443,'both','[\"203.0.113.0/24\"]',?,?)")
            .bind(db::now()).bind(db::now()).execute(&pool).await.unwrap();
        for port in [41000, 41001] {
            sqlx::query(
                "INSERT INTO port_leases(port,owner_id,rule_id,created_at) VALUES(?,1,1,?)",
            )
            .bind(port)
            .bind(db::now())
            .execute(&pool)
            .await
            .unwrap();
        }
        sqlx::query("INSERT INTO apply_jobs(owner_id,revision,created_at) VALUES(1,1,?)")
            .bind(db::now())
            .execute(&pool)
            .await
            .unwrap();
        Self {
            _directory: directory,
            pool,
        }
    }

    fn reconciler(&self, driver: TestDriver) -> Reconciler<TestDriver> {
        Reconciler::new(
            self.pool.clone(),
            ExecutorPolicy::default(),
            driver,
            Duration::from_secs(1),
        )
        .unwrap()
    }

    async fn leases(&self) -> Vec<i64> {
        sqlx::query_scalar("SELECT port FROM port_leases ORDER BY port")
            .fetch_all(&self.pool)
            .await
            .unwrap()
    }

    async fn applied(&self) -> i64 {
        sqlx::query_scalar("SELECT applied_revision FROM users WHERE id=1")
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn confirmed_apply_publishes_revision_and_releases_only_historical_leases() {
    let fixture = Fixture::new().await;
    let driver = TestDriver::default();
    let reconciler = fixture.reconciler(driver.clone());
    assert_eq!(reconciler.pending_owners().await.unwrap(), [1]);
    assert_eq!(
        reconciler.reconcile_owner(1).await.unwrap(),
        ReconcileOutcome::Applied
    );
    assert_eq!(*driver.actions.lock().await, ["apply:1:1"]);
    assert_eq!(fixture.applied().await, 1);
    assert_eq!(fixture.leases().await, [41000]);
    assert!(reconciler.pending_owners().await.unwrap().is_empty());
    let status: String = sqlx::query_scalar("SELECT status FROM runtime_states WHERE owner_id=1")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(status, "active");
}

#[tokio::test]
async fn temporary_database_lock_before_runtime_changes_does_not_stop_accounts() {
    let fixture = Fixture::new().await;
    let driver = TestDriver::default();
    let path: String = sqlx::query_as::<_, (i64, String, String)>("PRAGMA database_list")
        .fetch_one(&fixture.pool)
        .await
        .unwrap()
        .2;
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            sqlx::sqlite::SqliteConnectOptions::new()
                .filename(path)
                .busy_timeout(Duration::from_millis(1)),
        )
        .await
        .unwrap();
    let reconciler = Reconciler::new(
        pool.clone(),
        ExecutorPolicy::default(),
        driver.clone(),
        Duration::from_secs(1),
    )
    .unwrap();
    let tx = fixture.pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
    let error = reconciler.reconcile_owner(1).await.unwrap_err();
    assert!(
        matches!(error,relaydeck::executor::ReconcileError::Database(ref error) if relaydeck::worker::transient_database(error))
    );
    assert!(driver.actions.lock().await.is_empty());
    tx.rollback().await.unwrap();
    assert_eq!(
        reconciler.reconcile_owner(1).await.unwrap(),
        ReconcileOutcome::Applied
    );
    pool.close().await;
}

#[tokio::test]
async fn deleted_rule_releases_port_only_after_confirmed_account_stop() {
    let fixture = Fixture::new().await;
    sqlx::query("UPDATE rules SET deleted_at=?,enabled=0 WHERE id=1")
        .bind(db::now())
        .execute(&fixture.pool)
        .await
        .unwrap();
    let driver = TestDriver::default();
    let reconciler = fixture.reconciler(driver.clone());
    assert_eq!(
        reconciler.reconcile_owner(1).await.unwrap(),
        ReconcileOutcome::Stopped
    );
    assert_eq!(*driver.actions.lock().await, ["stop:1"]);
    assert_eq!(fixture.applied().await, 1);
    assert!(fixture.leases().await.is_empty());
}

#[tokio::test]
async fn failure_stops_runtime_keeps_leases_and_has_no_unbounded_automatic_retry() {
    let fixture = Fixture::new().await;
    let driver = TestDriver {
        fail_apply: true,
        ..Default::default()
    };
    let reconciler = fixture.reconciler(driver.clone());
    assert_eq!(
        reconciler.reconcile_owner(1).await.unwrap(),
        ReconcileOutcome::Failed
    );
    assert_eq!(*driver.actions.lock().await, ["apply:1:1", "stop:1"]);
    assert_eq!(fixture.applied().await, 0);
    assert_eq!(fixture.leases().await, [41000, 41001]);
    assert!(reconciler.pending_owners().await.unwrap().is_empty());
    let (status, error): (String, String) =
        sqlx::query_as("SELECT status,last_error FROM runtime_states WHERE owner_id=1")
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert_eq!(status, "failed");
    assert_eq!(error, "listenerverification failed");
}

#[tokio::test]
async fn a_disable_racing_with_apply_wins_and_cannot_release_or_publish_stale_state() {
    let fixture = Fixture::new().await;
    let driver = TestDriver {
        block_apply: true,
        ..Default::default()
    };
    let reconciler = Arc::new(fixture.reconciler(driver.clone()));
    let task = tokio::spawn({
        let reconciler = reconciler.clone();
        async move { reconciler.reconcile_owner(1).await }
    });
    driver.started.notified().await;
    let mut transaction = fixture.pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
    sqlx::query("UPDATE users SET enabled=0,desired_revision=2 WHERE id=1")
        .execute(&mut *transaction)
        .await
        .unwrap();
    sqlx::query("INSERT INTO apply_jobs(owner_id,revision,created_at) VALUES(1,2,?)")
        .bind(db::now())
        .execute(&mut *transaction)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    driver.resume.notify_one();
    assert_eq!(task.await.unwrap().unwrap(), ReconcileOutcome::StaleStopped);
    assert_eq!(*driver.actions.lock().await, ["apply:1:1", "stop:1"]);
    assert_eq!(fixture.applied().await, 0);
    assert_eq!(fixture.leases().await, [41000, 41001]);
    assert_eq!(
        reconciler.reconcile_owner(1).await.unwrap(),
        ReconcileOutcome::Stopped
    );
    assert_eq!(fixture.applied().await, 2);
    assert_eq!(fixture.leases().await, [41000]);
}

#[tokio::test]
async fn expired_account_is_discovered_without_http_job_and_stops_corrupt_old_rules() {
    let fixture = Fixture::new().await;
    let reconciler = fixture.reconciler(TestDriver::default());
    assert_eq!(
        reconciler.reconcile_owner(1).await.unwrap(),
        ReconcileOutcome::Applied
    );
    sqlx::query("UPDATE users SET expires_at=? WHERE id=1")
        .bind(db::now())
        .execute(&fixture.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE rules SET target_ip='not-a-numeric-IP' WHERE id=1")
        .execute(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(reconciler.pending_owners().await.unwrap(), [1]);
    assert_eq!(
        reconciler.reconcile_owner(1).await.unwrap(),
        ReconcileOutcome::Stopped
    );
    assert!(reconciler.pending_owners().await.unwrap().is_empty());
}

#[tokio::test]
async fn expiry_during_apply_stops_runtime_even_without_revision_change() {
    let fixture = Fixture::new().await;
    let driver = TestDriver {
        block_apply: true,
        ..Default::default()
    };
    let reconciler = Arc::new(fixture.reconciler(driver.clone()));
    let task = tokio::spawn({
        let reconciler = reconciler.clone();
        async move { reconciler.reconcile_owner(1).await }
    });
    driver.started.notified().await;
    sqlx::query("UPDATE users SET expires_at=? WHERE id=1")
        .bind(db::now())
        .execute(&fixture.pool)
        .await
        .unwrap();
    driver.resume.notify_one();
    assert_eq!(task.await.unwrap().unwrap(), ReconcileOutcome::StaleStopped);
    assert_eq!(*driver.actions.lock().await, ["apply:1:1", "stop:1"]);
    assert_eq!(fixture.applied().await, 0);
    assert_eq!(fixture.leases().await, [41000, 41001]);
}

#[tokio::test]
async fn timeout_is_retryable_and_stopped_without_port_release() {
    let fixture = Fixture::new().await;
    let driver = TestDriver {
        block_apply: true,
        ..Default::default()
    };
    let reconciler = Reconciler::new(
        fixture.pool.clone(),
        ExecutorPolicy::default(),
        driver.clone(),
        Duration::from_millis(20),
    )
    .unwrap();
    assert!(matches!(
        reconciler.reconcile_owner(1).await,
        Err(relaydeck::executor::ReconcileError::Temporary(_))
    ));
    assert_eq!(*driver.actions.lock().await, ["apply:1:1", "stop:1"]);
    assert_eq!(fixture.applied().await, 0);
    assert_eq!(fixture.leases().await, [41000, 41001]);
}

#[tokio::test]
async fn failed_stop_is_reported_and_preserves_every_lease() {
    let fixture = Fixture::new().await;
    sqlx::query("UPDATE users SET enabled=0 WHERE id=1")
        .execute(&fixture.pool)
        .await
        .unwrap();
    let driver = TestDriver {
        fail_stop: true,
        ..Default::default()
    };
    let reconciler = fixture.reconciler(driver);
    assert!(reconciler.reconcile_owner(1).await.is_err());
    assert_eq!(fixture.applied().await, 0);
    assert_eq!(fixture.leases().await, [41000, 41001]);
    let status: String = sqlx::query_scalar("SELECT status FROM runtime_states WHERE owner_id=1")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(status, "failed");
}

#[tokio::test]
async fn missing_reservation_never_reaches_driver_apply() {
    let fixture = Fixture::new().await;
    sqlx::query("DELETE FROM port_leases WHERE port=41000")
        .execute(&fixture.pool)
        .await
        .unwrap();
    let driver = TestDriver::default();
    let reconciler = fixture.reconciler(driver.clone());
    assert_eq!(
        reconciler.reconcile_owner(1).await.unwrap(),
        ReconcileOutcome::Failed
    );
    assert_eq!(*driver.actions.lock().await, ["stop:1"]);
    assert_eq!(fixture.applied().await, 0);
    assert_eq!(fixture.leases().await, [41001]);
}

#[tokio::test]
async fn database_finalization_failure_stops_runtime_and_rolls_back_lease_release() {
    let fixture = Fixture::new().await;
    sqlx::query("CREATE TRIGGER prevent_lease_delete BEFORE DELETE ON port_leases BEGIN SELECT RAISE(ABORT,'injected lease cleanup failure'); END")
        .execute(&fixture.pool).await.unwrap();
    let driver = TestDriver::default();
    let reconciler = fixture.reconciler(driver.clone());
    assert!(reconciler.reconcile_owner(1).await.is_err());
    assert_eq!(*driver.actions.lock().await, ["apply:1:1", "stop:1"]);
    assert_eq!(fixture.applied().await, 0);
    assert_eq!(fixture.leases().await, [41000, 41001]);
}

#[tokio::test]
async fn a_new_revision_retries_after_failure_and_disabled_rules_survive_grant_narrowing() {
    let fixture = Fixture::new().await;
    let failed = fixture.reconciler(TestDriver {
        fail_apply: true,
        ..Default::default()
    });
    assert_eq!(
        failed.reconcile_owner(1).await.unwrap(),
        ReconcileOutcome::Failed
    );
    let mut transaction = fixture.pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
    sqlx::query("UPDATE users SET desired_revision=2,port_start=42000,port_end=42009,max_rules=0 WHERE id=1")
        .execute(&mut *transaction).await.unwrap();
    sqlx::query("UPDATE rules SET enabled=0 WHERE id=1")
        .execute(&mut *transaction)
        .await
        .unwrap();
    sqlx::query("INSERT INTO apply_jobs(owner_id,revision,created_at) VALUES(1,2,?)")
        .bind(db::now())
        .execute(&mut *transaction)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    let driver = TestDriver::default();
    let reconciler = fixture.reconciler(driver.clone());
    assert_eq!(reconciler.pending_owners().await.unwrap(), [1]);
    assert_eq!(
        reconciler.reconcile_owner(1).await.unwrap(),
        ReconcileOutcome::Stopped
    );
    assert_eq!(*driver.actions.lock().await, ["stop:1"]);
    assert_eq!(fixture.applied().await, 2);
    assert_eq!(fixture.leases().await, [41000]);
    assert!(reconciler.pending_owners().await.unwrap().is_empty());
}

#[tokio::test]
async fn broker_outage_keeps_jobs_retryable_and_recovers_without_manual_revision() {
    let fixture = Fixture::new().await;
    let driver = TestDriver {
        temporary_apply: true,
        ..Default::default()
    };
    let reconciler = fixture.reconciler(driver.clone());
    relaydeck::worker::reconcile_tick(&fixture.pool, &reconciler)
        .await
        .unwrap();
    assert_eq!(reconciler.pending_owners().await.unwrap(), [1]);
    assert_eq!(*driver.actions.lock().await, ["apply:1:1"]);
    let recovered = fixture.reconciler(TestDriver::default());
    relaydeck::worker::reconcile_tick(&fixture.pool, &recovered)
        .await
        .unwrap();
    assert!(recovered.pending_owners().await.unwrap().is_empty());
    assert_eq!(fixture.applied().await, 1);
}

#[tokio::test]
async fn retry_budget_recovers_after_stability_but_not_each_rapid_restart() {
    let fixture = Fixture::new().await;
    let reconciler = fixture.reconciler(TestDriver::default());
    reconciler.reconcile_owner(1).await.unwrap();
    sqlx::query("UPDATE runtime_states SET status='failed',healthy_since=NULL,retry_count=3 WHERE owner_id=1").execute(&fixture.pool).await.unwrap();
    reconciler.reconcile_owner(1).await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT retry_count FROM runtime_states WHERE owner_id=1")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(count, 3);
    sqlx::query("UPDATE runtime_states SET healthy_since=? WHERE owner_id=1")
        .bind(db::now() - 301)
        .execute(&fixture.pool)
        .await
        .unwrap();
    reconciler.reconcile_owner(1).await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT retry_count FROM runtime_states WHERE owner_id=1")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn failed_stop_does_not_abort_other_owners_reconciliation() {
    let fixture = Fixture::new().await;
    sqlx::query("UPDATE users SET enabled=0 WHERE id=1")
        .execute(&fixture.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO users(id,username,password_hash,role,port_start,port_end,max_rules,desired_revision,created_at) VALUES(2,'bob','unused','user',42000,42009,3,1,?)").bind(db::now()).execute(&fixture.pool).await.unwrap();
    sqlx::query("INSERT INTO rules(id,owner_id,name,listen_port,target_host,target_ip,target_port,protocol,source_cidrs,created_at,updated_at) VALUES(2,2,'second',42000,'1.1.1.1','1.1.1.1',443,'tcp','[]',?,?)").bind(db::now()).bind(db::now()).execute(&fixture.pool).await.unwrap();
    sqlx::query("INSERT INTO port_leases(port,owner_id,rule_id,created_at) VALUES(42000,2,2,?)")
        .bind(db::now())
        .execute(&fixture.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO apply_jobs(owner_id,revision,created_at) VALUES(2,1,?)")
        .bind(db::now())
        .execute(&fixture.pool)
        .await
        .unwrap();
    let driver = TestDriver {
        fail_stop: true,
        ..Default::default()
    };
    let reconciler = fixture.reconciler(driver.clone());
    relaydeck::worker::reconcile_tick(&fixture.pool, &reconciler)
        .await
        .unwrap();
    assert!(
        driver
            .actions
            .lock()
            .await
            .contains(&"apply:2:1".to_string())
    );
    let status: String = sqlx::query_scalar("SELECT status FROM runtime_states WHERE owner_id=2")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(status, "active");
    let heartbeat: String = sqlx::query_scalar("SELECT status FROM executor_status WHERE id=1")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(heartbeat, "running");
}

#[tokio::test]
async fn consecutive_crashes_exhaust_budget_and_later_stability_restores_it() {
    let fixture = Fixture::new().await;
    let reconciler = fixture.reconciler(TestDriver::default());
    reconciler.reconcile_owner(1).await.unwrap();
    let event = relaydeck::broker::Failure {
        owner: 1,
        revision: 1,
        message: "realm crashed".into(),
        retryable: true,
    };
    for expected in 1..=3 {
        relaydeck::worker::record_runtime_failures(&fixture.pool, std::slice::from_ref(&event))
            .await
            .unwrap();
        let state: (i64, Option<i64>) =
            sqlx::query_as("SELECT retry_count,retry_at FROM runtime_states WHERE owner_id=1")
                .fetch_one(&fixture.pool)
                .await
                .unwrap();
        assert_eq!(state.0, expected);
        assert!(state.1.is_some());
        sqlx::query("UPDATE runtime_states SET retry_at=? WHERE owner_id=1")
            .bind(db::now() - 1)
            .execute(&fixture.pool)
            .await
            .unwrap();
        relaydeck::worker::reconcile_tick(&fixture.pool, &reconciler)
            .await
            .unwrap();
    }
    relaydeck::worker::record_runtime_failures(&fixture.pool, std::slice::from_ref(&event))
        .await
        .unwrap();
    let due: Option<i64> =
        sqlx::query_scalar("SELECT retry_at FROM runtime_states WHERE owner_id=1")
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert!(due.is_none());
    assert!(reconciler.pending_owners().await.unwrap().is_empty());
    reconciler.reconcile_owner(1).await.unwrap();
    sqlx::query("UPDATE runtime_states SET healthy_since=? WHERE owner_id=1")
        .bind(db::now() - 301)
        .execute(&fixture.pool)
        .await
        .unwrap();
    reconciler.reconcile_owner(1).await.unwrap();
    relaydeck::worker::record_runtime_failures(&fixture.pool, std::slice::from_ref(&event))
        .await
        .unwrap();
    let state: (i64, Option<i64>) =
        sqlx::query_as("SELECT retry_count,retry_at FROM runtime_states WHERE owner_id=1")
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert_eq!(state.0, 1);
    assert!(state.1.is_some());
}
