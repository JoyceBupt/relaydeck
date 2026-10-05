use crate::config::Config;
use anyhow::ensure;
use sqlx::SqlitePool;

/// The old installed updater already checks `executor == running`. Make that
/// check include recovery of its pre-upgrade forwarding snapshot, so the first
/// upgrade from an older manager receives the same rollback protection.
pub async fn upgrade_ready(pool: &SqlitePool, config: &Config) -> anyhow::Result<bool> {
    let Some(upgrade) = &config.upgrade else {
        return Ok(true);
    };
    if !upgrade.maintenance.try_exists()? {
        return Ok(true);
    }
    let path = upgrade.maintenance.with_file_name("upgrade-readiness.json");
    crate::linux::secure_root_path(&path, false)?;
    let bytes = tokio::fs::read(&path).await?;
    ensure!(
        bytes.len() <= 4 * 1024 * 1024,
        "upgrade baseline is too large"
    );
    let record: serde_json::Value = serde_json::from_slice(&bytes)?;
    let expected: Vec<(i64, i64, Option<i64>)> = serde_json::from_value(record["rules"].clone())?;
    let observed_after = record["observed_after"]
        .as_i64()
        .ok_or_else(|| anyhow::anyhow!("missing upgrade observation boundary"))?;
    expected_ready(pool, &expected, observed_after).await
}

async fn expected_ready(
    pool: &SqlitePool,
    expected: &[(i64, i64, Option<i64>)],
    observed_after: i64,
) -> anyhow::Result<bool> {
    for (rule, owner, expiry) in expected {
        if expiry.is_some_and(|end| end <= crate::db::now()) {
            continue;
        }
        let ready:i64=sqlx::query_scalar("SELECT COUNT(*) FROM rules r JOIN users u ON u.id=r.owner_id JOIN runtime_states s ON s.owner_id=u.id JOIN rule_runtime_states rs ON rs.rule_id=r.id WHERE r.id=? AND r.owner_id=? AND r.deleted_at IS NULL AND r.enabled=1 AND r.dns_blocked=0 AND u.enabled=1 AND u.traffic_blocked=0 AND s.status='active' AND s.revision=u.desired_revision AND u.applied_revision=u.desired_revision AND rs.revision=u.desired_revision AND rs.active=1 AND rs.observed_at>?")
            .bind(rule).bind(owner).bind((crate::db::now()-20).max(observed_after)).fetch_one(pool).await?;
        if ready != 1 {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn preupgrade_rules_need_fresh_individual_confirmation_and_natural_expiry_is_allowed() {
        let directory = tempfile::tempdir().unwrap();
        let pool = crate::db::connect(&directory.path().join("data/db"))
            .await
            .unwrap();
        sqlx::query("INSERT INTO users(id,username,password_hash,role,port_start,port_end,max_rules,created_at,desired_revision,applied_revision) VALUES(1,'owner','unused','admin',1024,65535,10,0,7,7)").execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO rules(id,owner_id,name,listen_port,target_host,target_ip,target_port,protocol,created_at,updated_at) VALUES(1,1,'active',45001,'8.8.8.8','8.8.8.8',443,'tcp',0,0),(2,1,'failed',45002,'8.8.8.8','8.8.8.8',443,'tcp',0,0)").execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO runtime_states(owner_id,revision,status,updated_at) VALUES(1,7,'active',?)").bind(crate::db::now()).execute(&pool).await.unwrap();
        let expected = [(1, 1, None)];
        assert!(!expected_ready(&pool, &expected, 0).await.unwrap());
        sqlx::query("INSERT INTO rule_runtime_states VALUES(1,7,1,?),(2,7,0,?)")
            .bind(crate::db::now())
            .bind(crate::db::now())
            .execute(&pool)
            .await
            .unwrap();
        // The pre-existing failed rule is deliberately not in the baseline.
        assert!(expected_ready(&pool, &expected, 0).await.unwrap());
        assert!(
            !expected_ready(&pool, &expected, crate::db::now())
                .await
                .unwrap(),
            "pre-restart observations must not pass readiness"
        );
        sqlx::query("UPDATE rule_runtime_states SET active=0 WHERE rule_id=1")
            .execute(&pool)
            .await
            .unwrap();
        assert!(!expected_ready(&pool, &expected, 0).await.unwrap());
        assert!(
            expected_ready(&pool, &[(1, 1, Some(crate::db::now() - 1))], 0)
                .await
                .unwrap()
        );
        sqlx::query("UPDATE rule_runtime_states SET active=1,observed_at=? WHERE rule_id=1")
            .bind(crate::db::now() - 30)
            .execute(&pool)
            .await
            .unwrap();
        assert!(!expected_ready(&pool, &expected, 0).await.unwrap());
        sqlx::query("UPDATE rule_runtime_states SET observed_at=?,revision=6 WHERE rule_id=1")
            .bind(crate::db::now())
            .execute(&pool)
            .await
            .unwrap();
        assert!(!expected_ready(&pool, &expected, 0).await.unwrap());
    }
}
