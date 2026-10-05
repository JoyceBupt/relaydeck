use sqlx::{Sqlite, Transaction};

pub const PERIOD_SECONDS: i64 = 30 * 24 * 60 * 60;

pub async fn next_identity(
    tx: &mut Transaction<'_, Sqlite>,
    name: &str,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("UPDATE identity_sequences SET value=MAX(value,CASE WHEN name='account' THEN (SELECT COALESCE(MAX(id),0) FROM users) WHEN name='rule' THEN (SELECT COALESCE(MAX(id),0) FROM rules) ELSE (SELECT COALESCE(MAX(subscription_id),0) FROM users) END)+1 WHERE name=? RETURNING value")
        .bind(name).fetch_one(&mut **tx).await
}

// Called inside the reconciliation transaction, after a successful driver stop
// and a second current-revision check. Until then the slot and ports stay leased.
pub async fn finalize_deletion(
    tx: &mut Transaction<'_, Sqlite>,
    id: i64,
) -> Result<(), sqlx::Error> {
    let deleting: bool = sqlx::query_scalar("SELECT deletion_requested_at IS NOT NULL AND role='user' AND enabled=0 FROM users WHERE id=?")
        .bind(id).fetch_one(&mut **tx).await?;
    if !deleting {
        return Ok(());
    }
    sqlx::query("INSERT INTO audit_events(actor_id,actor_username,action,resource_id,created_at,resource_kind,resource_name) SELECT NULL,'系统','user_deleted',id,unixepoch(),'user',username FROM users WHERE id=?")
        .bind(id).execute(&mut **tx).await?;
    sqlx::query("UPDATE audit_events SET actor_id=NULL WHERE actor_id=?")
        .bind(id)
        .execute(&mut **tx)
        .await?;
    for table in ["sessions", "mfa_recovery_codes", "authentication_failures"] {
        sqlx::query(&format!("DELETE FROM {table} WHERE user_id=?"))
            .bind(id)
            .execute(&mut **tx)
            .await?;
    }
    for table in ["port_leases", "rules", "apply_jobs", "runtime_states"] {
        sqlx::query(&format!("DELETE FROM {table} WHERE owner_id=?"))
            .bind(id)
            .execute(&mut **tx)
            .await?;
    }
    sqlx::query("DELETE FROM users WHERE id=?")
        .bind(id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
