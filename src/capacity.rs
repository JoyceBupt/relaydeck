use crate::{error::ApiError, linux::BrokerPolicy};
use std::path::Path;

pub fn installed() -> anyhow::Result<Option<i64>> {
    let path = Path::new("/etc/relaydeck/broker.json");
    if !path.try_exists()? {
        return Ok(None);
    }
    crate::linux::secure_root_path(path, false)?;
    anyhow::ensure!(
        std::fs::metadata(path)?.len() <= 16 * 1024,
        "capacity policy too large"
    );
    let policy: BrokerPolicy = serde_json::from_slice(&std::fs::read(path)?)?;
    policy.validate()?;
    Ok(Some(i64::from(policy.max_owners) - 1))
}

pub async fn allocate_slot(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    maximum: Option<i64>,
) -> Result<i64, ApiError> {
    let slots: Vec<i64> = sqlx::query_scalar(
        "SELECT COALESCE(runtime_slot,id) FROM users ORDER BY COALESCE(runtime_slot,id)",
    )
    .fetch_all(&mut **tx)
    .await?;
    let mut slot = 1;
    for used in slots {
        if used != slot {
            break;
        }
        slot += 1;
    }
    if maximum.is_some_and(|count| slot > count + 1) {
        return Err(ApiError::conflict("运行席位已满"));
    }
    sqlx::query("INSERT OR IGNORE INTO runtime_slots(id) VALUES(?)")
        .bind(slot)
        .execute(&mut **tx)
        .await?;
    Ok(slot)
}
