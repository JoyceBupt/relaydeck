use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};

pub const DEFAULT_LIMIT: i64 = 100_000_000_000;
pub const MAX_LIMIT: i64 = 1_000_000_000_000_000;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrafficMode {
    #[default]
    Both,
    Ingress,
    Egress,
}

impl TrafficMode {
    pub fn usage(self, incoming: u64, outgoing: u64) -> u64 {
        match self {
            Self::Both => incoming.saturating_add(outgoing),
            Self::Ingress => incoming,
            Self::Egress => outgoing,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Both => "both",
            Self::Ingress => "ingress",
            Self::Egress => "egress",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrafficBudget {
    pub limit_bytes: Option<i64>,
    #[serde(default)]
    pub mode: TrafficMode,
}
impl Default for TrafficBudget {
    fn default() -> Self {
        Self {
            limit_bytes: Some(DEFAULT_LIMIT),
            mode: TrafficMode::Both,
        }
    }
}
impl TrafficBudget {
    pub fn validate(&self) -> Result<(), crate::error::ApiError> {
        if self
            .limit_bytes
            .is_some_and(|limit| !(1..=MAX_LIMIT).contains(&limit))
        {
            return Err(crate::error::ApiError::bad_request(
                "流量额度须为1字节至1000TB",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrafficGrant {
    #[serde(default)]
    pub period: Option<TrafficPeriod>,
    pub owner_id: i64,
    pub budget: TrafficBudget,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrafficPeriod {
    pub id: i64,
    pub start: i64,
    pub end: i64,
}
impl TrafficPeriod {
    pub fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.id > 0 && self.start >= 0 && self.end > self.start,
            "invalid subscription period"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrafficSnapshot {
    #[serde(default)]
    pub period_id: Option<i64>,
    pub owner_id: i64,
    pub budget: TrafficBudget,
    pub in_bytes: u64,
    pub out_bytes: u64,
    pub used_bytes: u64,
    pub period_start: i64,
    pub reset_at: i64,
    pub blocked: bool,
    pub ready: bool,
    pub error: Option<String>,
    pub observed_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrafficView {
    pub limit_bytes: Option<i64>,
    pub mode: String,
    pub in_bytes: i64,
    pub out_bytes: i64,
    pub used_bytes: i64,
    pub period_start: Option<i64>,
    pub reset_at: Option<i64>,
    pub blocked: bool,
    pub observed_at: Option<i64>,
    pub ready: bool,
    pub error: Option<String>,
}
impl TrafficView {
    pub fn from_user(user: &crate::models::DbUser) -> Self {
        Self {
            limit_bytes: user.traffic_limit_bytes,
            mode: user.traffic_mode.clone(),
            in_bytes: user.traffic_in_bytes,
            out_bytes: user.traffic_out_bytes,
            used_bytes: user.traffic_used_bytes,
            period_start: user.subscription_started_at,
            reset_at: user.expires_at,
            blocked: user.traffic_blocked,
            observed_at: user.traffic_observed_at,
            ready: user.traffic_ready,
            error: user.traffic_error.clone(),
        }
    }
}

pub fn utc_month(timestamp: i64) -> anyhow::Result<(i64, i64)> {
    ensure!(timestamp >= 0, "invalid billing timestamp");
    let seconds: libc::time_t = timestamp;
    let mut calendar = std::mem::MaybeUninit::<libc::tm>::uninit();
    unsafe {
        ensure!(
            !libc::gmtime_r(&seconds, calendar.as_mut_ptr()).is_null(),
            "billing calendar conversion failed"
        );
        let mut calendar = calendar.assume_init();
        calendar.tm_mday = 1;
        calendar.tm_hour = 0;
        calendar.tm_min = 0;
        calendar.tm_sec = 0;
        let start = libc::timegm(&mut calendar);
        calendar.tm_mon += 1;
        let next = libc::timegm(&mut calendar);
        ensure!(start >= 0 && next > start, "invalid monthly boundary");
        Ok((start, next))
    }
}

pub fn kernel_values(
    value: &serde_json::Value,
) -> anyhow::Result<std::collections::BTreeMap<String, u64>> {
    let mut values = std::collections::BTreeMap::new();
    for entry in value
        .get("nftables")
        .and_then(|v| v.as_array())
        .context("missing traffic objects")?
    {
        for (kind, field) in [("counter", "bytes"), ("quota", "used")] {
            if let Some(object) = entry.get(kind) {
                ensure!(
                    object.get("table").and_then(|v| v.as_str()) == Some("relaydeck_usage"),
                    "unexpected traffic table"
                );
                let name = object
                    .get("name")
                    .and_then(|v| v.as_str())
                    .context("unnamed traffic object")?;
                let count = object
                    .get(field)
                    .and_then(|v| v.as_u64())
                    .context("invalid traffic byte count")?;
                ensure!(
                    values.insert(name.to_owned(), count).is_none(),
                    "duplicate traffic object"
                );
            }
        }
    }
    Ok(values)
}

#[cfg(target_os = "linux")]
pub mod driver;
