use serde::Serialize;

#[derive(Clone, sqlx::FromRow)]
pub struct DbUser {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub role: String,
    pub enabled: bool,
    pub must_change_password: bool,
    pub expires_at: Option<i64>,
    pub subscription_id: i64,
    pub subscription_started_at: Option<i64>,
    pub deletion_requested_at: Option<i64>,
    pub port_start: i64,
    pub port_end: i64,
    pub max_rules: i64,
    pub auth_version: i64,
    pub view_mode: String,
    pub desired_revision: i64,
    pub applied_revision: i64,
    pub mfa_secret: Option<String>,
    pub mfa_failures: i64,
    pub mfa_locked_until: i64,
    pub traffic_limit_bytes: Option<i64>,
    pub traffic_mode: String,
    pub traffic_in_bytes: i64,
    pub traffic_out_bytes: i64,
    pub traffic_period_start: Option<i64>,
    pub traffic_reset_at: Option<i64>,
    pub traffic_blocked: bool,
    pub traffic_observed_at: Option<i64>,
    pub traffic_used_bytes: i64,
    pub traffic_ready: bool,
    pub traffic_error: Option<String>,
}

impl DbUser {
    pub fn available(&self) -> bool {
        self.enabled
            && self.deletion_requested_at.is_none()
            && self
                .expires_at
                .is_none_or(|expiry| expiry > crate::db::now())
    }
}

#[derive(Serialize)]
pub struct UserView {
    pub id: i64,
    pub username: String,
    pub role: String,
    pub enabled: bool,
    pub must_change_password: bool,
    pub expires_at: Option<i64>,
    pub subscription_id: i64,
    pub subscription_started_at: Option<i64>,
    pub deletion_requested_at: Option<i64>,
    pub deletion_error: Option<String>,
    pub port_start: i64,
    pub port_end: i64,
    pub max_rules: i64,
    pub rule_count: i64,
    pub view_mode: String,
    pub desired_revision: i64,
    pub applied_revision: i64,
    pub mfa_enabled: bool,
    pub traffic: crate::traffic::TrafficView,
}

impl UserView {
    pub fn from_user(user: DbUser, rule_count: i64) -> Self {
        let traffic = crate::traffic::TrafficView::from_user(&user);
        Self {
            traffic,
            id: user.id,
            username: user.username,
            role: user.role,
            enabled: user.enabled,
            must_change_password: user.must_change_password,
            expires_at: user.expires_at,
            subscription_id: user.subscription_id,
            subscription_started_at: user.subscription_started_at,
            deletion_requested_at: user.deletion_requested_at,
            deletion_error: None,
            port_start: user.port_start,
            port_end: user.port_end,
            max_rules: user.max_rules,
            rule_count,
            view_mode: user.view_mode,
            desired_revision: user.desired_revision,
            applied_revision: user.applied_revision,
            mfa_enabled: user.mfa_secret.is_some(),
        }
    }
}
