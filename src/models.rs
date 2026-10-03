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
    pub port_start: i64,
    pub port_end: i64,
    pub max_rules: i64,
    pub auth_version: i64,
    pub view_mode: String,
    pub desired_revision: i64,
    pub applied_revision: i64,
}

impl DbUser {
    pub fn available(&self) -> bool {
        self.enabled
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
    pub port_start: i64,
    pub port_end: i64,
    pub max_rules: i64,
    pub rule_count: i64,
    pub view_mode: String,
    pub desired_revision: i64,
    pub applied_revision: i64,
}

impl UserView {
    pub fn from_user(user: DbUser, rule_count: i64) -> Self {
        Self {
            id: user.id,
            username: user.username,
            role: user.role,
            enabled: user.enabled,
            must_change_password: user.must_change_password,
            expires_at: user.expires_at,
            port_start: user.port_start,
            port_end: user.port_end,
            max_rules: user.max_rules,
            rule_count,
            view_mode: user.view_mode,
            desired_revision: user.desired_revision,
            applied_revision: user.applied_revision,
        }
    }
}
