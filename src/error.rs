use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

impl ApiError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_input",
            message: message.into(),
        }
    }
    pub fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthorized",
            message: "请重新登录".into(),
        }
    }
    pub fn forbidden() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "forbidden",
            message: "无操作权限".into(),
        }
    }
    pub fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: "记录不存在".into(),
        }
    }
    pub fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "conflict",
            message: message.into(),
        }
    }
    pub fn unavailable() -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "busy",
            message: "服务繁忙，请稍后重试".into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({"error": {"code":self.code,"message":self.message}})),
        )
            .into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        if error
            .as_database_error()
            .is_some_and(|e| e.is_unique_violation())
        {
            return Self::conflict("名称或端口已被占用");
        }
        tracing::error!(error = %error, "database operation failed");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "database_error",
            message: "数据操作失败".into(),
        }
    }
}

impl From<crate::policy::PolicyError> for ApiError {
    fn from(error: crate::policy::PolicyError) -> Self {
        Self::bad_request(error.to_string())
    }
}

impl From<crate::credentials::CredentialError> for ApiError {
    fn from(error: crate::credentials::CredentialError) -> Self {
        if matches!(error, crate::credentials::CredentialError::Busy) {
            return Self::unavailable();
        }
        tracing::error!(error = %error, "credential operation failed");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "credential_error",
            message: "认证处理失败".into(),
        }
    }
}

impl From<crate::mfa::MfaError> for ApiError {
    fn from(error: crate::mfa::MfaError) -> Self {
        match error {
            crate::mfa::MfaError::AlreadyEnabled => Self::conflict("双因素已启用"),
            crate::mfa::MfaError::Database(error) => error.into(),
            _ => {
                tracing::error!("MFA operation failed");
                Self::unavailable()
            }
        }
    }
}
