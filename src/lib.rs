pub mod api;
pub mod config;
pub mod credentials;
pub mod db;
pub mod error;
pub mod executor;
pub mod limits;
pub mod linux;
pub mod mfa;
pub mod models;
pub mod policy;
pub mod rules;
pub mod tenant;

pub fn health_router() -> axum::Router {
    axum::Router::new().route(
        "/api/health",
        axum::routing::get(|| async {
            axum::Json(serde_json::json!({
                "status": "ok", "name": "RelayDeck", "version": env!("CARGO_PKG_VERSION"),
                "executor": "unconfigured"
            }))
        }),
    )
}
