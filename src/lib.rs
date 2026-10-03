pub mod config;
pub mod credentials;
pub mod db;
pub mod policy;

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
