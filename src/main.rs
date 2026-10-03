#[tokio::main(worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "relaydeck=info".into()),
        )
        .init();
    let config = relaydeck::config::Config::from_env()?;
    let _pool = relaydeck::db::connect(&config.database).await?;
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    tracing::info!(address = %config.listen, "RelayDeck listening");
    axum::serve(listener, relaydeck::health_router())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
