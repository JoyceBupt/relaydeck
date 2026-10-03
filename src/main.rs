#[tokio::main(worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "relaydeck=info".into()),
        )
        .init();
    let config = relaydeck::config::Config::from_env()?;
    let pool = relaydeck::db::connect(&config.database).await?;
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.as_slice() {
        [command, username] if command == "init-admin" => {
            let password = rpassword::prompt_password("Administrator password: ")?;
            let confirmation = rpassword::prompt_password("Confirm password: ")?;
            anyhow::ensure!(password == confirmation, "passwords do not match");
            relaydeck::api::initialize_admin(&pool, username, password).await?;
            println!("Administrator initialized. No password was stored in command arguments.");
            return Ok(());
        }
        [] => (),
        [command] if command == "serve" => (),
        _ => anyhow::bail!("usage: relaydeck [serve | init-admin <username>]"),
    }
    let state = relaydeck::api::AppState::new(pool, config.clone()).await?;
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    tracing::info!(address = %config.listen, "RelayDeck listening");
    axum::serve(
        listener,
        relaydeck::api::router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    Ok(())
}
