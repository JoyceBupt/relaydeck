#[tokio::main(worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "relaydeck=info".into()),
        )
        .init();
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.as_slice() == ["--version"] {
        println!("RelayDeck {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if arguments.as_slice() == ["--help"] {
        println!(
            "relaydeck [serve | init-admin <username> | init-key | migrate | backup <new-directory> | worker <policy.json> | broker <policy.json> | prepare-broker-policy <source.json> <effective.json>]"
        );
        return Ok(());
    }
    if let [command, realm, config, expires_at, uid] = arguments.as_slice()
        && command == "tenant"
    {
        return relaydeck::tenant::run(
            std::path::Path::new(realm),
            std::path::Path::new(config),
            expires_at.parse()?,
            uid.parse()?,
        )
        .await;
    }
    if let [command, realm, config, expires_at, uid, revision] = arguments.as_slice()
        && command == "tenant"
    {
        return relaydeck::tenant::run_checked(
            std::path::Path::new(realm),
            std::path::Path::new(config),
            expires_at.parse()?,
            uid.parse()?,
            Some(revision.parse()?),
        )
        .await;
    }
    if let [command, realm, config, expires_at, uid, revision] = arguments.as_slice()
        && command == "tenant-plan"
    {
        return relaydeck::tenant::run_plan(
            std::path::Path::new(realm),
            std::path::Path::new(config),
            expires_at.parse()?,
            uid.parse()?,
            revision.parse()?,
        )
        .await;
    }
    if let [command, path] = arguments.as_slice()
        && command == "worker"
    {
        return relaydeck::worker::run(std::path::Path::new(path)).await;
    }
    if let [command, path] = arguments.as_slice()
        && command == "broker"
    {
        return relaydeck::linux::run(std::path::Path::new(path)).await;
    }
    if let [command, source, destination] = arguments.as_slice()
        && command == "prepare-broker-policy"
    {
        return relaydeck::linux::prepare_broker_policy(
            std::path::Path::new(source),
            std::path::Path::new(destination),
        );
    }
    let config = relaydeck::config::Config::from_env()?;
    let pool = relaydeck::db::connect(&config.database).await?;
    match arguments.as_slice() {
        [command] if command == "migrate" => {
            relaydeck::db::close(&pool).await?;
            return Ok(());
        }
        [command] if command == "init-key" => {
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE mfa_secret IS NOT NULL OR mfa_pending_secret IS NOT NULL").fetch_one(&pool).await?;
            anyhow::ensure!(
                count == 0,
                "existing MFA enrollment requires the original key; restore its backup"
            );
            relaydeck::mfa::MfaService::create_key_file(&config.mfa_key)?;
            println!("MFA key initialized. Back up this key together with the database.");
            relaydeck::db::close(&pool).await?;
            return Ok(());
        }
        [command, username] if command == "init-admin" => {
            let password = rpassword::prompt_password("Administrator password: ")?;
            let confirmation = rpassword::prompt_password("Confirm password: ")?;
            anyhow::ensure!(password == confirmation, "passwords do not match");
            relaydeck::api::initialize_admin(&pool, username, password).await?;
            if !config.mfa_key.try_exists()? {
                relaydeck::mfa::MfaService::create_key_file(&config.mfa_key)?;
            }
            println!("Administrator initialized. No password was stored in command arguments.");
            relaydeck::db::close(&pool).await?;
            return Ok(());
        }
        [command, destination] if command == "backup" => {
            relaydeck::db::backup(&pool, &config.mfa_key, std::path::Path::new(destination))
                .await?;
            relaydeck::db::close(&pool).await?;
            println!("Consistent database and MFA key backup created.");
            return Ok(());
        }
        [] => (),
        [command] if command == "serve" => (),
        _ => anyhow::bail!(
            "usage: relaydeck [serve | init-admin <username> | init-key | migrate | backup <new-directory> | worker <policy.json> | broker <policy.json> | prepare-broker-policy <source.json> <effective.json>]"
        ),
    }
    let state = relaydeck::api::AppState::new(pool.clone(), config.clone()).await?;
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    tracing::info!(address = %config.listen, "RelayDeck listening");
    axum::serve(
        listener,
        relaydeck::api::router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        #[cfg(unix)]
        {
            if let Ok(mut terminate) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            {
                tokio::select! { _=tokio::signal::ctrl_c()=>(), _=terminate.recv()=>() }
                return;
            }
        }
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    relaydeck::db::close(&pool).await?;
    Ok(())
}
