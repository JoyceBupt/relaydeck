use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

#[derive(Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub database: PathBuf,
    pub public_origin: String,
    pub secure_cookie: bool,
    pub trust_proxy: bool,
    pub reserved_ports: Vec<u16>,
    pub local_ips: Vec<IpAddr>,
    pub frontend: PathBuf,
    pub mfa_key: PathBuf,
    pub require_admin_mfa: bool,
    pub upgrade: Option<crate::upgrade::UpgradeConfig>,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let listen: SocketAddr = std::env::var("RELAYDECK_LISTEN")
            .unwrap_or_else(|_| "127.0.0.1:7410".into())
            .parse()?;
        anyhow::ensure!(
            listen.ip().is_loopback(),
            "the HTTP backend must listen on loopback; use Caddy for HTTPS"
        );
        let public_origin =
            std::env::var("RELAYDECK_ORIGIN").unwrap_or_else(|_| format!("http://{listen}"));
        let url = url::Url::parse(&public_origin)?;
        anyhow::ensure!(
            url.username().is_empty()
                && url.password().is_none()
                && url.path() == "/"
                && url.query().is_none()
                && url.fragment().is_none(),
            "RELAYDECK_ORIGIN must contain only a scheme, host and optional port"
        );
        let secure_cookie = url.scheme() == "https";
        let trust_proxy = match std::env::var("RELAYDECK_TRUST_PROXY")
            .unwrap_or_else(|_| secure_cookie.to_string())
            .as_str()
        {
            "true" => true,
            "false" => false,
            _ => anyhow::bail!("RELAYDECK_TRUST_PROXY must be true or false"),
        };
        anyhow::ensure!(
            !trust_proxy || secure_cookie,
            "trusted proxy mode requires an HTTPS public origin"
        );
        anyhow::ensure!(
            !secure_cookie || trust_proxy,
            "HTTPS deployment requires RELAYDECK_TRUST_PROXY=true and a proxy that overwrites X-RelayDeck-Client-IP"
        );
        let local_origin = match url.host() {
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            Some(url::Host::Domain(host)) => host == "localhost",
            _ => false,
        };
        anyhow::ensure!(
            secure_cookie || (url.scheme() == "http" && local_origin && listen.ip().is_loopback()),
            "HTTP is supported only on loopback; configure an HTTPS public origin for deployment"
        );
        let public_port = url.port_or_known_default().filter(|port| *port != 0);
        anyhow::ensure!(
            public_port.is_some(),
            "RELAYDECK_ORIGIN requires a valid port"
        );
        let parse_ports = |s: &str| -> anyhow::Result<Vec<u16>> {
            s.split(',')
                .filter(|p| !p.trim().is_empty())
                .map(|p| Ok(p.trim().parse()?))
                .collect()
        };
        let mut reserved_ports = parse_ports(
            &std::env::var("RELAYDECK_RESERVED_PORTS").unwrap_or_else(|_| "22,80,443".into()),
        )?;
        reserved_ports.extend([22, 80, 443, listen.port()]);
        reserved_ports.extend(public_port);
        reserved_ports.sort_unstable();
        reserved_ports.dedup();
        let local_ips = std::env::var("RELAYDECK_LOCAL_IPS")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().parse())
            .collect::<Result<Vec<IpAddr>, _>>()?;
        let database = std::env::var_os("RELAYDECK_DATABASE")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(".local/relaydeck.db"));
        let mfa_key = std::env::var_os("RELAYDECK_MFA_KEY")
            .map(PathBuf::from)
            .unwrap_or_else(|| database.with_file_name("mfa.key"));
        let require_admin_mfa = match std::env::var("RELAYDECK_REQUIRE_ADMIN_MFA") {
            Ok(value) if value == "true" => true,
            Ok(value) if value == "false" && !secure_cookie => false,
            Ok(_) => anyhow::bail!("administrator MFA cannot be disabled for an HTTPS deployment"),
            Err(_) => secure_cookie,
        };
        Ok(Self {
            listen,
            database,
            mfa_key,
            require_admin_mfa,
            upgrade: crate::upgrade::installed_config()?,
            public_origin: url.origin().ascii_serialization(),
            secure_cookie,
            trust_proxy,
            reserved_ports,
            local_ips,
            frontend: std::env::var_os("RELAYDECK_FRONTEND")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("frontend/dist")),
        })
    }
}
