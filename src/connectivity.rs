use serde::{Deserialize, Serialize};
use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckRequest {
    pub owner_id: i64,
    pub revision: i64,
    pub rule_id: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpCheck {
    pub status: String,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleCheck {
    pub rule_id: i64,
    pub revision: i64,
    pub target_ip: std::net::IpAddr,
    pub target_port: u16,
    pub checked_at: i64,
    pub tcp_listener: Option<bool>,
    pub udp_listener: Option<bool>,
    pub target_tcp: Option<TcpCheck>,
}

pub type CheckFuture<'a> = Pin<Box<dyn Future<Output = anyhow::Result<RuleCheck>> + Send + 'a>>;
pub trait CheckChannel: Send + Sync {
    fn check(&self, request: CheckRequest) -> CheckFuture<'_>;
}

pub async fn tcp(address: SocketAddr) -> TcpCheck {
    let started = Instant::now();
    let status = match tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::TcpStream::connect(address),
    )
    .await
    {
        Ok(Ok(stream)) => {
            drop(stream);
            "connected"
        }
        Err(_) => "timeout",
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionRefused => "refused",
        Ok(Err(_)) => "unreachable",
    };
    TcpCheck {
        status: status.into(),
        elapsed_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
    }
}
