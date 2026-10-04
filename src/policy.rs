use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PolicyError {
    #[error("用户名须为3至32位字母、数字、下划线或短横线，且以字母开头")]
    Username,
    #[error("密码长度须为12至128字节")]
    Password,
    #[error("规则名称须为1至64字且不含控制字符")]
    RuleName,
    #[error("端口范围须在1024至65535内且起点不大于终点")]
    PortRange,
    #[error("端口额度须在0至30之间")]
    RuleLimit,
    #[error("监听端口不在授权范围内")]
    PortOutsideGrant,
    #[error("端口{0}已保留")]
    ReservedPort(u16),
    #[error("来源网段最多32项")]
    SourceCidrLimit,
    #[error("第{0}项来源网段格式无效")]
    SourceCidr(usize),
    #[error("目标地址禁止访问")]
    TargetIp,
    #[error("目标不能是本机地址")]
    TargetLocalIp,
    #[error("目标须为有效公网IP或完整域名")]
    TargetHost,
    #[error("目标端口禁止访问")]
    TargetPort,
}

pub fn validate_target_port(port: u16) -> Result<(), PolicyError> {
    if port == 0 || matches!(port, 25 | 465 | 587) {
        Err(PolicyError::TargetPort)
    } else {
        Ok(())
    }
}

pub fn validate_username(value: &str) -> Result<(), PolicyError> {
    let bytes = value.as_bytes();
    if !(3..=32).contains(&bytes.len())
        || !bytes[0].is_ascii_alphabetic()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(PolicyError::Username);
    }
    Ok(())
}

pub fn validate_password(value: &str) -> Result<(), PolicyError> {
    if !(12..=128).contains(&value.len()) {
        return Err(PolicyError::Password);
    }
    Ok(())
}

pub fn validate_rule_name(value: &str) -> Result<(), PolicyError> {
    if value.chars().any(char::is_control) || !(1..=64).contains(&value.trim().chars().count()) {
        return Err(PolicyError::RuleName);
    }
    Ok(())
}

pub fn validate_port_grant(start: i64, end: i64, max_rules: i64) -> Result<(), PolicyError> {
    if !(1024..=65535).contains(&start) || !(start..=65535).contains(&end) {
        return Err(PolicyError::PortRange);
    }
    if !(0..=30).contains(&max_rules) {
        return Err(PolicyError::RuleLimit);
    }
    Ok(())
}

pub fn validate_listen_port(
    port: i64,
    start: i64,
    end: i64,
    reserved_ports: &[u16],
) -> Result<(), PolicyError> {
    validate_port_grant(start, end, 0)?;
    if !(start..=end).contains(&port) {
        return Err(PolicyError::PortOutsideGrant);
    }
    let port = port as u16;
    if reserved_ports.contains(&port) {
        return Err(PolicyError::ReservedPort(port));
    }
    Ok(())
}

// An empty vector remains empty. The rule API must explicitly apply its
// documented allow-all semantics; this validator never adds a broad CIDR.
pub fn validate_source_cidrs(values: &[String]) -> Result<Vec<String>, PolicyError> {
    if values.len() > 32 {
        return Err(PolicyError::SourceCidrLimit);
    }
    let mut normalized = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let invalid = || PolicyError::SourceCidr(index + 1);
        if value
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control())
        {
            return Err(invalid());
        }
        let (address, prefix) = value.split_once('/').ok_or_else(invalid)?;
        // ipnet accepts some noncanonical IPv4 spellings, including leading
        // zeros. The stricter std parser rejects those before normalization.
        address.parse::<IpAddr>().map_err(|_| invalid())?;
        if prefix.is_empty()
            || !prefix.bytes().all(|byte| byte.is_ascii_digit())
            || (prefix.len() > 1 && prefix.starts_with('0'))
        {
            return Err(invalid());
        }
        let network: IpNet = value.parse().map_err(|_| invalid())?;
        let network = network.trunc().to_string();
        if !normalized.contains(&network) {
            normalized.push(network);
        }
    }
    Ok(normalized)
}

// Syntax normalization only. Literal IPs and every DNS result must subsequently
// pass validate_target_ip; resolving an accepted domain is not authorization.
pub fn validate_target_host(value: &str) -> Result<String, PolicyError> {
    if !value.is_ascii()
        || value.is_empty()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err(PolicyError::TargetHost);
    }
    let host = value.strip_suffix('.').unwrap_or(value);
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }
    if host.len() > 253 {
        return Err(PolicyError::TargetHost);
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2
        || !labels
            .last()
            .is_some_and(|label| label.bytes().any(|byte| byte.is_ascii_alphabetic()))
        || labels.iter().any(|label| {
            let bytes = label.as_bytes();
            bytes.is_empty()
                || bytes.len() > 63
                || !bytes[0].is_ascii_alphanumeric()
                || !bytes[bytes.len() - 1].is_ascii_alphanumeric()
                || !bytes
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        })
    {
        return Err(PolicyError::TargetHost);
    }
    Ok(host.to_ascii_lowercase())
}

pub fn validate_target_ip(ip: IpAddr, local_ips: &[IpAddr]) -> Result<(), PolicyError> {
    if local_ips.contains(&ip) {
        return Err(PolicyError::TargetLocalIp);
    }
    let allowed = match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    };
    if !allowed {
        return Err(PolicyError::TargetIp);
    }
    Ok(())
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    // Conservative exclusions derived from IANA's special-purpose registry:
    // https://www.iana.org/assignments/iana-ipv4-special-registry/
    // Exclude entire protocol-assignment and deprecated relay blocks, including
    // their exceptional anycast addresses. Multicast/reserved includes broadcast.
    const DENIED: &[([u8; 4], u32)] = &[
        ([0, 0, 0, 0], 8),
        ([10, 0, 0, 0], 8),
        ([100, 64, 0, 0], 10),
        ([127, 0, 0, 0], 8),
        ([169, 254, 0, 0], 16),
        ([172, 16, 0, 0], 12),
        ([192, 0, 0, 0], 24),
        ([192, 0, 2, 0], 24),
        ([192, 88, 99, 0], 24),
        ([192, 168, 0, 0], 16),
        ([198, 18, 0, 0], 15),
        ([198, 51, 100, 0], 24),
        ([203, 0, 113, 0], 24),
        ([224, 0, 0, 0], 3),
    ];
    let address = u32::from(ip);
    !DENIED.iter().any(|(network, prefix)| {
        let mask = u32::MAX << (32 - prefix);
        address & mask == u32::from(Ipv4Addr::from(*network)) & mask
    })
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    // Positive global-unicast boundary rejects mapped IPv4, NAT64, local, site
    // local, multicast, unspecified and other non-global address families.
    if ip.segments()[0] & 0xe000 != 0x2000 {
        return false;
    }
    // https://www.iana.org/assignments/iana-ipv6-special-registry/
    // https://www.iana.org/assignments/ipv6-unicast-address-assignments/
    // IETF protocol assignments, transition ranges and current reserved ranges
    // are excluded conservatively rather than allowing special-case exceptions.
    const DENIED: &[([u16; 8], u32)] = &[
        ([0x2001, 0, 0, 0, 0, 0, 0, 0], 23),
        ([0x2001, 0x0db8, 0, 0, 0, 0, 0, 0], 32),
        ([0x2002, 0, 0, 0, 0, 0, 0, 0], 16),
        ([0x2d00, 0, 0, 0, 0, 0, 0, 0], 8),
        ([0x2e00, 0, 0, 0, 0, 0, 0, 0], 7),
        ([0x3000, 0, 0, 0, 0, 0, 0, 0], 4),
    ];
    let address = u128::from(ip);
    !DENIED.iter().any(|(network, prefix)| {
        let mask = u128::MAX << (128 - prefix);
        address & mask == u128::from(Ipv6Addr::from(*network)) & mask
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_identifiers_have_unambiguous_ascii_boundaries() {
        for name in ["abc", "Alice_001", "user-1", &"a".repeat(32)] {
            assert!(validate_username(name).is_ok(), "{name}");
        }
        for name in [
            "",
            "ab",
            "1user",
            "用户abc",
            " user",
            "a/b",
            &"a".repeat(33),
        ] {
            assert_eq!(
                validate_username(name),
                Err(PolicyError::Username),
                "{name}"
            );
        }
        assert!(validate_password(&"a".repeat(12)).is_ok());
        assert!(validate_password(&"a".repeat(128)).is_ok());
        assert_eq!(
            validate_password(&"a".repeat(11)),
            Err(PolicyError::Password)
        );
        assert_eq!(
            validate_password(&"a".repeat(129)),
            Err(PolicyError::Password)
        );
        assert!(validate_rule_name("  东京转发  ").is_ok());
        assert!(validate_rule_name(&"转".repeat(64)).is_ok());
        for name in ["", "   ", "name\n", "a\0b", &"转".repeat(65)] {
            assert_eq!(validate_rule_name(name), Err(PolicyError::RuleName));
        }
    }

    #[test]
    fn authorization_ranges_and_reserved_listener_ports_are_independent() {
        assert!(validate_port_grant(7000, 7500, 30).is_ok());
        assert!(validate_port_grant(1024, 65535, 0).is_ok());
        for (start, end, limit) in [
            (0, 1000, 1),
            (1023, 1024, 1),
            (65535, 65536, 1),
            (2000, 1999, 1),
        ] {
            assert_eq!(
                validate_port_grant(start, end, limit),
                Err(PolicyError::PortRange)
            );
        }
        for limit in [-1, 31] {
            assert_eq!(
                validate_port_grant(7000, 7500, limit),
                Err(PolicyError::RuleLimit)
            );
        }
        assert_eq!(
            validate_listen_port(7410, 7000, 7500, &[7410]),
            Err(PolicyError::ReservedPort(7410))
        );
        assert!(validate_listen_port(7411, 7000, 7500, &[7410]).is_ok());
        assert_eq!(
            validate_listen_port(7501, 7000, 7500, &[]),
            Err(PolicyError::PortOutsideGrant)
        );
        assert_eq!(
            validate_listen_port(-1, 7000, 7500, &[]),
            Err(PolicyError::PortOutsideGrant)
        );
    }

    #[test]
    fn source_cidrs_normalize_host_bits_and_preserve_explicit_empty_list() {
        assert_eq!(validate_source_cidrs(&[]).unwrap(), Vec::<String>::new());
        let entries = ["8.8.8.9/24", "8.8.8.0/24", "2001:4860:ABCD::1/64"].map(str::to_owned);
        assert_eq!(
            validate_source_cidrs(&entries).unwrap(),
            ["8.8.8.0/24", "2001:4860:abcd::/64"]
        );
        for entry in [
            "8.8.8.8",
            "8.8.8.8/33",
            "8.8.8.8/024",
            "08.8.8.8/24",
            "8.8.8.8/24 ",
            "::1/129",
            "fe80::1%eth0/64",
            "8.8.8.8/+24",
        ] {
            assert_eq!(
                validate_source_cidrs(&[entry.to_owned()]),
                Err(PolicyError::SourceCidr(1)),
                "{entry}"
            );
        }
        assert_eq!(
            validate_source_cidrs(&vec!["8.8.8.0/24".to_owned(); 33]),
            Err(PolicyError::SourceCidrLimit)
        );
    }

    #[test]
    fn target_syntax_excludes_urls_search_names_and_numeric_aliases() {
        assert_eq!(validate_target_host("EXAMPLE.COM.").unwrap(), "example.com");
        assert_eq!(
            validate_target_host("2001:4860:0000:0000:0000:0000:0000:8888").unwrap(),
            "2001:4860::8888"
        );
        assert_eq!(validate_target_host("8.8.8.8").unwrap(), "8.8.8.8");
        for host in [
            "",
            "localhost",
            "127.1",
            "2130706433",
            "0x7f000001",
            "https://example.com",
            "example.com/path",
            "example.com:80",
            "user@example.com",
            "a_b.example.com",
            "-a.example.com",
            "a-.example.com",
            "example..com",
            "example.com..",
            " example.com",
            "例子.com",
            "[::1]",
            "fe80::1%eth0",
            "example.com\n",
        ] {
            assert_eq!(
                validate_target_host(host),
                Err(PolicyError::TargetHost),
                "{host}"
            );
        }
        assert!(validate_target_host(&format!("{}.com", "a".repeat(64))).is_err());
        assert!(
            validate_target_host(&format!(
                "{}.{}.{}.{}.com",
                "a".repeat(63),
                "b".repeat(63),
                "c".repeat(63),
                "d".repeat(63)
            ))
            .is_err()
        );
        // Syntax acceptance must never be confused with network authorization.
        assert_eq!(validate_target_host("127.0.0.1").unwrap(), "127.0.0.1");
        assert!(validate_target_ip("127.0.0.1".parse().unwrap(), &[]).is_err());
    }

    #[test]
    fn target_policy_rejects_local_special_and_transition_addresses() {
        for ip in [
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "100.127.255.255",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.9",
            "192.0.2.1",
            "192.88.99.2",
            "192.168.0.1",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "fc00::1",
            "fdff::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
            "2001::1",
            "2001:2::1",
            "2001:1ff:ffff::1",
            "2001:db8::1",
            "2002:808:808::1",
            "2d00::1",
            "2fff::1",
            "3000::1",
            "3ffe::1",
            "3fff:fff::1",
            "4000::1",
        ] {
            assert_eq!(
                validate_target_ip(ip.parse().unwrap(), &[]),
                Err(PolicyError::TargetIp),
                "{ip}"
            );
        }
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "100.63.255.255",
            "100.128.0.1",
            "172.15.255.255",
            "172.32.0.1",
            "198.17.255.255",
            "198.20.0.1",
            "2001:200::1",
            "2001:4860::8888",
            "2606:4700:4700::1111",
            "2c00::1",
        ] {
            assert!(validate_target_ip(ip.parse().unwrap(), &[]).is_ok(), "{ip}");
        }
        for self_ip in ["8.8.8.8", "2001:4860::8888"] {
            let ip: IpAddr = self_ip.parse().unwrap();
            assert_eq!(
                validate_target_ip(ip, &[ip]),
                Err(PolicyError::TargetLocalIp)
            );
        }
    }
}
