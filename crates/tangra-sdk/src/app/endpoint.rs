//! Advertised endpoints of bound listeners.
//!
//! - HTTP: go-tangra `transport.ResolveEndpoint` - a concrete configured host
//!   is used as-is; for an unspecified host (`0.0.0.0`, `::`, empty) the
//!   `FREYA_ADVERTISE_HOST` environment variable, else the first
//!   non-loopback IPv4 address, else `127.0.0.1`.
//! - gRPC: Kratos `internal/host.Extract` (go-tangra builds its gRPC server
//!   without an explicit endpoint, so `FREYA_ADVERTISE_HOST` does not apply):
//!   a concrete host as-is; otherwise the first global-unicast address of the
//!   lowest-index up interface, preferring IPv4.

use std::net::{IpAddr, SocketAddr};

/// The environment variable naming the advertised host.
pub const ADVERTISE_HOST_ENV: &str = "FREYA_ADVERTISE_HOST";

fn join(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// `host:port` to advertise for an HTTP listener bound at `bound` from the
/// configured address `configured`.
pub fn resolve_endpoint(configured: &str, bound: SocketAddr) -> String {
    resolve_with(configured, bound, std::env::var(ADVERTISE_HOST_ENV).ok())
}

fn resolve_with(configured: &str, bound: SocketAddr, advertise: Option<String>) -> String {
    let port = bound.port();
    let host = crate::config::split_host_port(configured).ok().map(|(h, _)| h);
    match host.as_deref() {
        Some(h) if !h.is_empty() && h != "0.0.0.0" && h != "::" => join(h, port),
        _ => {
            if let Some(h) = advertise
                && !h.is_empty()
            {
                return join(&h, port);
            }
            if let Some(ip) = first_non_loopback_ipv4() {
                return join(&ip.to_string(), port);
            }
            join("127.0.0.1", port)
        }
    }
}

fn first_non_loopback_ipv4() -> Option<IpAddr> {
    if_addrs::get_if_addrs()
        .ok()?
        .into_iter()
        .map(|i| i.ip())
        .find(|ip| ip.is_ipv4() && !ip.is_loopback())
}

/// Go `net.IP.IsGlobalUnicast` (private ranges included) minus
/// interface-local multicast.
fn global_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_multicast()
                || v4.is_link_local()
                || v4.is_broadcast())
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return global_unicast(IpAddr::V4(v4));
            }
            let seg0 = v6.segments()[0];
            !(v6.is_unspecified() || v6.is_loopback() || v6.is_multicast() || (seg0 & 0xffc0) == 0xfe80)
        }
    }
}

/// `host:port` to advertise for a gRPC listener (Kratos `host.Extract`).
pub fn extract_endpoint(configured: &str, bound: SocketAddr) -> String {
    let port = bound.port();
    let host = crate::config::split_host_port(configured).ok().map(|(h, _)| h);
    if let Some(h) = host.as_deref()
        && !h.is_empty()
        && h != "0.0.0.0"
        && h != "[::]"
        && h != "::"
    {
        return join(h, port);
    }
    let Ok(ifaces) = if_addrs::get_if_addrs() else {
        return String::new();
    };
    // Group addresses by interface index, in enumeration order.
    let mut order: Vec<(u32, Vec<IpAddr>)> = Vec::new();
    for i in ifaces {
        if matches!(i.oper_status, if_addrs::IfOperStatus::Down) {
            continue;
        }
        let idx = i.index.unwrap_or(u32::MAX);
        match order.iter_mut().find(|(x, _)| *x == idx) {
            Some((_, v)) => v.push(i.ip()),
            None => order.push((idx, vec![i.ip()])),
        }
    }
    let mut min_index = 0u32;
    let mut ips: Vec<IpAddr> = Vec::new();
    for (idx, addrs) in order {
        if idx >= min_index && !ips.is_empty() {
            continue;
        }
        for ip in addrs {
            if global_unicast(ip) {
                min_index = idx;
                ips.push(ip);
                if ip.is_ipv4() {
                    break;
                }
            }
        }
    }
    ips.last()
        .map_or_else(String::new, |ip| join(&ip.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concrete_hosts_are_kept() {
        let b: SocketAddr = "0.0.0.0:9946".parse().expect("addr");
        assert_eq!(resolve_endpoint("10.1.2.3:0", b), "10.1.2.3:9946");
        assert_eq!(
            extract_endpoint("deployer:9945", b),
            "deployer:9946",
            "the bound port wins"
        );
        assert_eq!(resolve_endpoint("[::1]:1", b), "[::1]:9946");
    }

    #[test]
    fn unspecified_hosts_resolve() {
        let b: SocketAddr = "0.0.0.0:9946".parse().expect("addr");
        let ep = resolve_with("0.0.0.0:9946", b, None);
        assert!(ep.ends_with(":9946"), "{ep}");
        assert!(!ep.starts_with("0.0.0.0"), "{ep}");
        assert_eq!(resolve_with(":9946", b, Some("deployer".into())), "deployer:9946");
        assert_eq!(
            resolve_with("[::]:1", b, Some("10.9.8.7".into())),
            "10.9.8.7:9946"
        );
        // A concrete host ignores the variable.
        assert_eq!(resolve_with("10.0.0.5:1", b, Some("x".into())), "10.0.0.5:9946");
    }

    #[test]
    fn global_unicast_like_go() {
        for (ip, want) in [
            ("10.0.0.1", true),
            ("192.168.1.1", true),
            ("127.0.0.1", false),
            ("169.254.1.1", false),
            ("0.0.0.0", false),
            ("224.0.0.1", false),
            ("fe80::1", false),
            ("2001:db8::1", true),
            ("::1", false),
        ] {
            assert_eq!(global_unicast(ip.parse().expect("ip")), want, "{ip}");
        }
    }
}
