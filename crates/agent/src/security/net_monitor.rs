use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use runsafety_shared::types::{CliType, Signal};

use super::rules::SecurityRules;

/// A parsed TCP connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TcpConnection {
    pub remote_addr: IpAddr,
    pub remote_port: u16,
}

/// Scan network connections for a PID and check against allowlist.
/// Uses time-windowed dedup: same (addr, port) re-alerts after `dedup_window` expires.
pub fn scan_connections(
    pid: u32,
    session_id: u64,
    cli_type: &CliType,
    rules: &SecurityRules,
    already_seen: &mut HashMap<(IpAddr, u16), Instant>,
    dedup_window: Duration,
) -> Vec<Signal> {
    let mut signals = Vec::new();
    let connections = list_connections(pid);

    for conn in &connections {
        let key = (conn.remote_addr, conn.remote_port);
        if let Some(&seen_at) = already_seen.get(&key) {
            if seen_at.elapsed() < dedup_window {
                continue;
            }
        }

        if !rules.is_allowed_ip(&conn.remote_addr) {
            already_seen.insert(key, Instant::now());
            signals.push(Signal::UnexpectedNetwork {
                session_id,
                pid,
                cli_type: cli_type.clone(),
                remote_addr: conn.remote_addr.to_string(),
                remote_port: conn.remote_port,
            });
        }
    }

    signals
}

// --- Linux implementation ---

#[cfg(target_os = "linux")]
fn list_connections(pid: u32) -> Vec<TcpConnection> {
    let socket_inodes = read_socket_inodes(pid);
    if socket_inodes.is_empty() {
        return Vec::new();
    }

    let mut connections = Vec::new();
    connections.extend(parse_proc_net_tcp(pid, false, &socket_inodes));
    connections.extend(parse_proc_net_tcp(pid, true, &socket_inodes));
    connections
}

#[cfg(target_os = "linux")]
fn read_socket_inodes(pid: u32) -> std::collections::HashSet<u64> {
    use std::collections::HashSet;
    use std::fs;
    let mut inodes = HashSet::new();
    let fd_dir = format!("/proc/{pid}/fd");

    let entries = match fs::read_dir(&fd_dir) {
        Ok(e) => e,
        Err(_) => return inodes,
    };

    for entry in entries.flatten() {
        if let Ok(link) = fs::read_link(entry.path()) {
            let link_str = link.to_string_lossy();
            if let Some(inode_str) = link_str
                .strip_prefix("socket:[")
                .and_then(|s| s.strip_suffix(']'))
            {
                if let Ok(inode) = inode_str.parse::<u64>() {
                    inodes.insert(inode);
                }
            }
        }
    }

    inodes
}

#[cfg(target_os = "linux")]
fn parse_proc_net_tcp(
    pid: u32,
    ipv6: bool,
    socket_inodes: &std::collections::HashSet<u64>,
) -> Vec<TcpConnection> {
    use std::fs;
    use std::net::Ipv4Addr;

    let path = if ipv6 {
        format!("/proc/{pid}/net/tcp6")
    } else {
        format!("/proc/{pid}/net/tcp")
    };

    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut connections = Vec::new();

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }

        // State field (index 3): 01 = ESTABLISHED
        if fields[3] != "01" {
            continue;
        }

        // Check inode belongs to this process
        if let Ok(inode) = fields[9].parse::<u64>() {
            if !socket_inodes.contains(&inode) {
                continue;
            }
        }

        // Remote address field (index 2): hex_ip:hex_port
        if let Some(conn) = parse_addr_field(fields[2], ipv6) {
            if conn.remote_addr == IpAddr::V4(Ipv4Addr::UNSPECIFIED) {
                continue;
            }
            connections.push(conn);
        }
    }

    connections
}

#[cfg(target_os = "linux")]
fn parse_addr_field(field: &str, ipv6: bool) -> Option<TcpConnection> {
    let (addr_hex, port_hex) = field.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;

    let addr = if ipv6 {
        parse_ipv6_hex(addr_hex)?
    } else {
        parse_ipv4_hex(addr_hex)?
    };

    Some(TcpConnection {
        remote_addr: addr,
        remote_port: port,
    })
}

#[cfg(target_os = "linux")]
fn parse_ipv4_hex(hex: &str) -> Option<IpAddr> {
    use std::net::Ipv4Addr;
    if hex.len() != 8 {
        return None;
    }
    let native = u32::from_str_radix(hex, 16).ok()?;
    Some(IpAddr::V4(Ipv4Addr::from(native.to_be())))
}

#[cfg(target_os = "linux")]
fn parse_ipv6_hex(hex: &str) -> Option<IpAddr> {
    use std::net::Ipv6Addr;
    if hex.len() != 32 {
        return None;
    }
    let mut octets = [0u8; 16];
    for group in 0..4 {
        let start = group * 8;
        let native = u32::from_str_radix(&hex[start..start + 8], 16).ok()?;
        let network = native.to_be();
        let bytes = network.to_be_bytes();
        let offset = group * 4;
        octets[offset] = bytes[0];
        octets[offset + 1] = bytes[1];
        octets[offset + 2] = bytes[2];
        octets[offset + 3] = bytes[3];
    }
    Some(IpAddr::V6(Ipv6Addr::from(octets)))
}

// --- macOS implementation ---

/// List network connections for a PID using lsof (macOS).
#[cfg(target_os = "macos")]
fn list_connections(pid: u32) -> Vec<TcpConnection> {
    use std::process::Command;

    // lsof -i -n -P -p PID -F outputs structured data
    // -n = no DNS, -P = no port names, -i = network files only
    let output = match Command::new("lsof")
        .args(["-i", "-n", "-P", "-p", &pid.to_string(), "-Fnt"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let mut connections = Vec::new();

    for line in text.lines() {
        // 'n' prefix lines contain the connection info like "n192.168.1.1:443->10.0.0.1:12345"
        // or "nlocalhost:8080"
        if let Some(name) = line.strip_prefix('n') {
            if let Some(conn) = parse_lsof_connection(name) {
                connections.push(conn);
            }
        }
    }

    connections
}

/// Parse a lsof connection string like "10.0.0.1:443->192.168.1.100:54321"
/// or "[::1]:8080->[::1]:54321"
#[cfg(target_os = "macos")]
fn parse_lsof_connection(s: &str) -> Option<TcpConnection> {
    // We want the remote side (after "->")
    let remote = s.split("->").nth(1)?;
    parse_lsof_addr(remote)
}

#[cfg(target_os = "macos")]
fn parse_lsof_addr(s: &str) -> Option<TcpConnection> {
    // Handle IPv6 [addr]:port and IPv4 addr:port
    if let Some(bracket_end) = s.find(']') {
        // IPv6: [addr]:port
        let addr_str = &s[1..bracket_end];
        let port_str = s.get(bracket_end + 2..)?;
        let addr: IpAddr = addr_str.parse().ok()?;
        let port: u16 = port_str.parse().ok()?;
        Some(TcpConnection {
            remote_addr: addr,
            remote_port: port,
        })
    } else {
        // IPv4: addr:port
        let (addr_str, port_str) = s.rsplit_once(':')?;
        let addr: IpAddr = addr_str.parse().ok()?;
        let port: u16 = port_str.parse().ok()?;
        Some(TcpConnection {
            remote_addr: addr,
            remote_port: port,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_ipv4_loopback() {
        let addr = parse_ipv4_hex("0100007F").unwrap();
        assert_eq!(addr, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_ipv4_external() {
        let addr = parse_ipv4_hex("08080808").unwrap();
        assert_eq!(addr, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_ipv6_loopback() {
        use std::net::Ipv6Addr;
        let addr = parse_ipv6_hex("00000000000000000000000001000000").unwrap();
        assert_eq!(addr, IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_addr_field_established() {
        let conn = parse_addr_field("0100007F:1F40", false).unwrap();
        assert_eq!(conn.remote_addr, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(conn.remote_port, 8000);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn own_process_socket_inodes() {
        let inodes = read_socket_inodes(std::process::id());
        assert!(inodes.len() < 10000);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parse_lsof_ipv4_connection() {
        let conn = parse_lsof_connection("10.0.0.1:443->8.8.8.8:54321").unwrap();
        assert_eq!(conn.remote_addr, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(conn.remote_port, 54321);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parse_lsof_ipv6_connection() {
        use std::net::Ipv6Addr;
        let conn = parse_lsof_connection("[::1]:8080->[::1]:54321").unwrap();
        assert_eq!(
            conn.remote_addr,
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))
        );
        assert_eq!(conn.remote_port, 54321);
    }
}
