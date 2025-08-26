use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use surge_ping::{Client, Config, IcmpPacket, PingIdentifier, PingSequence};
use tokio::time::timeout;
use tokio::net::TcpSocket;

pub struct PingScanner {
    client: Client,
}

impl PingScanner {
    pub fn new() -> Result<Self> {
        let client_v4 = Client::new(&Config::default())?;
        Ok(PingScanner { client: client_v4 })
    }

    pub async fn ping_host(&self, ip: Ipv4Addr, timeout_ms: u64) -> bool {
        // Try ICMP ping first
        if self.icmp_ping(ip, timeout_ms).await {
            return true;
        }
        
        // If ICMP fails, try TCP connect to common ports
        self.tcp_ping(ip, timeout_ms).await
    }

    async fn icmp_ping(&self, ip: Ipv4Addr, timeout_ms: u64) -> bool {
        let payload = [0; 56];
        
        // Try multiple ICMP attempts for reliability
        for _ in 0..2 {
            let mut pinger = self
                .client
                .pinger(IpAddr::V4(ip), PingIdentifier(rand::random()))
                .await;
            
            let ping_result = timeout(
                Duration::from_millis(timeout_ms / 2),
                pinger.ping(PingSequence(0), &payload),
            ).await;

            match ping_result {
                Ok(Ok((IcmpPacket::V4(_), _))) => return true,
                _ => continue,
            }
        }
        false
    }

    async fn tcp_ping(&self, ip: Ipv4Addr, timeout_ms: u64) -> bool {
        // Common ports to check (like nmap does)
        let ports = [80, 443, 22, 21, 23, 53, 25];
        
        for &port in &ports {
            let addr = format!("{}:{}", ip, port);
            let connect_timeout = Duration::from_millis(timeout_ms / ports.len() as u64);
            
            if let Ok(socket) = TcpSocket::new_v4() {
                if let Ok(addr) = addr.parse() {
                    let connect_result = timeout(connect_timeout, socket.connect(addr)).await;
                    match connect_result {
                        Ok(Ok(_)) => return true,
                        Ok(Err(_)) => continue, // Connection refused is still a live host
                        Err(_) => continue,     // Timeout
                    }
                }
            }
        }
        false
    }

    pub async fn sweep(&self, ip_addresses: Vec<Ipv4Addr>, timeout_ms: u64) -> Vec<Ipv4Addr> {
        use futures::stream::{self, StreamExt};
        
        // Limit concurrency to avoid overwhelming the network
        let concurrent_limit = 50;
        
        let results: Vec<_> = stream::iter(ip_addresses)
            .map(|ip| async move {
                if self.ping_host(ip, timeout_ms).await {
                    Some(ip)
                } else {
                    None
                }
            })
            .buffer_unordered(concurrent_limit)
            .collect()
            .await;

        results.into_iter().filter_map(|result| result).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_ping_localhost() {
        let scanner = PingScanner::new().unwrap();
        let localhost = Ipv4Addr::from_str("127.0.0.1").unwrap();
        let result = scanner.ping_host(localhost, 1000).await;
        assert!(result);
    }

    #[tokio::test]
    async fn test_sweep_with_timeout() {
        let scanner = PingScanner::new().unwrap();
        let localhost = Ipv4Addr::from_str("127.0.0.1").unwrap();
        let hosts = vec![localhost];
        let results = scanner.sweep(hosts, 1000).await;
        assert!(!results.is_empty());
    }
}