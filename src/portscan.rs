use anyhow::Result;
use futures::future::join_all;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use colored::*;

pub struct PortScanner {
    timeout_duration: Duration,
}

impl PortScanner {
    pub fn new(timeout_ms: u64) -> Self {
        PortScanner {
            timeout_duration: Duration::from_millis(timeout_ms),
        }
    }

    async fn check_port(&self, ip: Ipv4Addr, port: u16) -> Option<(u16, String)> {
        let socket_addr = SocketAddr::from((ip, port));
        
        match timeout(self.timeout_duration, TcpStream::connect(socket_addr)).await {
            Ok(Ok(mut stream)) => {
                let banner = self.grab_banner(&mut stream, port).await;
                Some((port, banner))
            }
            _ => None,
        }
    }

    async fn grab_banner(&self, stream: &mut TcpStream, port: u16) -> String {
        match port {
            // Common HTTP ports
            80 | 8080 | 8000 | 8888 | 3000 | 5000 | 9000 | 8081 | 8082 | 8090 => {
                self.grab_http_banner(stream, false).await
            },
            // Common HTTPS ports - use generic banner grabbing since TLS handshake is required
            443 | 8443 | 9443 | 4443 | 8444 => {
                self.grab_ssl_banner(stream).await
            },
            // Standard service ports
            21 => self.grab_ftp_banner(stream).await,
            22 => self.grab_ssh_banner(stream).await,
            23 => self.grab_telnet_banner(stream).await,
            25 => self.grab_smtp_banner(stream).await,
            // Additional common ports that might have banners
            110 => self.grab_pop3_banner(stream).await,
            143 => self.grab_imap_banner(stream).await,
            _ => self.grab_generic_banner(stream).await,
        }
    }

    async fn grab_generic_banner(&self, stream: &mut TcpStream) -> String {
        let mut buffer = [0; 1024];
        
        match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
            Ok(Ok(bytes_read)) if bytes_read > 0 => {
                let data_str = String::from_utf8_lossy(&buffer[..bytes_read]);
                
                // Get first line that contains meaningful text
                for line in data_str.lines() {
                    let clean_line: String = line.chars()
                        .filter(|c| c.is_ascii_graphic() || *c == ' ')
                        .collect();
                    
                    if clean_line.trim().len() > 3 {  // Only return if meaningful content
                        return clean_line.trim().to_string();
                    }
                }
                
                String::new()
            }
            _ => String::new(),
        }
    }

    async fn grab_ssl_banner(&self, stream: &mut TcpStream) -> String {
        // For SSL/TLS ports, we can't do a simple HTTP request
        // Instead, we'll attempt to detect if it's an SSL service
        let mut buffer = [0; 512];
        
        // Try reading any initial data the server might send
        match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
            Ok(Ok(bytes_read)) if bytes_read > 0 => {
                let data = String::from_utf8_lossy(&buffer[..bytes_read]);
                if !data.trim().is_empty() {
                    return format!("SSL/TLS service - {}", data.trim().replace('\n', " ").replace('\r', " "));
                }
            }
            _ => {}
        }
        
        // If no initial banner, just indicate it's an SSL service
        "SSL/TLS service".to_string()
    }

    async fn grab_http_banner(&self, stream: &mut TcpStream, _is_https: bool) -> String {
        let http_request = "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
        
        if stream.write_all(http_request.as_bytes()).await.is_err() {
            return String::new();
        }

        let mut buffer = [0; 2048];
        match timeout(Duration::from_millis(1000), stream.read(&mut buffer)).await {
            Ok(Ok(bytes_read)) if bytes_read > 0 => {
                let response = String::from_utf8_lossy(&buffer[..bytes_read]);
                
                // Extract server header
                for line in response.lines() {
                    if line.to_lowercase().starts_with("server:") {
                        return line.trim().to_string();
                    }
                }
                
                // Extract status line
                if let Some(first_line) = response.lines().next() {
                    if first_line.starts_with("HTTP/") {
                        return first_line.trim().to_string();
                    }
                }
                
                "HTTP service detected".to_string()
            }
            _ => String::new(),
        }
    }

    async fn grab_ftp_banner(&self, stream: &mut TcpStream) -> String {
        let mut buffer = [0; 512];
        
        match timeout(Duration::from_millis(1000), stream.read(&mut buffer)).await {
            Ok(Ok(bytes_read)) if bytes_read > 0 => {
                let banner = String::from_utf8_lossy(&buffer[..bytes_read]);
                if banner.starts_with("220") {
                    return banner.trim().replace('\n', " ").replace('\r', " ");
                }
                banner.trim().replace('\n', " ").replace('\r', " ")
            }
            _ => String::new(),
        }
    }

    async fn grab_telnet_banner(&self, stream: &mut TcpStream) -> String {
        let mut buffer = [0; 512];
        
        // Telnet often sends IAC sequences first, then a banner
        match timeout(Duration::from_millis(1000), stream.read(&mut buffer)).await {
            Ok(Ok(bytes_read)) if bytes_read > 0 => {
                let raw_data = &buffer[..bytes_read];
                
                // Filter out telnet control characters (IAC sequences)
                let filtered: Vec<u8> = raw_data.iter()
                    .filter(|&&b| b >= 32 && b <= 126 || b == b'\n' || b == b'\r')
                    .cloned()
                    .collect();
                
                if !filtered.is_empty() {
                    String::from_utf8_lossy(&filtered)
                        .trim()
                        .replace('\n', " ")
                        .replace('\r', " ")
                } else {
                    "Telnet service".to_string()
                }
            }
            _ => String::new(),
        }
    }

    async fn grab_ssh_banner(&self, stream: &mut TcpStream) -> String {
        let mut buffer = [0; 256];
        
        match timeout(Duration::from_millis(1000), stream.read(&mut buffer)).await {
            Ok(Ok(bytes_read)) if bytes_read > 0 => {
                // Convert to string and find SSH version line
                let data_str = String::from_utf8_lossy(&buffer[..bytes_read]);
                
                // Look for SSH version and extract only the clean part
                if let Some(ssh_line) = data_str.lines().find(|line| line.starts_with("SSH-")) {
                    // Extract only printable characters up to first space after version
                    let clean_version: String = ssh_line.chars()
                        .take_while(|c| c.is_ascii_graphic())
                        .collect();
                    
                    if !clean_version.is_empty() {
                        return clean_version;
                    }
                }
                
                String::new()
            }
            _ => String::new(),
        }
    }

    async fn grab_smtp_banner(&self, stream: &mut TcpStream) -> String {
        let mut buffer = [0; 512];
        
        match timeout(Duration::from_millis(1000), stream.read(&mut buffer)).await {
            Ok(Ok(bytes_read)) if bytes_read > 0 => {
                let banner = String::from_utf8_lossy(&buffer[..bytes_read]);
                if banner.starts_with("220") {
                    return banner.trim().replace('\n', " ").replace('\r', " ");
                }
                banner.trim().replace('\n', " ").replace('\r', " ")
            }
            _ => String::new(),
        }
    }

    async fn grab_pop3_banner(&self, stream: &mut TcpStream) -> String {
        let mut buffer = [0; 512];
        
        match timeout(Duration::from_millis(1000), stream.read(&mut buffer)).await {
            Ok(Ok(bytes_read)) if bytes_read > 0 => {
                let banner = String::from_utf8_lossy(&buffer[..bytes_read]);
                if banner.starts_with("+OK") {
                    return banner.trim().replace('\n', " ").replace('\r', " ");
                }
                banner.trim().replace('\n', " ").replace('\r', " ")
            }
            _ => String::new(),
        }
    }

    async fn grab_imap_banner(&self, stream: &mut TcpStream) -> String {
        let mut buffer = [0; 512];
        
        match timeout(Duration::from_millis(1000), stream.read(&mut buffer)).await {
            Ok(Ok(bytes_read)) if bytes_read > 0 => {
                let banner = String::from_utf8_lossy(&buffer[..bytes_read]);
                if banner.contains("* OK") {
                    return banner.trim().replace('\n', " ").replace('\r', " ");
                }
                banner.trim().replace('\n', " ").replace('\r', " ")
            }
            _ => String::new(),
        }
    }

    pub async fn scan_ports(&self, ip: Ipv4Addr, ports: &[u16]) -> Vec<(u16, String)> {
        println!("{} is online", ip.to_string().green());
        
        let scan_futures = ports.iter().map(|&port| async move {
            self.check_port(ip, port).await
        });

        let results = join_all(scan_futures).await;
        let mut open_ports = Vec::new();
        
        for result in results {
            if let Some((port, banner)) = result {
                let banner_display = if banner.is_empty() {
                    "".to_string()
                } else {
                    format!(" [{}]", banner.chars().take(50).collect::<String>())
                };
                println!("   Port {} is open{}", port.to_string().cyan(), banner_display.yellow());
                open_ports.push((port, banner));
            }
        }
        
        open_ports
    }
}

pub fn read_ports_from_file(file_path: &str) -> Result<Vec<u16>> {
    // Try the provided path first
    let path = std::path::Path::new(file_path);
    
    let file = if path.exists() {
        File::open(file_path)?
    } else {
        // Try system-installed location as fallback
        let system_path = find_system_ports_file(file_path)?;
        File::open(system_path)?
    };
    
    let reader = BufReader::new(file);
    let content: String = reader.lines().collect::<Result<Vec<_>, _>>()?.join("");
    
    let ports: Result<Vec<u16>, _> = content
        .split(',')
        .map(|s| s.trim().parse::<u16>())
        .collect();
    
    Ok(ports?)
}

fn find_system_ports_file(original_path: &str) -> Result<String> {
    // Extract filename from original path
    let filename = std::path::Path::new(original_path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("10000.txt");
    
    // Try system installation paths
    let system_paths = [
        format!("/usr/local/share/angryether/ports/{}", filename),
        format!("/usr/share/angryether/ports/{}", filename),
        format!("/opt/angryether/ports/{}", filename),
    ];
    
    for path in &system_paths {
        if std::path::Path::new(path).exists() {
            println!("Using system ports file: {}", path);
            return Ok(path.clone());
        }
    }
    
    // If no system file found, return error with helpful message
    Err(anyhow::anyhow!(
        "Ports file not found at '{}'. Tried system locations:\n{}",
        original_path,
        system_paths.join("\n")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_read_ports_from_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "80,443,22,21").unwrap();
        
        let ports = read_ports_from_file(temp_file.path().to_str().unwrap()).unwrap();
        assert_eq!(ports, vec![80, 443, 22, 21]);
    }

    #[tokio::test]
    async fn test_port_scanner() {
        let scanner = PortScanner::new(1000);
        // This is just a structure test, actual scanning requires network access
        assert_eq!(scanner.timeout_duration, Duration::from_millis(1000));
    }
}