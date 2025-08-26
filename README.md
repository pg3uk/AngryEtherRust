# AngryEther - Rust Edition

A high-performance network scanner written in Rust for comprehensive host discovery and port scanning.

## Features

- **Multi-method Host Discovery**
  - Enhanced ICMP ping with TCP fallback
  - Lightning-fast ARP scanning (100-200x faster than traditional methods)
  - Configurable timeouts for different network conditions
- **Advanced Port Scanning**
  - Multi-threaded TCP port scanning with intelligent banner grabbing
  - Service detection for HTTP, SSH, FTP, SMTP, and more
  - Concurrent scanning with controlled rate limiting
- **Flexible Output Options**
  - Colorized real-time terminal output
  - Structured JSON export for automation and reporting
  - Comprehensive scan metadata and timestamps
- **Network Interface Management**
  - Automatic interface detection and subnet calculation
  - Interface listing with network information
  - IPv4 and IPv6 support
- **Performance Optimized**
  - Asynchronous I/O with Tokio runtime
  - Batch processing for maximum throughput
  - Memory-safe Rust implementation
  - Cross-platform compatibility

## Installation

### Prerequisites
- Rust (1.70 or later)
- Administrator/root privileges for ICMP ping functionality

### Building from source
```bash
git clone <repository>
cd AngryEther
cargo build --release
```

## Usage

### Basic usage
```bash
# Run with default settings (ICMP + TCP ping, 500ms timeout)
sudo ./target/release/angryether

# List available network interfaces
./target/release/angryether --interfaces

# Scan specific interface with custom timeout
sudo ./target/release/angryether -i eth0 -t 1000

# Use a custom ports file
sudo ./target/release/angryether -p custom_ports.txt
```

### Host Discovery Methods
```bash
# Default: Enhanced ICMP ping with TCP fallback
sudo ./target/release/angryether

# Add lightning-fast ARP scanning
sudo ./target/release/angryether --arp

# ARP-only scanning (fastest for local networks)
sudo ./target/release/angryether --arp-only

# Slow networks: increase timeout
sudo ./target/release/angryether -t 2000 --arp
```

### Output Options
```bash
# Save results to JSON file
sudo ./target/release/angryether -j scan_results.json

# Combine with ARP scanning and custom timeout
sudo ./target/release/angryether --arp -t 1000 -j detailed_scan.json

# Quick local network scan
sudo ./target/release/angryether --arp-only -t 200 -j quick_scan.json
```

### Command-line options
- `-i, --interface <INTERFACE>`: Network interface to scan (default: enp37s0)
- `-p, --ports <PORTS_FILE>`: Path to ports file (default: ports/10000.txt)
- `-t, --timeout <MILLISECONDS>`: Timeout for ping operations (default: 500ms)
- `--arp`: Enable ARP scanning in addition to ICMP ping
- `--arp-only`: Use only ARP scanning (no ICMP ping)
- `-j, --json <FILE_PATH>`: Output scan results to JSON file
- `--interfaces`: List available network interfaces and exit
- `-h, --help`: Show help message
- `-V, --version`: Show version information

### Ports file format
Create a text file with comma-separated port numbers:
```
80,443,22,21,23,25,53,110,143,993,995
```

### JSON Output Format
When using the `-j` flag, results are saved in structured JSON format:
```json
{
  "timestamp": "2025-01-15T10:30:45.123Z",
  "interface": "enp37s0",
  "subnet": "192.168.1.0/24",
  "timeout_ms": 500,
  "total_hosts_scanned": 256,
  "active_hosts_found": 12,
  "discovery_methods": ["ICMP", "TCP", "ARP"],
  "hosts": [
    {
      "ip": "192.168.1.1",
      "discovery_method": "ICMP/TCP",
      "open_ports": [
        {
          "port": 80,
          "banner": "HTTP/1.1 200 OK"
        },
        {
          "port": 443,
          "banner": "SSL/TLS service"
        }
      ]
    }
  ]
}
```

This format is ideal for:
- Automation and scripting
- Integration with security tools
- Historical scan comparisons
- Compliance reporting

## Architecture

- **Async/await**: Non-blocking I/O operations using Tokio runtime
- **Multi-method Discovery**: ICMP ping, TCP connect probes, and ARP scanning
- **Concurrent scanning**: Parallel host discovery and port scanning with rate limiting
- **Batch Processing**: Optimized ARP scanning with burst transmission (100-200x faster)
- **Memory safety**: Rust's ownership system prevents common security issues
- **High Performance**: Zero-cost abstractions and efficient resource usage
- **Structured Output**: JSON serialization with comprehensive metadata
- **Error handling**: Comprehensive error handling with the `anyhow` crate

## Performance

### Host Discovery Speed
- **ICMP + TCP Fallback**: 500ms timeout (configurable)
- **ARP Scanning**: ~1-2 seconds for /24 network (256 hosts)
- **Combined Method**: Best coverage with reasonable speed

### ARP Scanning Optimization
Traditional ARP scanning: `256 hosts × 1000ms = 4+ minutes`
AngryEther ARP scanning: `256 hosts × 100μs + 200ms = 1-2 seconds`

**Speed improvement: 100-200x faster!**

### Scanning Techniques
1. **Burst ARP Transmission**: Sends all requests rapidly with 100μs intervals
2. **Batch Processing**: Groups requests to avoid overwhelming network interfaces  
3. **Efficient Response Collection**: Reads multiple packets per iteration
4. **Short Response Window**: 200ms total collection time vs 1000ms per host
5. **Concurrent Port Scanning**: Multiple TCP connections with intelligent banner grabbing

## Security Note

This tool is designed for legitimate network security assessment and monitoring purposes. Users are responsible for ensuring they have proper authorization before scanning networks they do not own or administer.