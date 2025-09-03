mod arp;
mod network;
mod ping;
mod portscan;

use anyhow::Result;
use arp::ArpScanner;
use chrono::{DateTime, Utc};
use clap::{Arg, Command};
use colored::*;
use network::{get_local_subnet, get_network_hosts, list_interfaces};
use ping::PingScanner;
use portscan::{read_ports_from_file, PortScanner};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;

const BANNER: &str = r#"
░█▀█░█▀█░█▀▀░█▀▄░█░█░█▀▀░▀█▀░█░█░█▀▀░█▀▄
░█▀█░█░█░█░█░█▀▄░░█░░█▀▀░░█░░█▀█░█▀▀░█▀▄
░▀░▀░▀░▀░▀▀▀░▀░▀░░▀░░▀▀▀░░▀░░▀░▀░▀▀▀░▀░▀
                    Network Scanner v1.0
"#;

#[derive(Serialize, Deserialize, Debug)]
struct OpenPort {
    port: u16,
    banner: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct HostResult {
    ip: String,
    discovery_method: String,
    open_ports: Vec<OpenPort>,
}

#[derive(Serialize, Deserialize, Debug)]
struct ScanResults {
    timestamp: DateTime<Utc>,
    interface: String,
    subnet: String,
    timeout_ms: u64,
    total_hosts_scanned: usize,
    active_hosts_found: usize,
    discovery_methods: Vec<String>,
    hosts: Vec<HostResult>,
}

fn get_default_ports_file() -> String {
    // Try local ports file first
    let local_path = "ports/10000.txt";
    if std::path::Path::new(local_path).exists() {
        return local_path.to_string();
    }
    
    // Try system-installed locations
    let system_paths = [
        "/usr/local/share/angryether/ports/10000.txt",
        "/usr/share/angryether/ports/10000.txt", 
        "/opt/angryether/ports/10000.txt",
    ];
    
    for path in &system_paths {
        if std::path::Path::new(path).exists() {
            return path.to_string();
        }
    }
    
    // Fallback to local path (will trigger proper error handling later)
    local_path.to_string()
}

#[tokio::main]
async fn main() -> Result<()> {
    let matches = Command::new("AngryEther")
        .version("1.0.0")
        .about("Network scanner for host discovery and port scanning")
        .arg(
            Arg::new("interface")
                .short('i')
                .long("interface")
                .value_name("INTERFACE")
                .help("Network interface to scan (e.g., enp37s0)")
                .default_value("enp37s0")
        )
        .arg(
            Arg::new("ports")
                .short('p')
                .long("ports")
                .value_name("PORTS_FILE")
                .help("Path to ports file (default: ports/10000.txt or system location)")
        )
        .arg(
            Arg::new("arp")
                .long("arp")
                .help("Enable ARP scanning in addition to ICMP ping")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("arp-only")
                .long("arp-only")
                .help("Use only ARP scanning (no ICMP ping)")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("timeout")
                .short('t')
                .long("timeout")
                .value_name("MILLISECONDS")
                .help("Timeout for ping operations in milliseconds")
                .default_value("500")
                .value_parser(clap::value_parser!(u64))
        )
        .arg(
            Arg::new("json")
                .short('j')
                .long("json")
                .value_name("FILE_PATH")
                .help("Output scan results to JSON file")
                .value_parser(clap::value_parser!(String))
        )
        .arg(
            Arg::new("interfaces")
                .long("interfaces")
                .help("List available network interfaces and exit")
                .action(clap::ArgAction::SetTrue)
        )
        .get_matches();

    // Check if user wants to list interfaces
    if matches.get_flag("interfaces") {
        return list_interfaces();
    }

    // Print banner
    println!("{}", BANNER.red());

    let interface = matches.get_one::<String>("interface").unwrap();
    let default_ports = get_default_ports_file();
    let ports_file = matches.get_one::<String>("ports")
        .map(|s| s.as_str())
        .unwrap_or(&default_ports);
    let enable_arp = matches.get_flag("arp");
    let arp_only = matches.get_flag("arp-only");
    let timeout_ms = *matches.get_one::<u64>("timeout").unwrap();
    let json_output = matches.get_one::<String>("json");

    // Get local subnet
    let subnet = match get_local_subnet(interface) {
        Ok(subnet) => {
            println!("Detected Subnet: {}", subnet.to_string().green());
            subnet
        }
        Err(e) => {
            eprintln!("Error detecting subnet: {}", e.to_string().red());
            return Ok(());
        }
    };

    // Get all hosts in the subnet
    let hosts = get_network_hosts(subnet);
    println!("Scanning {} hosts in subnet...", hosts.len());

    let mut active_hosts = HashSet::new();

    if !arp_only {
        // Initialize ping scanner
        let ping_scanner = PingScanner::new()?;
        
        // Perform ping sweep
        println!("Performing enhanced ping sweep (ICMP + TCP fallback, {}ms timeout per host)...", timeout_ms);
        let ping_hosts = ping_scanner.sweep(hosts.clone(), timeout_ms).await;
        for host in ping_hosts {
            active_hosts.insert(host);
        }
        println!("Found {} hosts via ICMP ping", active_hosts.len());
    }

    // Perform ARP sweep only if explicitly enabled
    if enable_arp || arp_only {
        println!("Performing ARP sweep...");
        match ArpScanner::new(interface) {
            Ok(mut arp_scanner) => {
                let arp_hosts = arp_scanner.sweep(hosts).await;
                let arp_count = arp_hosts.len();
                for host in arp_hosts {
                    active_hosts.insert(host);
                }
                println!("Found {} hosts via ARP scan", arp_count);
                println!("Total unique hosts: {}", active_hosts.len());
            }
            Err(e) => {
                eprintln!("Warning: ARP scanning failed: {}", e.to_string().yellow());
                if arp_only {
                    eprintln!("ARP-only mode failed, no results available.");
                    return Ok(());
                }
                eprintln!("Continuing with ICMP results only...");
            }
        }
    }

    let active_hosts: Vec<_> = active_hosts.into_iter().collect();
    
    if active_hosts.is_empty() {
        println!("No active hosts found.");
        return Ok(());
    }

    println!("\nProceeding with {} active hosts for port scanning", active_hosts.len());

    // Load ports from file
    let ports = match read_ports_from_file(ports_file) {
        Ok(ports) => {
            println!("Loaded {} ports from {}", ports.len(), ports_file);
            ports
        }
        Err(e) => {
            eprintln!("Error reading ports file '{}': {}", ports_file, e.to_string().red());
            return Ok(());
        }
    };

    // Initialize port scanner
    let port_scanner = PortScanner::new(1000);
    
    // Scan each active host and collect results
    println!("\nStarting port scans...");
    let mut scan_results = Vec::new();
    
    for host in &active_hosts {
        let open_ports_data = port_scanner.scan_ports(*host, &ports).await;
        let open_ports: Vec<OpenPort> = open_ports_data
            .into_iter()
            .map(|(port, banner)| OpenPort { port, banner })
            .collect();
            
        scan_results.push(HostResult {
            ip: host.to_string(),
            discovery_method: "ICMP/TCP".to_string(), // Simplified for now
            open_ports,
        });
    }

    println!("\nScan completed!");
    
    // Generate JSON output if requested
    if let Some(json_path) = json_output {
        let mut discovery_methods = vec!["ICMP", "TCP"];
        if enable_arp || arp_only {
            discovery_methods.push("ARP");
        }
        
        let results = ScanResults {
            timestamp: Utc::now(),
            interface: interface.clone(),
            subnet: subnet.to_string(),
            timeout_ms,
            total_hosts_scanned: subnet.size() as usize,
            active_hosts_found: active_hosts.len(),
            discovery_methods: discovery_methods.into_iter().map(String::from).collect(),
            hosts: scan_results,
        };
        
        match serde_json::to_string_pretty(&results) {
            Ok(json_string) => {
                match fs::write(json_path, json_string) {
                    Ok(_) => println!("Results saved to {}", json_path.green()),
                    Err(e) => eprintln!("Failed to write JSON file: {}", e.to_string().red()),
                }
            }
            Err(e) => eprintln!("Failed to serialize results to JSON: {}", e.to_string().red()),
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_banner_display() {
        assert!(!BANNER.is_empty());
        assert!(BANNER.contains("Ethernet Scanner"));
    }
}
