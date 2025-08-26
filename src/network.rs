use anyhow::Result;
use if_addrs::{get_if_addrs, IfAddr};
use ipnetwork::Ipv4Network;
use std::net::Ipv4Addr;

pub fn get_local_subnet(interface_name: &str) -> Result<Ipv4Network> {
    let if_addrs = get_if_addrs()?;
    
    for iface in if_addrs {
        if iface.name == interface_name {
            if let IfAddr::V4(addr) = iface.addr {
                let ip = addr.ip;
                let netmask = addr.netmask;
                let network_addr = Ipv4Addr::from(u32::from(ip) & u32::from(netmask));
                let prefix_len = netmask.to_bits().count_ones() as u8;
                
                return Ok(Ipv4Network::new(network_addr, prefix_len)?);
            }
        }
    }
    
    Err(anyhow::anyhow!("Interface '{}' not found or has no IPv4 address", interface_name))
}

pub fn get_network_hosts(network: Ipv4Network) -> Vec<Ipv4Addr> {
    network.iter().collect()
}

pub fn list_interfaces() -> Result<()> {
    use colored::*;
    
    println!("{}", "Available Network Interfaces:".bold().cyan());
    println!();
    
    let if_addrs = get_if_addrs()?;
    let mut interface_map = std::collections::HashMap::new();
    
    // Group addresses by interface name
    for iface in if_addrs {
        interface_map.entry(iface.name.clone())
            .or_insert_with(Vec::new)
            .push(iface);
    }
    
    for (name, interfaces) in interface_map {
        println!("  {}", name.green().bold());
        
        for iface in interfaces {
            match iface.addr {
                IfAddr::V4(addr_v4) => {
                    println!("    IPv4: {} (netmask: {})", 
                        addr_v4.ip.to_string().blue(),
                        addr_v4.netmask.to_string().yellow()
                    );
                    
                    // Calculate network
                    let network_addr = std::net::Ipv4Addr::from(
                        u32::from(addr_v4.ip) & u32::from(addr_v4.netmask)
                    );
                    let prefix_len = addr_v4.netmask.to_bits().count_ones() as u8;
                    
                    if let Ok(network) = Ipv4Network::new(network_addr, prefix_len) {
                        println!("    Network: {} ({} hosts)", 
                            network.to_string().cyan(),
                            network.size().to_string().magenta()
                        );
                    }
                }
                IfAddr::V6(addr_v6) => {
                    println!("    IPv6: {} (netmask: {})", 
                        addr_v6.ip.to_string().blue(),
                        addr_v6.netmask.to_string().yellow()
                    );
                }
            }
        }
        println!();
    }
    
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

}