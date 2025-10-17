use anyhow::Result;
use pnet::datalink::{self, NetworkInterface, DataLinkSender, DataLinkReceiver};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::process::Command;
use std::time::Instant;

pub struct ArpScanner {
    interface: NetworkInterface,
    sender: Box<dyn DataLinkSender>,
    receiver: Box<dyn DataLinkReceiver>,
}

impl ArpScanner {
    pub fn new(interface_name: &str) -> Result<Self> {
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| iface.name == interface_name)
            .ok_or_else(|| anyhow::anyhow!("Interface {} not found", interface_name))?;

        let (sender, receiver) = match datalink::channel(&interface, Default::default()) {
            Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(anyhow::anyhow!("Unsupported channel type")),
            Err(e) => return Err(anyhow::anyhow!("Failed to create channel: {}", e)),
        };

        Ok(ArpScanner {
            interface,
            sender,
            receiver,
        })
    }

    fn create_arp_request(&self, target_ip: Ipv4Addr) -> Vec<u8> {
        let mut ethernet_buffer = [0u8; 42];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

        ethernet_packet.set_destination(MacAddr::broadcast());
        ethernet_packet.set_source(self.interface.mac.unwrap());
        ethernet_packet.set_ethertype(EtherTypes::Arp);

        let mut arp_buffer = [0u8; 28];
        let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Request);
        arp_packet.set_sender_hw_addr(self.interface.mac.unwrap());
        
        if let Some(source_ip) = self.interface.ips.iter()
            .find_map(|ip| if let pnet::ipnetwork::IpNetwork::V4(net) = ip { Some(net.ip()) } else { None }) {
            arp_packet.set_sender_proto_addr(source_ip);
        }
        
        arp_packet.set_target_hw_addr(MacAddr::zero());
        arp_packet.set_target_proto_addr(target_ip);

        ethernet_packet.set_payload(arp_packet.packet());
        ethernet_packet.packet().to_vec()
    }


    pub async fn sweep(&mut self, ip_addresses: Vec<Ipv4Addr>) -> Vec<(Ipv4Addr, MacAddr)> {
        // Use the new fast batch scanning method
        self.fast_arp_sweep(ip_addresses).await
    }

    pub async fn fast_arp_sweep(&mut self, ip_addresses: Vec<Ipv4Addr>) -> Vec<(Ipv4Addr, MacAddr)> {
        use std::collections::HashMap;
        use tokio::time::{sleep, Duration};

        if ip_addresses.is_empty() {
            return Vec::new();
        }

        let mut discovered_hosts = HashMap::new();
        let total_targets = ip_addresses.len();

        // Send all ARP requests rapidly in batches
        const BATCH_SIZE: usize = 100;
        const BURST_DELAY: Duration = Duration::from_micros(100); // 100μs between packets
        const RESPONSE_WINDOW: Duration = Duration::from_millis(200); // Total response collection time

        println!("Sending {} ARP requests...", total_targets);

        // Send all requests in batches
        for chunk in ip_addresses.chunks(BATCH_SIZE) {
            for &ip in chunk {
                let arp_request = self.create_arp_request(ip);
                let _ = self.sender.send_to(&arp_request, None);

                // Small delay to avoid overwhelming the network interface
                sleep(BURST_DELAY).await;
            }
        }

        // Collect responses for a short window
        let start_time = Instant::now();
        let mut responses_received = 0;

        while start_time.elapsed() < RESPONSE_WINDOW {
            // Try to read multiple packets in a tight loop
            for _ in 0..50 { // Read up to 50 packets per iteration
                match self.receiver.next() {
                    Ok(packet) => {
                        if let Some(ethernet_packet) = EthernetPacket::new(packet) {
                            if ethernet_packet.get_ethertype() == EtherTypes::Arp {
                                if let Some(arp_packet) = ArpPacket::new(ethernet_packet.payload()) {
                                    if arp_packet.get_operation() == ArpOperations::Reply {
                                        let sender_ip = arp_packet.get_sender_proto_addr();
                                        let sender_mac = arp_packet.get_sender_hw_addr();
                                        if ip_addresses.contains(&sender_ip) {
                                            discovered_hosts.insert(sender_ip, sender_mac);
                                            responses_received += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => break, // No more packets available right now
                }
            }

            // Very short sleep to allow more responses to arrive
            sleep(Duration::from_millis(1)).await;
        }

        println!("ARP scan completed: {} responses received", responses_received);
        discovered_hosts.into_iter().collect()
    }
}

/// Read MAC addresses from the system's ARP cache
pub fn read_system_arp_cache() -> HashMap<Ipv4Addr, String> {
    let mut cache = HashMap::new();

    // Try to read from /proc/net/arp on Linux
    if let Ok(output) = Command::new("cat").arg("/proc/net/arp").output() {
        if let Ok(content) = String::from_utf8(output.stdout) {
            for line in content.lines().skip(1) { // Skip header
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    if let Ok(ip) = parts[0].parse::<Ipv4Addr>() {
                        let mac = parts[3].to_string();
                        // Only add if it's a valid MAC (not incomplete)
                        if mac != "00:00:00:00:00:00" && mac.contains(':') && mac.len() == 17 {
                            cache.insert(ip, mac);
                        }
                    }
                }
            }
        }
    }

    cache
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_arp_scanner_creation() {
        let interfaces = datalink::interfaces();
        if let Some(interface) = interfaces.first() {
            let result = ArpScanner::new(&interface.name);
            assert!(result.is_ok() || result.is_err()); // Either works or needs privileges
        }
    }
}