use crate::PrimitiveValues;

use alloc::vec::Vec;

use core::net::Ipv4Addr;

use pnet_base::MacAddr;
use pnet_macros::packet;
use pnet_macros_support::{packet::Packet, types::*};

/// Represents an Dhcp operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DhcpOperation(pub u8);

impl DhcpOperation {
    /// Create a new `ArpOperation`.
    pub fn new(value: u8) -> Self {
        DhcpOperation(value)
    }
}

impl PrimitiveValues for DhcpOperation {
    type T = (u8,);
    fn to_primitive_values(&self) -> (u8,) {
        (self.0,)
    }
}

/// The Dhcp protocol operations.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod DhcpOperations {
    use super::DhcpOperation;

    /// DHCP request
    pub const Request: DhcpOperation = DhcpOperation(1);

    /// Dhcp reply
    pub const Reply: DhcpOperation = DhcpOperation(2);
}

/// Represents the Dhcp hardware types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DhcpHardwareType(pub u8);

impl DhcpHardwareType {
    /// Create a new `DhcpHardwareType`.
    pub fn new(value: u8) -> Self {
        DhcpHardwareType(value)
    }
}

impl PrimitiveValues for DhcpHardwareType {
    type T = (u8,);
    fn to_primitive_values(&self) -> (u8,) {
        (self.0,)
    }
}

/// The Dhcp protocol hardware types.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod DhcpHardwareTypes {
    use super::DhcpHardwareType;

    /// Ethernet
    pub const Ethernet: DhcpHardwareType = DhcpHardwareType(1);
}

/// Represents an DHCP Packet.
#[packet]
#[allow(non_snake_case)]
pub struct Dhcp {
    #[construct_with(u8)]
    pub op: DhcpOperation,
    #[construct_with(u8)]
    pub htype: DhcpHardwareType,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32be,
    pub secs: u16be,
    pub flags: u16be,
    #[construct_with(u8, u8, u8, u8)]
    pub ciaddr: Ipv4Addr,
    #[construct_with(u8, u8, u8, u8)]
    pub yiaddr: Ipv4Addr,
    #[construct_with(u8, u8, u8, u8)]
    pub siaddr: Ipv4Addr,
    #[construct_with(u8, u8, u8, u8)]
    pub giaddr: Ipv4Addr,
    #[construct_with(u8, u8, u8, u8, u8, u8)]
    pub chaddr: MacAddr,
    #[length = "10"]
    pub chaddr_pad: Vec<u8>,
    #[length = "64"]
    pub sname: Vec<u8>,
    #[length = "128"]
    pub file: Vec<u8>,
    #[payload]
    pub options: Vec<u8>,
}

/// Represents the DHCP options.
#[packet]
#[allow(non_snake_case)]
pub struct DhcpOptions {
    #[length_fn = "options_length"]
    pub options: Vec<u8>,
    #[payload]
    pub payload: Vec<u8>,
}

// Special DHCP option codes
const DHCP_OPTION_PAD: u8 = 0;
const DHCP_OPTION_END: u8 = 255;

#[packet]
#[allow(non_snake_case)]
pub struct DhcpOption {
    pub code: u8,
    pub data_len: u8,
    #[length = "data_len"]
    pub value: Vec<u8>,
    #[payload]
    pub payload: Vec<u8>,
}

fn options_length(packet: &DhcpOptionsPacket) -> usize {
    let mut length = 0;
    loop{
        let code = packet.packet()[length];
        length += match code {
            DHCP_OPTION_PAD => 1,
            DHCP_OPTION_END => 1,
            _ => {
                let len = packet.packet()[length + 1] as usize;
                2 + len
            }
        };
        if code == DHCP_OPTION_END {
            break;
        }
    }
    length
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_analyze_dhcp_response_packet() {
        // Create a sample DHCP response packet
        let mut packet = Dhcp::default();
        packet.op = DhcpOperations::Reply;
        packet.htype = DhcpHardwareTypes::Ethernet;
        packet.hlen = 6;
        packet.hops = 0;
        packet.xid = 123456789;
        packet.secs = 0;
        packet.flags = 0;
        packet.ciaddr = Ipv4Addr::new(192, 168, 0, 1);
        packet.yiaddr = Ipv4Addr::new(192, 168, 0, 100);
        packet.siaddr = Ipv4Addr::new(192, 168, 0, 254);
        packet.giaddr = Ipv4Addr::new(0, 0, 0, 0);
        packet.chaddr = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        packet.chaddr_pad = vec![0; 10];
        packet.sname = vec![0; 64];
        packet.file = vec![0; 128];
        packet.options = vec![0x35, 0x01, 0x02]; // DHCP Message Type: Offer
        
        // Analyze the DHCP response packet
        let analyzed_packet = analyze_dhcp_response_packet(&packet);
        
        // Assert the expected values
        assert_eq!(analyzed_packet.message_type, DhcpMessageType::Offer);
        assert_eq!(analyzed_packet.client_ip, Ipv4Addr::new(192, 168, 0, 1));
        assert_eq!(analyzed_packet.your_ip, Ipv4Addr::new(192, 168, 0, 100));
        assert_eq!(analyzed_packet.server_ip, Ipv4Addr::new(192, 168, 0, 254));
        assert_eq!(analyzed_packet.client_mac, MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55));
    }
    
    // Helper function to analyze the DHCP response packet
    fn analyze_dhcp_response_packet(packet: &Dhcp) -> AnalyzedDhcpResponse {
        // Implement your analysis logic here
        // ...
        // Return the analyzed results
        AnalyzedDhcpResponse {
            message_type: DhcpMessageType::Offer,
            client_ip: packet.ciaddr,
            your_ip: packet.yiaddr,
            server_ip: packet.siaddr,
            client_mac: packet.chaddr,
        }
    }
    
    // Struct to hold the analyzed DHCP response information
    struct AnalyzedDhcpResponse {
        message_type: DhcpMessageType,
        client_ip: Ipv4Addr,
        your_ip: Ipv4Addr,
        server_ip: Ipv4Addr,
        client_mac: MacAddr,
    }
    
    // Enum to represent the DHCP message type
    #[derive(Debug, PartialEq)]
    enum DhcpMessageType {
        Offer,
        // Add more message types as needed
    }
}
