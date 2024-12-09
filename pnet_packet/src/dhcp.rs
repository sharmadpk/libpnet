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
    #[length = "4"]
    pub magic: Vec<u8>,
    #[payload]
    pub options: Vec<u8>,
}

// Set of DHCP options
#[packet]
#[allow(non_snake_case)]
pub struct DhcpOptionList {
    #[length_fn ="dhcp_options_length"]
    pub options: Vec<DhcpOption>,
    #[payload]
    pub payload: Vec<u8>,
}

/// Represents an DHCP Option.
#[packet]
#[allow(non_snake_case)]
pub struct DhcpOption {
    pub code: u8,
    // Caution: does not exist for pad, end and is not relevant for magic
    pub data_len: u8,
    #[length = "data_len"]
    pub value: Vec<u8>,
    #[payload]
    pub payload: Vec<u8>,
}

// Set of common DHCP option codes
pub const DHCP_OPTION_PAD: u8 = 0;
pub const DHCP_OPTION_SUBNET_MASK: u8 = 1;
pub const DHCP_OPTION_ROUTER: u8 = 3;
pub const DHCP_OPTION_DNS_SERVER: u8 = 6;
pub const DHCP_OPTION_HOST_NAME: u8 = 12;
pub const DHCP_OPTION_DOMAIN_NAME: u8 = 15;
pub const DHCP_OPTION_REQUESTED_IP_ADDRESS: u8 = 50;
pub const DHCP_OPTION_IP_LEASE_TIME: u8 = 51;
pub const DHCP_OPTION_MESSAGE_TYPE: u8 = 53;
pub const DHCP_OPTION_SERVER_IDENTIFIER: u8 = 54;
pub const DHCP_OPTION_PARAMETER_REQUEST_LIST: u8 = 55;
pub const DHCP_OPTION_MAX_DHCP_MESSAGE_SIZE: u8 = 57;
pub const DHCP_OPTION_RENEWAL_TIME: u8 = 58;
pub const DHCP_OPTION_REBINDING_TIME: u8 = 59;
pub const DHCP_OPTION_VENDOR_CLASS_IDENTIFIER: u8 = 60;
pub const DHCP_OPTION_CLIENT_IDENTIFIER: u8 = 61;
pub const DHCP_OPTION_END: u8 = 255;
pub const DHCP_OPTION_MAGIC: u8 = 99;

fn dhcp_options_length(packet: &DhcpOptionListPacket) -> usize {
    let mut length = 0;
    loop{
        let code = packet.packet()[length];
        length += match code {
            DHCP_OPTION_PAD => 1,
            DHCP_OPTION_END => 1,
            DHCP_OPTION_MAGIC => 6,
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
        let packet = DhcpPacket::new(b"\x02\x01\x06\x00\xd2\x2b\x75\x5a\x00\x00\x00\x00\x00\x00\x00\x00\xc0\xa8\x01\x19\x00\x00\x00\x00\x00\x00\x00\x00\x82\x94\x79\x3b\xa8\x51\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x63\x82\x53\x63\x35\x01\x02\x36\x04\xc0\xa8\x01\x01\x33\x04\x00\x01\x51\x80\x01\x04\xff\xff\xff\x00\x03\x04\xc0\xa8\x01\x01\x06\x04\xc0\xa8\x01\x01\xff").unwrap();
        /*
        Dynamic Host Configuration Protocol (Offer)
            Message type: Boot Reply (2)
            Hardware type: Ethernet (0x01)
            Hardware address length: 6
            Hops: 0
            Transaction ID: 0xd22b755a
            Seconds elapsed: 0
            Bootp flags: 0x0000 (Unicast)
            Client IP address: 0.0.0.0
            Your (client) IP address: 192.168.1.25
            Next server IP address: 0.0.0.0
            Relay agent IP address: 0.0.0.0
            Client MAC address: 82:94:79:3b:a8:51 (82:94:79:3b:a8:51)
            Client hardware address padding: 00000000000000000000
            Server host name not given
            Boot file name not given
            Magic cookie: DHCP
            Option: (53) DHCP Message Type (Offer)
                Length: 1
                DHCP: Offer (2)
            Option: (54) DHCP Server Identifier (192.168.1.1)
                Length: 4
                DHCP Server Identifier: 192.168.1.1
            Option: (51) IP Address Lease Time
                Length: 4
                IP Address Lease Time: 1 day (86400)
            Option: (1) Subnet Mask (255.255.255.0)
                Length: 4
                Subnet Mask: 255.255.255.0
            Option: (3) Router
                Length: 4
                Router: 192.168.1.1
            Option: (6) Domain Name Server
                Length: 4
                Domain Name Server: 192.168.1.1
            Option: (255) End
                Option End: 255
         */
        // Analyze the DHCP response packet
        // Assert the expected values
        assert_eq!(packet.get_ciaddr(), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(packet.get_yiaddr(), Ipv4Addr::new(192, 168, 1, 25));
        assert_eq!(packet.get_siaddr(), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(packet.get_chaddr(), MacAddr::new(0x82, 0x94, 0x79, 0x3b, 0xa8, 0x51));
    }
    
    /*
    // Enum to represent the DHCP message type
    #[derive(Debug, PartialEq)]
    enum DhcpMessageType {
        Offer,
        // Add more message types as needed
    }
    */
}
