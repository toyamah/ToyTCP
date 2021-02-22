use crate::socket::{Socket, SocketID};
use std::collections::HashMap;
use std::io;
use std::io::Error;
use std::net::Ipv4Addr;
use std::ops::Range;

const UNDETERMINED_IP_ADDR: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);
const UNDEFINED_PORT: u16 = 0;
const MAX_TRANSMISSION: u8 = 5;
const RETRANSMISSION_TIMEOUT: u64 = 3;
const MSS: usize = 1460;
const PORT_RANGE: Range<u16> = 40000..60000;

pub struct TCP {
    sockets: HashMap<SocketID, Socket>,
}

impl TCP {
    pub fn new() -> Self {
        Self {
            sockets: HashMap::new(),
        }
    }

    fn select_unused_port(&self) -> u16 {
        33456
    }

    pub fn connect(&self, remote_addr: Ipv4Addr, remote_port: u16) -> io::Result<SocketID> {
        let mut socket = Socket::new(
            Ipv4Addr::new(10, 0, 0, 1),
            remote_addr,
            self.select_unused_port(),
            remote_port,
        )?;
        socket.send_tcp_packet(flags::SYN, &[])?;
        let socket_id = socket.get_socket_id();
        io::Result::Ok(socket_id)
    }
}

mod flags {
    pub const CWR: u8 = 1 << 7;
    pub const ECE: u8 = 1 << 6;
    pub const URG: u8 = 1 << 5;
    pub const ACK: u8 = 1 << 4;
    pub const PSH: u8 = 1 << 3;
    pub const RST: u8 = 1 << 2;
    pub const SYN: u8 = 1 << 1;
    pub const FIN: u8 = 1;
}
