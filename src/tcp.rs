use crate::socket::{Socket, SocketID};
use crate::tcp_flags;
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

    pub fn connect(&self, addr: Ipv4Addr, port: u16) -> io::Result<SocketID> {
        let mut socket = Socket::new(
            Ipv4Addr::new(10, 0, 0, 1),
            addr,
            self.select_unused_port(),
            port,
        )?;
        socket.send_tcp_packet(tcp_flags::SYN, &[])?;
        let socket_id = socket.get_socket_id();
        io::Result::Ok(socket_id)
    }
}
