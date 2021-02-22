use pnet::packet::Packet;

const TCP_HEADER_SIZE: usize = 20;
const SOCKET_BUFFER_SIZE: usize = 4380;

#[derive(Clone)]
pub struct TCPPacket {
    buffer: Vec<u8>,
}

/// https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
/// http://www.networksorcery.com/enp/protocol/tcp.htm
impl TCPPacket {
    pub fn new(payload_len: usize) -> Self {
        Self {
            buffer: vec![0; TCP_HEADER_SIZE + payload_len],
        }
    }

    pub fn set_src(&mut self, port: u16) {
        self.buffer[..2].copy_from_slice(&port.to_be_bytes())
    }

    pub fn set_dest(&mut self, port: u16) {
        self.buffer[2..4].copy_from_slice(&port.to_be_bytes())
    }

    pub fn set_flag(&mut self, flag: u8) {
        self.buffer[13] = flag
    }
}

impl Packet for TCPPacket {
    fn packet(&self) -> &[u8] {
        &self.buffer
    }

    fn payload(&self) -> &[u8] {
        &self.buffer[TCP_HEADER_SIZE..]
    }
}
