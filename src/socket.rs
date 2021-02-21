use crate::packet::TCPPacket;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::transport::{
    transport_channel, TransportChannelType, TransportProtocol, TransportSender,
};
use std::io;
use std::net::{IpAddr, Ipv4Addr};

pub struct SocketID(pub Ipv4Addr, pub Ipv4Addr, pub u16, pub u16);

pub struct Socket {
    pub local_addr: Ipv4Addr,
    pub remote_addr: Ipv4Addr,
    pub local_port: u16,
    pub remote_port: u16,
    pub sender: TransportSender,
}

impl Socket {
    pub fn new(
        local_addr: Ipv4Addr,
        remote_addr: Ipv4Addr,
        local_port: u16,
        remote_port: u16,
    ) -> io::Result<Self> {
        let (sender, _) = transport_channel(
            65535,
            // TransportChannelType::Layer4(IpNextHeaderProtocols::Ipv4(IpNextHeaderProtocols::Tcp)),
            TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)),
        )?;
        Ok(Self {
            local_addr,
            remote_addr,
            local_port,
            remote_port,
            sender,
        })
    }

    pub fn send_tcp_packet(&mut self, flag: u8, payload: &[u8]) -> io::Result<usize> {
        let mut tcp_packet = TCPPacket::new(payload.len());
        tcp_packet.set_src(self.local_port);
        tcp_packet.set_dest(self.remote_port);
        tcp_packet.set_flag(flag);

        let send_size = self
            .sender
            .send_to(tcp_packet.clone(), IpAddr::V4(self.remote_addr))?;

        io::Result::Ok(send_size)
    }

    pub fn get_socket_id(&self) -> SocketID {
        SocketID(
            self.local_addr,
            self.remote_addr,
            self.local_port,
            self.remote_port,
        )
    }
}

pub enum TcpStatus {}
