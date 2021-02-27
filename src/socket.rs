use crate::packet::{TCPPacket, SOCKET_BUFFER_SIZE};
use anyhow::Context;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::util::ipv4_checksum;
use pnet::packet::{util, Packet};
use pnet::transport::{
    transport_channel, TransportChannelType, TransportProtocol, TransportSender,
};
use std::collections::VecDeque;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::{fmt, io};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SocketID(pub Ipv4Addr, pub Ipv4Addr, pub u16, pub u16);

pub struct Socket {
    pub local_addr: Ipv4Addr,
    pub remote_addr: Ipv4Addr,
    pub local_port: u16,
    pub remote_port: u16,
    pub send_param: SendParam,
    pub recv_param: RecvParam,
    pub status: TcpStatus,
    // used only by a listening socket
    pub connected_connection_queue: VecDeque<SocketID>,
    // used only by a connected socket
    pub listening_socket: Option<SocketID>,
    sender: TransportSender,
}

impl Socket {
    pub fn new(
        local_addr: Ipv4Addr,
        remote_addr: Ipv4Addr,
        local_port: u16,
        remote_port: u16,
        status: TcpStatus,
    ) -> io::Result<Self> {
        let (sender, _) = transport_channel(
            65535,
            TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)),
        )?;
        Ok(Self {
            local_addr,
            remote_addr,
            local_port,
            remote_port,
            send_param: SendParam {
                unacked_seq: 0,
                next: 0,
                window: SOCKET_BUFFER_SIZE as u16,
                initial_seq: 0,
            },
            recv_param: RecvParam {
                next: 0,
                window: SOCKET_BUFFER_SIZE as u16,
                initial_seq: 0,
                tail: 0,
            },
            status,
            connected_connection_queue: VecDeque::new(),
            listening_socket: None,
            sender,
        })
    }

    pub fn send_tcp_packet(
        &mut self,
        seq: u32,
        ack: u32,
        flag: u8,
        payload: &[u8],
    ) -> anyhow::Result<usize> {
        let mut tcp_packet = TCPPacket::new(payload.len());
        tcp_packet.set_src(self.local_port);
        tcp_packet.set_dest(self.remote_port);
        tcp_packet.set_seq(seq);
        tcp_packet.set_ack(ack);
        tcp_packet.set_data_offset(5);
        tcp_packet.set_flag(flag);
        tcp_packet.set_window_size(self.recv_param.window);
        tcp_packet.set_checksum(ipv4_checksum(
            &tcp_packet.packet(),
            8,
            &[],
            &self.local_addr,
            &self.remote_addr,
            IpNextHeaderProtocols::Tcp,
        ));
        tcp_packet.set_payload(payload);

        let send_size = self
            .sender
            .send_to(tcp_packet.clone(), IpAddr::V4(self.remote_addr))
            .context(format!("failed to send: \n {:?}", tcp_packet))?;

        dbg!("sent", &tcp_packet);
        anyhow::Result::Ok(send_size)
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

/// https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Protocol_operation
/// https://en.wikipedia.org/wiki/Transmission_Control_Protocol#/media/File:Tcp_state_diagram_fixed_new.svg
#[derive(Debug)]
pub enum TcpStatus {
    Listen,
    SynSent,
    SynRcvd,
    Established,
    FinWait1,
    FinWait2,
    TimeWait,
    CloseWait,
    LastAck,
}

impl Display for TcpStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let str = match self {
            TcpStatus::Listen => "LISTEN",
            TcpStatus::SynSent => "SynSent",
            TcpStatus::SynRcvd => "SynRcvd",
            TcpStatus::Established => "Established",
            TcpStatus::FinWait1 => "FinWait1",
            TcpStatus::FinWait2 => "FinWait2",
            TcpStatus::TimeWait => "TimeWait",
            TcpStatus::CloseWait => "CloseWait",
            TcpStatus::LastAck => "LastAck",
        };
        f.write_str(str)
    }
}

///
///    1         2          3          4
///  ----------|----------|----------|----------
///         SND.UNA    SND.NXT    SND.UNA
///                              +SND.WND
///
///  1 - old sequence numbers which have been acknowledged
///  2 - sequence numbers of unacknowledged data
///  3 - sequence numbers allowed for new data transmission
///  4 - future sequence numbers which are not yet allowed
///
/// Fig4 borrowed by https://tools.ietf.org/html/rfc793#section-3.2
#[derive(Debug)]
pub struct SendParam {
    // un-acknowledge head sequence number
    pub unacked_seq: u32,
    // next sequence number to be send
    pub next: u32,
    pub window: u16,
    pub initial_seq: u32,
}

///
///     1          2          3
/// ----------|----------|----------
///        RCV.NXT    RCV.NXT
///                  +RCV.WND
///
///  1 - old sequence numbers which have been acknowledged
///  2 - sequence numbers allowed for new reception
///  3 - future sequence numbers which are not yet allowed
///
/// Fig5 borrowed by https://tools.ietf.org/html/rfc793#section-3.2
#[derive(Debug)]
pub struct RecvParam {
    pub next: u32,
    pub window: u16,
    pub initial_seq: u32,
    pub tail: u32,
}
