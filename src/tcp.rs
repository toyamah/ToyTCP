use crate::packet::TCPPacket;
use crate::socket::{Socket, SocketID, TcpStatus};
use anyhow::Context;
use pnet::packet::{ip::IpNextHeaderProtocols, tcp::TcpPacket, Packet};
use pnet::transport::{
    self, transport_channel, Ipv4TransportChannelIterator, TransportChannelType, TransportProtocol,
};
use rand::rngs::ThreadRng;
use rand::Rng;
use std::collections::HashMap;
use std::io;
use std::io::Error;
use std::net::{IpAddr, Ipv4Addr};
use std::ops::{DerefMut, Range};
use std::process::Command;
use std::str::FromStr;
use std::sync::{Arc, Condvar, Mutex, RwLock};

const UNDETERMINED_IP_ADDR: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);
const UNDEFINED_PORT: u16 = 0;
const MAX_TRANSMISSION: u8 = 5;
const RETRANSMISSION_TIMEOUT: u64 = 3;
const MSS: usize = 1460;
const PORT_RANGE: Range<u16> = 40000..60000;

pub struct TCP {
    sockets: RwLock<HashMap<SocketID, Socket>>,
    event_condvar: (Mutex<Option<TCPEvent>>, Condvar),
}

impl TCP {
    pub fn new() -> Arc<Self> {
        let sockets = RwLock::new(HashMap::new());
        let tcp = Arc::new(Self {
            sockets,
            event_condvar: (Mutex::new(None), Condvar::new()),
        });
        let cloned = Arc::clone(&tcp);
        std::thread::spawn(move || cloned.receive_handler());
        tcp
    }

    fn select_unused_port(&self, rng: &mut ThreadRng) -> anyhow::Result<u16> {
        for _ in PORT_RANGE {
            let local_port = rng.gen_range(PORT_RANGE);
            let sockets = self.sockets.read().unwrap();
            if sockets.keys().all(|k| local_port != k.2) {
                return Ok(local_port);
            }
        }
        anyhow::bail!("no available port found")
    }

    pub fn connect(&self, remote_addr: Ipv4Addr, remote_port: u16) -> anyhow::Result<SocketID> {
        let mut rng = rand::thread_rng();
        let mut socket = Socket::new(
            Ipv4Addr::new(10, 0, 0, 1),
            remote_addr,
            self.select_unused_port(&mut rng)?,
            remote_port,
            TcpStatus::SynSent,
        )?;
        socket.send_param.initial_seq = rng.gen_range(1..1 << 31);
        socket.send_tcp_packet(socket.send_param.initial_seq, 0, flags::SYN, &[])?;
        socket.send_param.unacked_seq = socket.send_param.initial_seq;
        socket.send_param.next = socket.send_param.initial_seq + 1;

        let socket_id = socket.get_socket_id();
        let mut table = self.sockets.write().unwrap();
        table.insert(socket_id, socket);

        std::mem::drop(table);

        self.wait_event(socket_id, TCPEventKind::ConnectionCompleted);
        anyhow::Result::Ok(socket_id)
    }

    fn receive_handler(&self) {
        dbg!("begin recv thread");
        let (_, mut receiver) = transport_channel(
            65532,
            TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp),
        )
        .unwrap();
        let mut packet_iter = transport::ipv4_packet_iter(&mut receiver);
        loop {
            let (packet, remote_addr) = match packet_iter.next() {
                Ok((p, r)) => (p, r),
                Err(_) => continue,
            };
            let local_addr = packet.get_destination();
            let tcp_packet = match TcpPacket::new(packet.payload()) {
                Some(p) => p,
                None => continue,
            };

            let packet = TCPPacket::from(tcp_packet);
            let remote_addr = match remote_addr {
                IpAddr::V4(addr) => addr,
                _ => continue,
            };

            if !packet.correct_checksum(local_addr, remote_addr) {
                dbg!("invalid checksum");
                continue;
            }

            let mut table = self.sockets.write().unwrap();
            let socket = table.get_mut(&SocketID(
                local_addr,
                remote_addr,
                packet.get_src(),
                packet.get_dest(),
            ));
            let socket = if socket.is_some() {
                socket
            } else {
                table.get_mut(&SocketID(
                    local_addr,
                    UNDETERMINED_IP_ADDR,
                    packet.get_src(),
                    UNDEFINED_PORT,
                ))
            };
            let socket = match socket {
                Some(s) => s,
                None => continue,
            };

            let result = match socket.status {
                // TcpStatus::Listen => {}
                TcpStatus::SynSent => self.synsent_handler(socket, &packet),
                // TcpStatus::SynRcvd => {}
                // TcpStatus::Established => {}
                // TcpStatus::FinWait1 => {}
                // TcpStatus::FinWait2 => {}
                // TcpStatus::TimeWait => {}
                // TcpStatus::CloseWait => {}
                // TcpStatus::LastAck => {}
                _ => {
                    dbg!("not implemented {}", &socket.status);
                    Ok(())
                }
            };
            if let Err(err) = result {
                dbg!(err);
            }
        }
    }

    fn synsent_handler(&self, socket: &mut Socket, packet: &TCPPacket) -> anyhow::Result<()> {
        dbg!("synsent_handler");
        if packet.has_flag(flags::ACK)
            && socket.send_param.unacked_seq <= packet.get_ack()
            && packet.get_ack() <= socket.send_param.next
            && packet.has_flag(flags::SYN)
        {
            socket.recv_param.next = packet.get_seq() + 1;
            socket.recv_param.initial_seq = packet.get_seq();
            socket.send_param.unacked_seq = packet.get_ack();
            socket.send_param.window = packet.get_window_size();

            if socket.send_param.unacked_seq > socket.send_param.initial_seq {
                socket.status = TcpStatus::Established;
                socket.send_tcp_packet(
                    socket.send_param.next,
                    socket.recv_param.next,
                    flags::ACK,
                    &[],
                )?;
                dbg!("status: synsent ->", &socket.status);
                self.publish_event(socket.get_socket_id(), TCPEventKind::ConnectionCompleted);
            } else {
                socket.status = TcpStatus::SynRcvd;
                socket.send_tcp_packet(
                    socket.send_param.next,
                    socket.recv_param.next,
                    flags::ACK,
                    &[],
                )?;
                dbg!("status: synsent ->", &socket.status);
            }
        }
        anyhow::Result::Ok(())
    }

    fn wait_event(&self, socket_id: SocketID, kind: TCPEventKind) {
        let (lock, cond_var) = &self.event_condvar;
        let mut event = lock.lock().unwrap();
        loop {
            if let Some(ref e) = *event {
                if e.socket_id == socket_id && e.kind == kind {
                    break;
                }
            }
            event = cond_var.wait(event).unwrap();
        }
        dbg!(&event);
        *event = None;
    }

    fn publish_event(&self, socket_id: SocketID, kind: TCPEventKind) {
        let (lock, cond_var) = &self.event_condvar;
        let mut e = lock.lock().unwrap();
        *e = Some(TCPEvent::new(socket_id, kind));
        cond_var.notify_all();
    }
}

#[derive(Debug, Clone)]
struct TCPEvent {
    socket_id: SocketID,
    kind: TCPEventKind,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TCPEventKind {
    ConnectionCompleted,
    Acked,
    DataArrived,
    ConnectionClosed,
}

impl TCPEvent {
    fn new(socket_id: SocketID, kind: TCPEventKind) -> Self {
        Self { socket_id, kind }
    }
}

fn get_source_addr(remote_addr: Ipv4Addr) -> anyhow::Result<Ipv4Addr> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("ip route get {} | grep src", remote_addr))
        .output()?;
    let mut output = std::str::from_utf8(&output.stdout)?
        .trim()
        .split_ascii_whitespace();

    while let Some(s) = output.next() {
        if s == "src" {
            break;
        }
    }
    let ip = output.next().context("failed to get source ip")?;
    dbg!("source addr: ", ip);

    Ipv4Addr::from_str(ip).context(format!("failed to parse source ip: {}", ip))
}

pub mod flags {
    pub const CWR: u8 = 1 << 7;
    pub const ECE: u8 = 1 << 6;
    pub const URG: u8 = 1 << 5;
    pub const ACK: u8 = 1 << 4;
    pub const PSH: u8 = 1 << 3;
    pub const RST: u8 = 1 << 2;
    pub const SYN: u8 = 1 << 1;
    pub const FIN: u8 = 1;

    pub fn flag_to_string(flag: u8) -> String {
        let mut string = String::new();
        if flag & CWR > 0 {
            string += "CWR ";
        }
        if flag & ECE > 0 {
            string += "ECE ";
        }
        if flag & URG > 0 {
            string += "URG ";
        }
        if flag & ACK > 0 {
            string += "ACK ";
        }
        if flag & PSH > 0 {
            string += "PSH ";
        }
        if flag & RST > 0 {
            string += "RST ";
        }
        if flag & SYN > 0 {
            string += "SYN ";
        }
        if flag & FIN > 0 {
            string += "FIN ";
        }

        string
    }
}
