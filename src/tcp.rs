use crate::packet::TCPPacket;
use crate::socket::{Socket, SocketID, TcpStatus};
use anyhow::Context;
use anyhow::Result;
use pnet::packet::{ip::IpNextHeaderProtocols, tcp::TcpPacket, Packet};
use pnet::transport::{
    self, transport_channel, Ipv4TransportChannelIterator, TransportChannelType, TransportProtocol,
};
use rand::rngs::ThreadRng;
use rand::Rng;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::ops::{DerefMut, Range};
use std::process::Command;
use std::str::FromStr;
use std::sync::{Arc, Condvar, Mutex, RwLock, RwLockWriteGuard};
use std::time::Duration;
use std::{cmp, io, thread};

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

        let cloned = Arc::clone(&tcp);
        std::thread::spawn(move || cloned.timer());
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
            get_source_addr(remote_addr)?,
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

    pub fn listen(&self, local_addr: Ipv4Addr, local_port: u16) -> Result<SocketID> {
        let socket = Socket::new(
            local_addr,
            UNDETERMINED_IP_ADDR,
            local_port,
            UNDEFINED_PORT,
            TcpStatus::Listen,
        )?;
        let socket_id = socket.get_socket_id();
        let mut table = self.sockets.write().unwrap();
        table.insert(socket_id, socket);
        Ok(socket_id)
    }

    pub fn accept(&self, socket_id: SocketID) -> Result<SocketID> {
        self.wait_event(socket_id, TCPEventKind::ConnectionCompleted);

        let mut table = self.sockets.write().unwrap();
        let socket = table
            .get_mut(&socket_id)
            .context(format!("No such socket: {:?}", socket_id))?;
        let socked_id = socket
            .connected_connection_queue
            .pop_front()
            .context("no connected socket")?;
        Ok(socket_id)
    }

    pub fn send(&self, socket_id: SocketID, buffer: &[u8]) -> Result<()> {
        let mut cursor = 0;
        while cursor < buffer.len() {
            let mut table = self.sockets.write().unwrap();
            let socket = table
                .get_mut(&socket_id)
                .context(format!("no such socket id: {:?}", socket_id))?;
            let send_size = cmp::min(MSS, buffer.len());
            socket.send_tcp_packet(
                socket.send_param.next,
                socket.recv_param.next,
                flags::ACK,
                &buffer[cursor..cursor + send_size],
            )?;
            cursor += send_size;
            socket.send_param.next += send_size as u32;
        }
        Ok(())
    }

    fn receive_handler(&self) {
        dbg!("begin recv thread");
        let (_, mut receiver) = transport_channel(
            65535,
            TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp),
        )
        .unwrap();
        let mut packet_iter = transport::ipv4_packet_iter(&mut receiver);
        loop {
            let (packet, remote_addr) = match packet_iter.next() {
                Ok(tuple) => tuple,
                Err(e) => {
                    println!("err: {:?}", e);
                    continue;
                }
            };
            // the packet is a received one so destination means local addr.
            let local_addr: Ipv4Addr = packet.get_destination();
            let remote_addr = match remote_addr {
                IpAddr::V4(addr) => addr,
                IpAddr::V6(_) => continue,
            };
            let packet = match get_tcp_packet(&packet) {
                Some(p) => p,
                None => continue,
            };
            if !packet.correct_checksum(local_addr, remote_addr) {
                dbg!("invalid checksum");
                continue;
            }

            // get Socket
            let mut table = self.sockets.write().unwrap();
            let socket = table.get_mut(&SocketID(
                local_addr,
                remote_addr,
                // the packet is a received one so dest and src mean local and remote port respectively.
                packet.get_dest(),
                packet.get_src(),
            ));
            let socket = if socket.is_some() {
                socket
            } else {
                table.get_mut(&SocketID(
                    local_addr,
                    UNDETERMINED_IP_ADDR,
                    packet.get_dest(),
                    UNDEFINED_PORT,
                ))
            };
            let socket = match socket {
                Some(s) => s,
                None => continue,
            };

            let socket_status = socket.status.clone();
            let socket_id = socket.get_socket_id();
            std::mem::drop(table);

            // execute handler based on TcpStatus
            let result = match socket_status {
                TcpStatus::Listen => self.handle_packet_in_listen(socket_id, &packet, remote_addr),
                TcpStatus::SynSent => self.handle_packet_in_synsent(socket_id, &packet),
                TcpStatus::SynRcvd => self.handle_packet_in_synrcvd(socket_id, &packet),
                TcpStatus::Established => self.handle_packet_in_established(socket_id, &packet),
                // TcpStatus::FinWait1 => {}
                // TcpStatus::FinWait2 => {}
                // TcpStatus::TimeWait => {}
                // TcpStatus::CloseWait => {}
                // TcpStatus::LastAck => {}
                _ => {
                    dbg!("not implemented {}", socket_status);
                    Ok(())
                }
            };
            if let Err(err) = result {
                dbg!(err);
            }
        }
    }

    pub fn handle_packet_in_listen(
        &self,
        listening_socket_id: SocketID,
        packet: &TCPPacket,
        remote_addr: Ipv4Addr,
    ) -> Result<()> {
        dbg!("handle_packet_in_listen");
        if packet.has_flag(flags::ACK) {
            // One of cases in the condition is that each TCP is passive open.
            // See Fig 12 on https://tools.ietf.org/html/rfc793#section-3.4
            // Expected to send RST flag which is not implemented in ToyTCP.
            return Ok(());
        }
        if !packet.has_flag(flags::SYN) {
            return Ok(());
        }

        let mut table = self.sockets.write().unwrap();
        let listening_socket = table.get_mut(&listening_socket_id).unwrap();

        // a socket to be connected
        let mut new_socket = Socket::new(
            listening_socket.local_addr,
            remote_addr,
            listening_socket.local_port,
            packet.get_src(),
            TcpStatus::SynRcvd,
        )?;
        new_socket.listening_socket = Some(listening_socket_id);
        // set recv
        new_socket.recv_param.initial_seq = packet.get_seq();
        new_socket.recv_param.next = packet.get_seq() + 1;
        // set send
        new_socket.send_param.initial_seq = rand::thread_rng().gen_range(1..1 << 31);
        new_socket.send_param.window = packet.get_window_size();
        new_socket.send_tcp_packet(
            new_socket.send_param.initial_seq,
            new_socket.recv_param.next,
            flags::SYN | flags::ACK,
            &[],
        )?;
        new_socket.send_param.next = new_socket.send_param.initial_seq + 1;
        new_socket.send_param.unacked_seq = new_socket.send_param.initial_seq;

        dbg!(format!("status: listen -> {}", &new_socket.status));
        table.insert(new_socket.get_socket_id(), new_socket);
        Ok(())
    }

    pub fn handle_packet_in_synrcvd(&self, socket_id: SocketID, packet: &TCPPacket) -> Result<()> {
        dbg!("handle packet in synrcd");
        let mut table = self.sockets.write().unwrap();
        let socket = table.get_mut(&socket_id).unwrap();

        let is_expected_packet = packet.has_flag(flags::ACK)
            && socket.send_param.unacked_seq <= packet.get_ack()
            && packet.get_ack() <= socket.send_param.next;

        if !is_expected_packet {
            dbg!("received unexpected packet");
            return Ok(());
        }

        socket.recv_param.next = packet.get_seq();
        socket.send_param.unacked_seq = packet.get_ack();
        socket.status = TcpStatus::Established;
        if let Some(listening_socket_id) = socket.listening_socket {
            let listening_socket = table.get_mut(&listening_socket_id).unwrap();
            listening_socket
                .connected_connection_queue
                .push_back(socket_id);
            self.publish_event(listening_socket_id, TCPEventKind::ConnectionCompleted);
            dbg!(format!(
                "publish event: {:?}, {:?}",
                &listening_socket_id,
                TCPEventKind::ConnectionCompleted
            ));
            return Ok(());
        }

        Ok(())
    }

    /// handles a received packet in synsent status
    /// see https://tools.ietf.org/html/rfc793#section-3.4
    fn handle_packet_in_synsent(
        &self,
        socket_id: SocketID,
        packet: &TCPPacket,
    ) -> anyhow::Result<()> {
        dbg!("synsent_handler");
        let mut table = self.sockets.write().unwrap();
        let socket = table.get_mut(&socket_id).unwrap();

        let is_correct_syn_received = packet.has_flag(flags::ACK | flags::SYN)
            && socket.send_param.unacked_seq <= packet.get_ack() // means the received ack is not yet acknowledged packet
            && packet.get_ack() <= socket.send_param.next; // means the received ack is in the range of next sequence number to be send

        if !is_correct_syn_received {
            return anyhow::Result::Ok(());
        }

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

        anyhow::Result::Ok(())
    }

    fn handle_packet_in_established(&self, socket_id: SocketID, packet: &TCPPacket) -> Result<()> {
        dbg!("handle packet in established");
        let mut table = self.sockets.write().unwrap();
        let socket = table
            .get_mut(&socket_id)
            .context(format!("no such socket id {:?}", socket_id))?;

        if socket.send_param.unacked_seq < packet.get_ack()
            && packet.get_ack() <= socket.send_param.next
        {
            socket.send_param.unacked_seq = packet.get_ack();
            self.delete_acked_segment_from_retransmission_queue(socket);
        } else if socket.send_param.next < packet.get_ack() {
            // in case receiving a packet that is not yet sent
            return Ok(());
        } else if !packet.has_flag(flags::ACK) {
            return Ok(());
        }

        Ok(())
    }

    fn delete_acked_segment_from_retransmission_queue(&self, socket: &mut Socket) {
        dbg!("ack accept", socket.send_param.unacked_seq);
        while let Some(entry) = socket.retransmission_queue.pop_front() {
            if socket.send_param.unacked_seq > entry.packet.get_seq() {
                dbg!("successfully acked", entry.packet.get_seq());
                self.publish_event(socket.get_socket_id(), TCPEventKind::Acked);
            } else {
                socket.retransmission_queue.push_front(entry);
                break;
            }
        }
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

    fn timer(&self) {
        dbg!("begin timer thread");
        loop {
            let mut table = self.sockets.write().unwrap();
            for (_, socket) in table.iter_mut() {
                while let Some(mut entry) = socket.retransmission_queue.pop_front() {
                    let is_acked = socket.send_param.unacked_seq > entry.packet.get_seq();
                    if is_acked {
                        dbg!("successfully acked", entry.packet.get_ack());
                        continue;
                    }

                    let is_in_time = entry.latest_transmission_time.elapsed().unwrap()
                        < Duration::from_secs(RETRANSMISSION_TIMEOUT);
                    if is_in_time {
                        socket.retransmission_queue.push_front(entry);
                        break;
                    }

                    if entry.transmission_count < MAX_TRANSMISSION {
                        dbg!("retransmit");
                        let entry = socket.resend_packet(entry).unwrap();
                        socket.retransmission_queue.push_back(entry);
                        break;
                    }

                    dbg!("reached MAX_TRANSMISSION");
                }
            }
            drop(table);
            thread::sleep(Duration::from_micros(100));
        }
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

fn get_tcp_packet(pnet_packet: &pnet::packet::ipv4::Ipv4Packet) -> Option<TCPPacket> {
    return match TcpPacket::new(pnet_packet.payload()) {
        Some(p) => Some(TCPPacket::from(p)),
        None => None,
    };
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
