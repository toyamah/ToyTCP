use std::net::Ipv4Addr;
use std::{env, io};
use toy_tcp::tcp::TCP;

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let addr: Ipv4Addr = args[1].parse().unwrap();
    let port: u16 = args[2].parse().unwrap();
    echo_client(addr, port)?;
    io::Result::Ok(())
}

fn echo_client(remote_addr: Ipv4Addr, remote_port: u16) -> io::Result<()> {
    let tcp = TCP::new();
    tcp.connect(remote_addr, remote_port)?;
    io::Result::Ok(())
}
