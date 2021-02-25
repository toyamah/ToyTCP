use std::env;
use std::net::Ipv4Addr;
use toy_tcp::tcp::TCP;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let addr: Ipv4Addr = args[1].parse().unwrap();
    let port: u16 = args[2].parse().unwrap();
    echo_client(addr, port)?;
    anyhow::Result::Ok(())
}

fn echo_client(remote_addr: Ipv4Addr, remote_port: u16) -> anyhow::Result<()> {
    let tcp = TCP::new();
    tcp.connect(remote_addr, remote_port)?;
    anyhow::Result::Ok(())
}
