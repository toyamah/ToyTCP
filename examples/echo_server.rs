use anyhow::Result;
use std::env;
use std::net::Ipv4Addr;
use toy_tcp::tcp::TCP;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let local_addr: Ipv4Addr = args[1].parse()?;
    let local_port: u16 = args[2].parse()?;
    echo_server(local_addr, local_port)?;
    Ok(())
}

fn echo_server(local_addr: Ipv4Addr, local_port: u16)-> Result<()> {
    let tcp = TCP::new();
    let listening_port = tcp.listen(local_addr, local_port)?;
    dbg!("listening");
    loop {
        let connected_socket = tcp.accept(listening_port);
        dbg!(format!("accepted: {:?}", connected_socket));
    }
}