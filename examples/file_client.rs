use anyhow::Result;
use std::{env, fs};
use std::net::Ipv4Addr;
use toy_tcp::tcp::TCP;
use std::sync::Arc;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let remote_addr: Ipv4Addr = args[1].parse().unwrap();
    let remote_port: u16 = args[2].parse().unwrap();
    let file_path: &str = &args[3];
    file_client(remote_addr, remote_port, file_path)?;
    Ok(())
}

fn file_client(remote_addr: Ipv4Addr, remote_port: u16, file_path: &str) -> Result<()>{
    let tcp = TCP::new();
    let socket_id = tcp.connect(remote_addr, remote_port)?;
    let cloned_tcp = Arc::clone(&tcp);
    ctrlc::set_handler(move || {
        cloned_tcp.close(socket_id).unwrap();
        std::process::exit(0);
    })?;

    let input = fs::read(file_path)?;
    tcp.send(socket_id, &input)? ;
    tcp.close(socket_id)?;
    Ok(())
}
