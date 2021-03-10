use anyhow::Result;
use std::{env, fs};
use std::net::Ipv4Addr;
use toy_tcp::tcp::TCP;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let local_addr: Ipv4Addr = args[1].parse().unwrap();
    let local_port: u16 = args[2].parse().unwrap();
    let file_path: &str = &args[3];
    file_server(local_addr, local_port, file_path)?;
    Ok(())
}

fn file_server(local_addr: Ipv4Addr, local_port: u16, file_path: &str) -> Result<()> {
    let tcp = TCP::new();
    let listening_socket_id = tcp.listen(local_addr, local_port)?;
    dbg!("listening...");

    loop {
        let connected_socket_id = tcp.accept(listening_socket_id)?;
        dbg!("accepted", connected_socket_id);
        let mut file_contents = Vec::new();
        let mut buffer = [0u8; 2000];
        loop {
            let received_size = tcp.recv(connected_socket_id, &mut buffer)?;
            if received_size == 0 {
                dbg!("closing connection...");
                tcp.close(connected_socket_id)?;
                break;
            }
            file_contents.extend_from_slice(&buffer[..received_size]);
        }
        fs::write(file_path, &file_contents)?;
    }
}
