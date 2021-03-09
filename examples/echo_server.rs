use anyhow::Result;
use std::env;
use std::net::Ipv4Addr;
use toy_tcp::tcp::TCP;
use std::sync::Arc;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let local_addr: Ipv4Addr = args[1].parse()?;
    let local_port: u16 = args[2].parse()?;
    echo_server(local_addr, local_port)?;
    Ok(())
}

fn echo_server(local_addr: Ipv4Addr, local_port: u16) -> Result<()> {
    let tcp = TCP::new();
    let listening_socket = tcp.listen(local_addr, local_port)?;
    dbg!("listening");
    loop {
        let connected_socket_id = tcp.accept(listening_socket)?;
        dbg!(format!("accepted: {:?}", connected_socket_id));
        let cloned_tcp = Arc::clone(&tcp);
        std::thread::spawn(move || {
            let mut buffer = [0; 1024];
            loop {
                let copy_size = cloned_tcp.recv(connected_socket_id, &mut buffer).unwrap();
                // dbg!("copy_size", copy_size);
                if copy_size == 0 {
                    dbg!("closing connection...");
                    cloned_tcp.close(connected_socket_id).unwrap();
                    return;
                }
                print!("> {}", std::str::from_utf8(&buffer[..copy_size]).unwrap());
                cloned_tcp
                    .send(connected_socket_id, &buffer[..copy_size])
                    .unwrap();
            }
        });
    }
}
