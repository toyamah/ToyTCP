use std::env;
use std::net::Ipv4Addr;
use toy_tcp::tcp::TCP;
use std::io::stdin;
use std::sync::Arc;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let addr: Ipv4Addr = args[1].parse().unwrap();
    let port: u16 = args[2].parse().unwrap();
    echo_client(addr, port)?;
    anyhow::Result::Ok(())
}

fn echo_client(remote_addr: Ipv4Addr, remote_port: u16) -> anyhow::Result<()> {
    let tcp = TCP::new();
    let socket_id = tcp.connect(remote_addr, remote_port)?;

    let cloned_tcp = Arc::clone(&tcp);
    ctrlc::set_handler(move || {
        cloned_tcp.close(socket_id).unwrap();
        std::process::exit(0);
    })?;

    loop {
        let mut input = String::new();
        stdin().read_line(&mut input)?;
        tcp.send(socket_id, input.as_bytes())?;

        let mut buffer = vec![0; 1500];
        let n = tcp.recv(socket_id, &mut buffer)?;
        println!("> {}", std::str::from_utf8(&buffer[..n])?);
    }
}
