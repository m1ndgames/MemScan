use std::net::UdpSocket;
use crate::confighandler;

pub fn sendpacket(input: &str) {
    let (_updatecycle, server_ip, server_port) = confighandler::readconfig();
    let socket = UdpSocket::bind("0.0.0.0:0").expect("couldn't bind to address");

    socket.set_nonblocking(true).unwrap();

    let message = String::from(input);
    let msg_bytes = message.into_bytes();

    socket.send_to(&msg_bytes, server_ip + ":" + &server_port).expect("couldn't send data");
}