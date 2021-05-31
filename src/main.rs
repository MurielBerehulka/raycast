use mio::{Events, Interest, Poll, Token};
use mio::net::{TcpListener, TcpStream};
use std::net::Shutdown;
use std::io::{self, Read, Write, ErrorKind, Cursor};
use std::collections::HashMap;
use sha1::{Sha1, Digest};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

const LISTENER_EVENT_TOKEN: Token = Token(0);
const HEADER_WS_0: &'static [u8] = b"Upgrade: websocket";
const HEADER_WS_1: &'static [u8] = b"Connection: Upgrade";
const HEADER_WS_2: &'static [u8] = b"Sec-WebSocket-Version: 13";
const HEADER_WS_3: &'static [u8] = b"Sec-WebSocket-Key";

struct Client {
    socket: TcpStream,
    //WebSocket HandShake Done
    wshs: bool,
    key: Option<String>
}

impl Client {
    pub fn send(&mut self, data: &[u8]) {
        if self.wshs {
            let mut one: u8 = 128;
            one |= 0x80;
            one |= 1u8;

            let mut two = 0u8;

            match data.len() {
                len if len < 126 => {
                    two |= len as u8;
                }
                len if len <= 65535 => {
                    two |= 126;
                }
                _ => {
                    two |= 127;
                }
            }

            let mut data_framed: Vec<u8> = Vec::new();
            let mut w = Cursor::new(&mut data_framed);
            if let Err(e) = w.write_all(&[one, two]) {panic!("{}", e)};

            if let Some(length_bytes) = match data.len() {
                len if len < 126 => None,
                len if len <= 65535 => Some(2),
                _ => Some(8)
            } {
                if let Err(e) = w.write_uint::<BigEndian>(data.len() as u64, length_bytes) {panic!("{}", e)};
            }

            if let Err(e) = w.write_all(&data) {panic!("{}", e)};
            
            println!("Sending: {:?}", &data_framed);
            if let Err(e) = self.socket.write_all(&data_framed) {
                println!("Error writing: {}", e);
            }
        }else {
            if let Err(e) = self.socket.write_all(data) {
                println!("Error writing: {}", e);
            }
        }
    }
}

fn main() {

    let addr = "127.0.0.1:80".parse().unwrap();

    let mut poll = Poll::new().unwrap();

    let mut listener = TcpListener::bind(addr).unwrap();
    poll.registry().register(&mut listener, LISTENER_EVENT_TOKEN, Interest::READABLE).unwrap();

    let mut clients_length = 0;
    let mut clients: HashMap<Token, Client> = HashMap::new();

    let mut events = Events::with_capacity(1024);
    loop {
        poll.poll(&mut events, None).unwrap();
        for event in events.iter() {
            match event.token() {
                LISTENER_EVENT_TOKEN => {
                    match listener.accept() {
                        Ok((mut socket, _)) => {
                            clients_length += 1;
                            let token = Token(clients_length);
                            poll.registry().register(
                                &mut socket,
                                token,
                                Interest::READABLE
                            ).unwrap();
                            clients.insert(token, Client {
                                socket,
                                wshs: false,
                                key: None
                            });
                            poll.registry().reregister(&mut listener, LISTENER_EVENT_TOKEN, Interest::READABLE).unwrap();
                        },
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => panic!("Unexpected error: {}", e)
                    }
                },
                token => {
                    let mut buff = [0; 2048];
                    let mut buff_len = 0;
                    let stream_close: bool = 
                        if let Some(client) = clients.get_mut(&token) {
                            loop {
                                match client.socket.read(&mut buff) {
                                    Ok(0) => break true,
                                    Ok(len) => {
                                        buff_len = len;
                                        break false
                                    },
                                    Err(e) => break match e.kind() {
                                        ErrorKind::WouldBlock => false,
                                        ErrorKind::ConnectionReset | _ => true
                                    }
                                }
                            }
                        } else {
                            false
                        };
                    if stream_close {
                        println!("Client destroyed");
                        let mut client = match clients.remove(&token) {
                            Some(v) => v,
                            None => panic!("Client not found")
                        };
                        if let Err(e) = client.socket.shutdown(Shutdown::Both) {
                            println!("Error shutting down connection: {}", e)
                        }
                        poll.registry().deregister(
                            &mut client.socket
                        ).unwrap();
                    } else {
                        if let Some(client) = clients.get_mut(&token) {
                            let data = &buff[0..buff_len];
                            if client.wshs && buff_len > 2{
                                if let Some(text) = parse_data(data) {
                                    println!("Received: {}", String::from_utf8_lossy(&text));
                                    client.send(b"test");
                                }
                            }else{
                                if let Some(key) = search_ws_headers(data) {
                                    let mut hasher = Sha1::new();
                                    hasher.update(&key);
                                    hasher.update("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
                                    let hashed = base64::encode(hasher.finalize());
                                    client.send(format!(
                                        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept:{}\r\n\r\n",
                                        &hashed
                                    ).as_bytes());
                                    client.key = Some(hashed);
                                    client.wshs = true;
                                    println!("New WS Connection");
                                }else {
                                    println!("No WS headers found");
                                }
                            }
                            poll.registry().reregister(
                                &mut client.socket,
                                token,
                                Interest::READABLE
                            ).unwrap();
                        }
                    }
                }
            }
        }
    }
}

fn search_ws_headers(data: &[u8]) -> Option<Vec<u8>> {
    let mut i: usize = 0;
    let mut j: usize = 0;
    let mut header_0_found = false;
    let mut header_1_found = false;
    let mut header_2_found = false;
    let mut header_3_found = false;
    let mut key: Option<Vec<u8>> = None;
    for d in data {
        if *d == '\r' as u8 {
            if i > 0 {
                i += 2;
            }
            let line = &data[i..j];
            if !header_0_found {
                if line == HEADER_WS_0 {
                    header_0_found = true;
                }
            }
            if !header_1_found {
                if line == HEADER_WS_1 {
                    header_1_found = true;
                }
            }
            if !header_2_found {
                if line == HEADER_WS_2 {
                    header_2_found = true;
                }
            }
            if !header_3_found {
                let len = line.len();
                if len > 19 && &line[0..17] == HEADER_WS_3 {
                    header_3_found = true;
                    key = Some(Vec::from(&line[19..len]));
                }
            }
            i = j;
        }
        j += 1;
    }
    if header_0_found && header_1_found && header_2_found {
        if let Some(key) = key {
            return Some(key)
        }
    }
    None
}

pub fn parse_data(_data: &[u8]) -> Option<Vec<u8>> {
    let mut cursor = Cursor::new(_data);

    cursor.set_position(2);

    let first = _data[0];
    let second = _data[1];
    let rsv1 = first & 0b1000000 != 0;
    let rsv2 = first & 0b100000 != 0;
    let rsv3 = first & 0b10000 != 0;
    let opcode = first & 0b1111;

    if second & 0b10000000 == 0 {
        return None
    }

    let mut header_length = 2;

    let mut length = u64::from(second & 0b1111111);
    if let Some(length_nbytes) = match length {
        126 => Some(2),
        127 => Some(8),
        _ => None,
    } {
        match cursor.read_uint::<BigEndian>(length_nbytes) {
            Ok(read) => length = read,
            Err(ref err) if err.kind() == ErrorKind::UnexpectedEof => {
                return None;
            }
            Err(_) => return None
        };
        header_length += length_nbytes as u64;
    }

    let mut mask_bytes = [0u8; 4];
    let mask = match cursor.read(&mut mask_bytes) {
        Ok(v) => {
            if v != 4 {
                return None;
            } else {
                header_length += 4;
                Some(mask_bytes)
            }
        },
        Err (_) => return None
    };

    match length.checked_add(header_length) {
        Some(l) if l > _data.len() as u64 => {
            return None;
        }
        Some(_) => (),
        None => return None
    };

    let mut data = vec![0u8; length as usize];
    if length > 0 {
        match cursor.read(&mut data) {
            Ok(v) => if v != length as usize {
                return None;
            },
            Err(_) => return None
        }
    }

    // Allow only text opcode
    if opcode != 1 {
        return None;
    }

    let mut one: u8 = 128;
    if rsv1 {
        one |= 0b1000000;
    }
    if rsv2 {
        one |= 0b100000;
    }
    if rsv3 {
        one |= 0b10000;
    }
    one |= opcode;

    let mut two = 0u8;
    if mask.is_some() {
        two |= 0b10000000;
    }

    match data.len() {
        len if len < 126 => {
            two |= len as u8;
        }
        len if len <= 65535 => {
            two |= 126;
        }
        _ => {
            two |= 127;
        }
    }

    let mut w = Cursor::new(Vec::with_capacity(length as usize));
    if let Err(_) = w.write_all(&[one, two]) {return None};

    if let Some(length_bytes) = match length {
        len if len < 126 => None,
        len if len <= 65535 => Some(2),
        _ => Some(8)
    } {
        if let Err(_) = w.write_uint::<BigEndian>(data.len() as u64, length_bytes) {return None};
    }

    if let Some(mask) = mask {
        let iter = data.iter_mut().zip(mask.iter().cycle());
        for (byte, &key) in iter {
            *byte ^= key
        }
    }

    return Some(data)
}

/* 
    0 => Continue,
    1 => Text,
    2 => Binary,
    8 => Close,
    9 => Ping,
    10 => Pong,
    _ => Bad
*/
