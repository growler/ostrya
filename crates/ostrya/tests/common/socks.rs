//! An in-process SOCKS5 proxy for the tests that reach an origin through a
//! SOCKS5 proxy.
//!
//! The proxy speaks the server side of RFC 1928 and RFC 1929 with blocking
//! sockets on threads, so a test crate needs no async runtime to use it. It
//! records each exchange that it reads, and counts its connections.

#![allow(dead_code)]

use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

/// The answer of the proxy to a `CONNECT` request.
#[derive(Clone, Copy, Debug)]
pub enum Reply {
    /// Connects to the target and carries the bytes in both directions.
    Open,
    /// Answers each request with this reply code and connects nothing.
    Refuse(u8),
    /// Answers the first request with this reply code and opens each later
    /// one.
    RefuseFirst(u8),
}

/// The behavior of the proxy.
#[derive(Clone, Copy, Debug)]
pub struct Socks {
    /// The method that the proxy selects. `ff` accepts no method.
    pub method: u8,
    /// The status of the RFC 1929 reply. `00` accepts the credential.
    pub auth_status: u8,
    /// The answer to a `CONNECT` request.
    pub reply: Reply,
}

impl Socks {
    /// A proxy that needs no authentication and opens each connection.
    pub const OPEN: Socks = Socks {
        method: 0x00,
        auth_status: 0x00,
        reply: Reply::Open,
    };
}

/// The record of one exchange. A field that the exchange did not reach keeps
/// its default value.
#[derive(Clone, Debug, Default)]
pub struct SocksSeen {
    /// The methods of the greeting.
    pub methods: Vec<u8>,
    /// The user name and the password of the RFC 1929 exchange.
    pub credential: Option<(Vec<u8>, Vec<u8>)>,
    /// The address type of the request.
    pub atyp: Option<u8>,
    /// The host of the request: an IP address as text, or the name.
    pub host: String,
    /// The port of the request.
    pub port: u16,
}

/// An in-process SOCKS5 proxy.
///
/// For a name, the proxy resolves it and tries each address in turn. If no
/// connect succeeds, it answers with the reply code `05` and closes the
/// connection.
pub struct TestSocks {
    pub addr: SocketAddr,
    seen: Arc<Mutex<Vec<SocksSeen>>>,
    connections: Arc<AtomicUsize>,
}

impl TestSocks {
    pub fn start(config: Socks) -> TestSocks {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let seen: Arc<Mutex<Vec<SocksSeen>>> = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let thread_seen = seen.clone();
        let thread_connections = connections.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else {
                    break;
                };
                thread_connections.fetch_add(1, Ordering::SeqCst);
                let seen = thread_seen.clone();
                let requests = requests.clone();
                thread::spawn(move || {
                    let mut record = SocksSeen::default();
                    let ending = exchange(&stream, config, &requests, &mut record);
                    // The record goes in before the last answer. So a client
                    // that read the answer finds the record.
                    seen.lock().unwrap().push(record);
                    let Ok(Some(ending)) = ending else {
                        return;
                    };
                    if (&stream).write_all(&ending.answer).is_err() {
                        return;
                    }
                    if let Some(target) = ending.target {
                        splice(stream, target);
                    }
                });
            }
        });
        TestSocks {
            addr,
            seen,
            connections,
        }
    }

    /// The URL of the proxy, with the proxy side of the resolve.
    pub fn url(&self) -> String {
        format!("socks5h://{}", self.addr)
    }

    /// The URL of the proxy with `userinfo`.
    pub fn url_with(&self, userinfo: &str) -> String {
        format!("socks5h://{userinfo}@{}", self.addr)
    }

    /// The URL of the proxy, with the client side of the resolve.
    pub fn client_resolve_url(&self) -> String {
        format!("socks5://{}", self.addr)
    }

    /// The URL of the proxy with `userinfo`, with the client side of the
    /// resolve.
    pub fn client_resolve_url_with(&self, userinfo: &str) -> String {
        format!("socks5://{userinfo}@{}", self.addr)
    }

    /// The exchanges that the proxy read, in the order that they ended.
    ///
    /// The proxy records an exchange before it writes the last answer of the
    /// exchange. So the record of each answer that a client read is in the
    /// list.
    pub fn seen(&self) -> Vec<SocksSeen> {
        self.seen.lock().unwrap().clone()
    }

    /// The number of connections that the proxy accepted.
    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

/// The end of an exchange: the last answer of the proxy, and the connection
/// to the target if the proxy opened one.
struct Ending {
    answer: Vec<u8>,
    target: Option<TcpStream>,
}

impl Ending {
    /// An end with `answer` and no connection to the target.
    fn refusal(answer: &[u8]) -> Option<Ending> {
        Some(Ending {
            answer: answer.to_vec(),
            target: None,
        })
    }
}

/// Runs the server side of one exchange up to its last answer, and does not
/// write that answer. Returns the last answer and the connection to the target
/// if the proxy opened one. Returns `None` if the exchange ends with no answer.
fn exchange(
    mut stream: &TcpStream,
    config: Socks,
    requests: &AtomicUsize,
    record: &mut SocksSeen,
) -> io::Result<Option<Ending>> {
    let [version, count] = read_array(&mut stream)?;
    if version != 0x05 {
        return Ok(None);
    }
    record.methods = read_vec(&mut stream, count)?;
    if config.method == 0xff {
        return Ok(Ending::refusal(&[0x05, config.method]));
    }
    stream.write_all(&[0x05, config.method])?;
    if config.method == 0x02 {
        let [_version, user_len] = read_array(&mut stream)?;
        let user = read_vec(&mut stream, user_len)?;
        let [password_len] = read_array(&mut stream)?;
        let password = read_vec(&mut stream, password_len)?;
        record.credential = Some((user, password));
        if config.auth_status != 0x00 {
            return Ok(Ending::refusal(&[0x01, config.auth_status]));
        }
        stream.write_all(&[0x01, config.auth_status])?;
    }
    let [_version, _command, _reserved, atyp] = read_array(&mut stream)?;
    record.atyp = Some(atyp);
    let host = match atyp {
        0x01 => Some(IpAddr::V4(Ipv4Addr::from(read_array::<4>(&mut stream)?))),
        0x04 => Some(IpAddr::V6(Ipv6Addr::from(read_array::<16>(&mut stream)?))),
        0x03 => {
            let [len] = read_array(&mut stream)?;
            record.host = String::from_utf8_lossy(&read_vec(&mut stream, len)?).into_owned();
            None
        }
        _ => return Ok(None),
    };
    record.port = u16::from_be_bytes(read_array(&mut stream)?);
    if let Some(ip) = host {
        record.host = ip.to_string();
    }
    let first = requests.fetch_add(1, Ordering::SeqCst) == 0;
    let refusal = match config.reply {
        Reply::Open => None,
        Reply::Refuse(code) => Some(code),
        Reply::RefuseFirst(code) => first.then_some(code),
    };
    if let Some(code) = refusal {
        return Ok(Ending::refusal(&reply(code)));
    }
    let addresses: Vec<SocketAddr> = match host {
        Some(ip) => vec![SocketAddr::new(ip, record.port)],
        None => (record.host.as_str(), record.port)
            .to_socket_addrs()
            .map(Iterator::collect)
            .unwrap_or_default(),
    };
    match addresses
        .iter()
        .find_map(|address| TcpStream::connect(address).ok())
    {
        Some(target) => Ok(Some(Ending {
            answer: reply(0x00).to_vec(),
            target: Some(target),
        })),
        None => Ok(Ending::refusal(&reply(0x05))),
    }
}

/// A `CONNECT` reply with `code` and the bound address 0.0.0.0:0.
fn reply(code: u8) -> [u8; 10] {
    [0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
}

fn read_array<const N: usize>(stream: &mut &TcpStream) -> io::Result<[u8; N]> {
    let mut bytes = [0; N];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn read_vec(stream: &mut &TcpStream, len: u8) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0; usize::from(len)];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// Carries the bytes in both directions until each side ends its half.
fn splice(client: TcpStream, target: TcpStream) {
    let (Ok(client_reader), Ok(target_reader)) = (client.try_clone(), target.try_clone()) else {
        return;
    };
    let upstream = thread::spawn(move || copy_half(client_reader, target));
    copy_half(target_reader, client);
    let _ = upstream.join();
}

/// Copies `from` into `to`, then ends the write half of `to`.
fn copy_half(mut from: TcpStream, mut to: TcpStream) {
    let _ = io::copy(&mut from, &mut to);
    let _ = to.shutdown(Shutdown::Write);
}
