use std::{fs::File, io::{self, Read, Write}, net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream}};

use aes_gcm::aead::OsRng;
use dns_lookup::lookup_host;
use getopts::Options;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

use crate::pipe::{DecryptPipe, EncryptPipe, Pipe};

mod rng;
mod pipe;

const DEFAULT_BUFFER_SIZE: usize = 4096;
const DEFAULT_PORT: u16 = 4096;

fn resolve_name(name: &str) -> Result<IpAddr, io::Error> {
    let Some(addr) = lookup_host(name)?.find(|a| a.is_ipv4()) else {
        return Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "No address available"));
    };
    return Ok(addr);
}

fn obtain_socket(host: Option<String>, port: u16) -> Result<(TcpStream, SocketAddr), io::Error> {
    match host {
        None => { // server
            let serversocket = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))?;
            return serversocket.accept();
        },
        Some(hostname) => {
            let addr = resolve_name(hostname.as_str())?;
            let sockaddr = SocketAddr::new(addr, port);
            let socket = TcpStream::connect(sockaddr)?;
            return Ok((socket, sockaddr));
        }
    }
}

fn dh_kex(socket: &mut TcpStream) -> Result<SharedSecret, io::Error> {
    let private = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&private);

    // Send our key
    socket.write_all(public.as_bytes())?;

    // Receive their key
    let mut peer_public_buffer = [0u8; 32];
    socket.read_exact(&mut peer_public_buffer)?;

    let peer_public = PublicKey::from(peer_public_buffer);

    return Ok(private.diffie_hellman(&peer_public));
}

fn main() {
    let mut opts = Options::new();

    opts.optflag("h", "help", "Displays this help message");
    opts.optflag("d", "decrypt", "Designated decrypting end");
    opts.optopt("i", "input", "Read input from", "source");
    opts.optopt("o", "output", "Write output to", "dest");
    opts.optopt("p", "port", "Use the given port", "port");
    opts.optopt("b", "block-size", "The size of plaintext blocks", "block-size");

    let m = opts.parse(std::env::args()).expect("Parsing arguments failed");

    if m.opt_present("h") {
        writeln!(io::stderr(), "{}\n{}", opts.short_usage("securepipe"), opts.usage("A simple pipe for secure network transfers")).expect("Writing help failed");
        return;
    }

    let port = m.opt_str("p").map(|x| x.parse::<u16>().expect("Parsing port number failed")).unwrap_or(DEFAULT_PORT);
    let Ok((socket, _)) = obtain_socket(m.free.get(1).cloned(), port) else {
        writeln!(io::stderr(), "Unable to estabilish connection").expect("STDERR write failed");
        return;
    };

    let mut boxed_socket = Box::new(socket);

    let key = dh_kex(boxed_socket.as_mut()).expect("Key exchange failed");
    let seed = dh_kex(boxed_socket.as_mut()).expect("Seed KEX failed");

    let mut src: Box<dyn Read> = match m.opt_str("i") {
        None => Box::new(io::stdin()),
        Some(filename) => Box::new(File::open(filename).expect("Input file open failed"))
    };

    let mut dest: Box<dyn Write> = match m.opt_str("o") {
        None => Box::new(io::stdout()),
        Some(filename) => Box::new(File::open(filename).expect("Output file open failed"))
    };

    if m.opt_present("d") {
        let mut pipe = DecryptPipe::new(key.as_bytes(), seed.as_bytes(), boxed_socket.as_mut(), dest.as_mut());
        pipe.pump_all().expect("IO error");
    }
    else {
        let mut pipe = EncryptPipe::new(key.as_bytes(), seed.as_bytes(), src.as_mut(), boxed_socket.as_mut());
        pipe.read_length = m.opt_str("b").map(|x| x.parse::<usize>().expect("Parsing block length failed")).unwrap_or(DEFAULT_BUFFER_SIZE);
        pipe.pump_all().expect("IO error");
    }
}
