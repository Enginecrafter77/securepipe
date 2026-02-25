/*
securepipe - a fast and secure means of transferring data between networked machines
Copyright (C) 2025 Enginecrafter77

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

use std::{
    fs::File,
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream},
};

use aes_gcm::aead::OsRng;
use dns_lookup::lookup_host;
use getopts::Options;
use log::{error, info};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

use crate::pipe::{DecryptPipe, EncryptPipe, Pipe};

mod pipe;
mod rng;

const DEFAULT_BUFFER_SIZE: usize = 4096;
const DEFAULT_PORT: u16 = 4096;

fn resolve_name(name: &str) -> Result<IpAddr, io::Error> {
    let Some(addr) = lookup_host(name)?.find(|a| a.is_ipv4()) else {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "No address available",
        ));
    };
    Ok(addr)
}

fn obtain_socket(host: Option<String>, port: u16) -> Result<(TcpStream, SocketAddr), io::Error> {
    match host {
        None => {
            // server
            let serversocket = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))?;
            info!("Listening on port 0.0.0.0:{}", port);
            serversocket.accept()
        }
        Some(hostname) => {
            let addr = resolve_name(hostname.as_str())?;
            info!("Connecting to {} ({}) port {}", hostname, addr, port);
            let sockaddr = SocketAddr::new(addr, port);
            let socket = TcpStream::connect(sockaddr)?;
            info!("Connection estabilished");
            Ok((socket, sockaddr))
        }
    }
}

fn dh_kex<C>(channel: &mut C) -> Result<SharedSecret, io::Error>
where
    C: Read + Write,
{
    let private = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&private);

    // Send our key
    channel.write_all(public.as_bytes())?;

    // Receive their key
    let mut peer_public_buffer = [0u8; 32];
    channel.read_exact(&mut peer_public_buffer)?;

    let peer_public = PublicKey::from(peer_public_buffer);

    Ok(private.diffie_hellman(&peer_public))
}

macro_rules! printerrln {
    ($($arg:tt)*) => {
        writeln!(io::stderr(), $($arg)*).expect("STDERR write failed");
    };
}

const DESCRIPTION: &str = r"
The main goal of securepipe is to allow fast and secure transfer of large amounts of data
between networked machines. Securepipe tries to follow the unix tools principles; the cleartext
data is read from stdin, and decrypted data is outputed from stdout on the other side, thus allowing
securepipe to be used in shell pipelines.

Securepipe operates in 4 distinct modes:
  1. encrypting server
  2. encrypting client
  3. decrypting server
  4. decrypting client

These modes are given by the command line options provided to securepipe. By default, securepipe operates
in the encryption mode. That is, plaintext data is read from input (stdin by default) and encrypted data are
sent through the socket. By specifying the -d switch, securepipe can be switched to decrypting mode; that is,
encrypted data is read from the socket, and decrypted data is written to output (stdout by default).

Whether securepipe acts as a server or client is given by the presence of the host argument. If the host
argument is missing, securepipe acts as server. That is, it binds to a port on 0.0.0.0 (all interfaces) and
listens for incoming connections. If the host argument is present, securepipe acts as client; that is, it attempts
to connect to a listening instance of securepipe running on the given host. By default, securepipe runs on port 4096,
but one can use a custom port using the -p switch.

By default, securepipe reads data from stdin (encrypting mode) and writes to stdout (decrypting mode). However,
you can directly read from a file using the -i option, and write the output to a file using the -o option.

A simple example use case:
(server) machine1: cat /var/log/messages.log | securepipe -vv
(client) machine2: securepipe -vv -d machine1.local > messages.log
";

const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let mut opts = Options::new();

    opts.optflag("h", "help", "Displays this help message");
    opts.optflag("d", "decrypt", "Designated decrypting end");
    opts.optopt("i", "input", "Read input from", "source");
    opts.optopt("o", "output", "Write output to", "dest");
    opts.optopt("p", "port", "Use the given port (default: 4096)", "port");
    opts.optopt(
        "b",
        "block-size",
        "The size of plaintext blocks",
        "block-size",
    );
    opts.optflagmulti("v", "verbose", "Add 1 verbosity level");
    opts.optflag("q", "quiet", "Suppresses all logging output");

    let m = opts
        .parse(std::env::args())
        .expect("Parsing arguments failed");

    stderrlog::new()
        .module(module_path!())
        .quiet(m.opt_present("q"))
        .verbosity(m.opt_count("v"))
        .init()
        .expect("Logging framework init failed");

    if m.opt_present("h") {
        printerrln!(
            "{} [host]\n{}{}\nSecurepipe version: {}",
            opts.short_usage("securepipe"),
            opts.usage("A simple pipe for secure network transfers."),
            DESCRIPTION,
            PKG_VERSION
        );
        return;
    }

    let port = m
        .opt_str("p")
        .map(|x| x.parse::<u16>().expect("Parsing port number failed"))
        .unwrap_or(DEFAULT_PORT);
    let Ok((mut socket, _)) = obtain_socket(m.free.get(1).cloned(), port) else {
        error!("Unable to estabilish TCP connection");
        return;
    };

    info!("Performing encryption key DH exchange");
    let key = dh_kex(&mut socket).expect("Key exchange failed");
    info!("Performing rng seed DH exchange");
    let seed = dh_kex(&mut socket).expect("Seed KEX failed");

    let mut src: Box<dyn Read> = match m.opt_str("i") {
        None => Box::new(io::stdin()),
        Some(filename) => Box::new(File::open(filename).expect("Input file open failed")),
    };

    let mut dest: Box<dyn Write> = match m.opt_str("o") {
        None => Box::new(io::stdout()),
        Some(filename) => Box::new(File::create(filename).expect("Output file open failed")),
    };

    if m.opt_present("d") {
        info!("Decrypting socket stream to output...");
        let mut pipe =
            DecryptPipe::new(key.as_bytes(), seed.as_bytes(), &mut socket, dest.as_mut());
        pipe.pump_all().expect("IO error");
    } else {
        info!("Encrypting input to socket stream...");
        let mut pipe = EncryptPipe::new(key.as_bytes(), seed.as_bytes(), src.as_mut(), &mut socket);
        pipe.read_length = m
            .opt_str("b")
            .map(|x| x.parse::<usize>().expect("Parsing block length failed"))
            .unwrap_or(DEFAULT_BUFFER_SIZE);
        pipe.pump_all().expect("IO error");
    }
}
