use std::{fs::File, io::{self, Read, Write}, net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream}, ops::DerefMut};

use aes_gcm::{AeadCore, Aes256Gcm, KeyInit, Nonce, aead::{AeadMutInPlace, consts::U12, rand_core::SeedableRng}};
use dns_lookup::lookup_host;
use getopts::Options;

use crate::{rng::StdRngWrapper};

mod rng;

struct CryptPipeContext {
    cipher: Aes256Gcm,
    rng: StdRngWrapper,
    len_buffer: [u8; 4],
    buffer: Vec<u8>,
    default_buffer_size: usize
}

impl CryptPipeContext {
    fn new(key: &[u8; 32], seed: &[u8; 32]) -> Self {
        return Self { cipher: Aes256Gcm::new(key.into()), rng: StdRngWrapper::from_seed(seed.clone()), buffer: Vec::new(), len_buffer: [0u8; 4], default_buffer_size: 4096 }
    }

    fn new_nonce(&mut self) -> Nonce<U12> {
        return Aes256Gcm::generate_nonce(&mut self.rng);
    }

    fn encrypt_round<I,O>(&mut self, src: &mut I, dst: &mut O) -> io::Result<usize> where I: Read, O: Write {
        let nonce = self.new_nonce();

        self.buffer.resize(self.default_buffer_size, 0);
        
        let read_bytes = src.read(self.buffer.as_mut())?;
        if read_bytes == 0 {
            dst.write_all((0 as u32).to_be_bytes().as_slice())?;
            return Ok(0);
        }
        self.buffer.resize(read_bytes, 0);
        self.cipher.encrypt_in_place(&nonce, b"", &mut self.buffer).expect("Encryption failed");

        dst.write_all((self.buffer.len() as u32).to_be_bytes().as_slice())?;
        dst.write_all(self.buffer.as_slice())?;

        return Ok(self.buffer.len());
    }

    fn decrypt_round<I,O>(&mut self, src: &mut I, dst: &mut O) -> io::Result<usize> where I: Read, O: Write {
        let nonce = self.new_nonce();

        src.read_exact(&mut self.len_buffer)?;
        let block_length = u32::from_be_bytes(self.len_buffer) as usize;
        if block_length == 0 {
            return Ok(0);
        }

        self.buffer.resize(block_length, 0);
        src.read_exact(self.buffer.as_mut())?;

        self.cipher.decrypt_in_place(&nonce, b"", &mut self.buffer).expect("Decryption failed");
        dst.write_all(&self.buffer.as_slice())?;

        return Ok(self.buffer.len());
    }
}

macro_rules! extract_array {
    ($n: literal, $a: expr) => {
        {
            let slice = $a.as_slice();
            let mut array = [0u8; $n];
            for i in 0..$n {
                array[i] = slice[i];
            }
            array
        }
    };
}

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

fn main() {
    let key_v = hex::decode(std::env::var("SP_KEY").expect("SP_KEY env variable not set")).expect("Illegal value in SP_KEY");
    let seed_v = hex::decode(std::env::var("SP_SEED").expect("SP_SEED env variable not set")).expect("Illegal value in SP_SEED");
    let key = extract_array!(32, key_v);
    let seed = extract_array!(32, seed_v);

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

    let port = m.opt_str("p").map(|x| x.parse::<u16>().expect("Parsing port number failed")).unwrap_or(4096);
    let Ok((socket, _)) = obtain_socket(m.free.get(1).cloned(), port) else {
        writeln!(io::stderr(), "Unable to estabilish connection").expect("STDERR write failed");
        return;
    };

    let mut boxed_socket = Box::new(socket);

    let mut src: Box<dyn Read> = match m.opt_str("i") {
        None => Box::new(io::stdin()),
        Some(filename) => Box::new(File::open(filename).expect("Input file open failed"))
    };

    let mut dest: Box<dyn Write> = match m.opt_str("o") {
        None => Box::new(io::stdout()),
        Some(filename) => Box::new(File::open(filename).expect("Output file open failed"))
    };

    let mut ctx = CryptPipeContext::new(&key, &seed);
    let mut blen: usize = 1;
    while blen > 0 {
        if m.opt_present("d") {
            blen = ctx.decrypt_round(&mut boxed_socket, &mut dest).expect("IO error");
        } else {
            blen = ctx.encrypt_round(&mut src, &mut boxed_socket).expect("IO error");
        }
    }
}
