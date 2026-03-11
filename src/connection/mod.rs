use std::{
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream},
};

use aes_gcm::aead::OsRng;
use dns_lookup::lookup_host;
use log::info;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

use crate::{
    connection::{
        config::SecurePipeConfig,
        handshake::{HandshakeMessage, StreamSerializable},
    },
    pump::{DecodingPump, EncodingPump, Pump},
};

pub mod config;

mod handshake;

fn resolve_name(name: &str) -> Result<IpAddr, io::Error> {
    let Some(addr) = lookup_host(name)?.find(|a| a.is_ipv4()) else {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "No address available",
        ));
    };
    Ok(addr)
}

pub struct SecurePipePeer {
    pub remote: Option<String>,
    pub port: u16,
    pub config: SecurePipeConfig,
}

pub struct SecurePipeConnection {
    config: SecurePipeConfig,
    shared_secret: SharedSecret,
    channel: TcpStream,
}

impl SecurePipePeer {
    pub fn server(config: SecurePipeConfig, port: u16) -> Self {
        Self {
            remote: None,
            port,
            config,
        }
    }

    pub fn client(config: SecurePipeConfig, remote: String, port: u16) -> Self {
        Self {
            remote: Some(remote),
            port,
            config,
        }
    }

    fn open_channel(&self) -> io::Result<(TcpStream, SocketAddr)> {
        match &self.remote {
            None => {
                // server
                let serversocket =
                    TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, self.port))?;
                info!("Listening on port 0.0.0.0:{}", self.port);
                serversocket.accept()
            }
            Some(hostname) => {
                let addr = resolve_name(hostname.as_str())?;
                info!("Connecting to {} ({}) port {}", hostname, addr, self.port);
                let sockaddr = SocketAddr::new(addr, self.port);
                let socket = TcpStream::connect(sockaddr)?;
                info!("Connection estabilished");
                Ok((socket, sockaddr))
            }
        }
    }

    pub fn connect(&self) -> anyhow::Result<SecurePipeConnection> {
        let (mut channel, _) = self.open_channel()?;

        let priv_key = EphemeralSecret::random_from_rng(OsRng);
        let our_hello = HandshakeMessage::new(PublicKey::from(&priv_key), self.config.clone());
        our_hello.write_to(&mut channel)?;

        let theirs_hello = HandshakeMessage::read_from(&mut channel)?;
        our_hello.check_peer_compatible(&theirs_hello)?;

        let shared_secret = theirs_hello.derive_key(priv_key);
        let connection = SecurePipeConnection {
            config: self.config.clone(),
            shared_secret,
            channel,
        };
        Ok(connection)
    }
}

impl SecurePipeConnection {
    pub fn pump_in(&mut self, src: &mut dyn Read) -> anyhow::Result<()> {
        let mut pump = EncodingPump::new(self.shared_secret.as_bytes(), src, &mut self.channel);
        pump.compression = self.config.use_compression;
        pump.pump_all()
    }

    pub fn pump_out(&mut self, dest: &mut dyn Write) -> anyhow::Result<()> {
        let mut pump = DecodingPump::new(self.shared_secret.as_bytes(), &mut self.channel, dest);
        pump.compression = self.config.use_compression;
        pump.pump_all()
    }
}

#[cfg(test)]
mod test {
    use std::{
        io::{Write, copy},
        sync::Arc,
        thread::{JoinHandle, sleep, spawn},
        time::Duration,
    };

    use rand::{TryRngCore, rngs::OsRng};

    use crate::{
        buffer::BufferedPipe,
        connection::{
            SecurePipePeer,
            config::{SecurePipeConfig, SecurePipeMode},
        },
    };

    fn run_through(data: Vec<u8>, use_compression: bool, port: u16) {
        let data_arc = Arc::new(data);

        let enc_config = SecurePipeConfig::new(SecurePipeMode::Encrypt, use_compression);
        let dec_config = SecurePipeConfig::new(SecurePipeMode::Decrypt, use_compression);
        let enc_data = data_arc.clone();
        let dec_data = data_arc.clone();

        let dec: JoinHandle<anyhow::Result<Box<Vec<u8>>>> = spawn(move || {
            let data = dec_data;
            let peer = SecurePipePeer::server(dec_config, port);
            let mut connection = peer.connect()?;

            let mut buffer = BufferedPipe::new(data.len());
            connection.pump_out(&mut buffer)?;

            let mut out = Box::new(Vec::new());
            copy(&mut buffer, &mut out)?;

            Ok(out)
        });
        let enc: JoinHandle<anyhow::Result<()>> = spawn(move || {
            sleep(Duration::from_millis(10));
            let data = enc_data;
            let peer = SecurePipePeer::client(enc_config, String::from("localhost"), port);

            let mut connection = peer.connect()?;

            let mut buffer = BufferedPipe::new(data.len());
            buffer.write_all(&data)?;
            connection.pump_in(&mut buffer)?;

            Ok(())
        });

        enc.join().unwrap().expect("Encryptor failed");
        let decrypted = dec.join().unwrap().expect("Decryptor error");

        assert_eq!(data_arc.as_slice(), decrypted.as_slice());
    }

    fn make_connection(
        server_config: SecurePipeConfig,
        client_config: SecurePipeConfig,
        port: u16,
    ) -> (anyhow::Result<()>, anyhow::Result<()>) {
        let server: JoinHandle<anyhow::Result<()>> = spawn(move || {
            SecurePipePeer::server(server_config, port).connect()?;
            Ok(())
        });
        let client: JoinHandle<anyhow::Result<()>> = spawn(move || {
            sleep(Duration::from_millis(10));
            SecurePipePeer::client(client_config, String::from("localhost"), port).connect()?;
            Ok(())
        });

        let client_result = client.join().unwrap();
        let server_result = server.join().unwrap();

        (client_result, server_result)
    }

    #[test]
    fn test_simple() {
        run_through(vec![1, 2, 3, 4, 5, 6], false, 10400);
    }

    #[test]
    fn test_empty_buffer() {
        run_through(Vec::new(), false, 10401);
    }

    #[test]
    fn test_empty_buffer_compressed() {
        run_through(Vec::new(), true, 10402);
    }

    #[test]
    fn test_randomized() {
        let mut data = vec![0u8; 128];
        OsRng.try_fill_bytes(&mut data).expect("RNG failed");
        run_through(data, false, 10403);
    }

    #[test]
    fn test_randomized_long() {
        let mut data = vec![0u8; 32768];
        OsRng.try_fill_bytes(&mut data).expect("RNG failed");
        run_through(data, false, 10404);
    }

    #[test]
    fn test_randomized_compressed() {
        let mut data = vec![0u8; 128];
        OsRng.try_fill_bytes(&mut data).expect("RNG failed");
        run_through(data, true, 10405);
    }

    #[test]
    fn test_randomized_long_compressed() {
        let mut data = vec![0u8; 32768];
        OsRng.try_fill_bytes(&mut data).expect("RNG failed");
        run_through(data, true, 10406);
    }

    #[test]
    fn test_connect_enc2enc() {
        let (r1, r2) = make_connection(
            SecurePipeConfig::new(SecurePipeMode::Encrypt, false),
            SecurePipeConfig::new(SecurePipeMode::Encrypt, false),
            10407,
        );
        assert!(r1.is_err());
        assert!(r2.is_err());
    }

    #[test]
    fn test_connect_dec2dec() {
        let (r1, r2) = make_connection(
            SecurePipeConfig::new(SecurePipeMode::Decrypt, false),
            SecurePipeConfig::new(SecurePipeMode::Decrypt, false),
            10408,
        );
        assert!(r1.is_err());
        assert!(r2.is_err());
    }

    #[test]
    fn test_connect_zenc2dec() {
        let (r1, r2) = make_connection(
            SecurePipeConfig::new(SecurePipeMode::Encrypt, true),
            SecurePipeConfig::new(SecurePipeMode::Decrypt, false),
            10409,
        );
        assert!(r1.is_err());
        assert!(r2.is_err());
    }

    #[test]
    fn test_connect_enc2zdec() {
        let (r1, r2) = make_connection(
            SecurePipeConfig::new(SecurePipeMode::Encrypt, false),
            SecurePipeConfig::new(SecurePipeMode::Decrypt, true),
            10410,
        );
        assert!(r1.is_err());
        assert!(r2.is_err());
    }
}
