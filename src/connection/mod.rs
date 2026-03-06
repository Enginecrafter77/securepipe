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
