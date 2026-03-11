use std::io::{Read, Write};

use anyhow::anyhow;
use pkg_version::pkg_version_major;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

use crate::connection::config::{SecurePipeConfig, SecurePipeMode};

const PROTOCOL_VERSION: u8 = pkg_version_major!();

const PEER_FLAG_ENCRYPT: u16 = 0b00;
const PEER_FLAG_DECRYPT: u16 = 0b01;
const PEER_FLAG_COMPRESS_LZ4: u16 = 0b10;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HandshakeMessage {
    pub protocol_version: u8,
    public_key: PublicKey,
    flags: u16,
}

impl HandshakeMessage {
    pub fn new(public_key: PublicKey, config: SecurePipeConfig) -> Self {
        let mode_flag = match config.mode {
            SecurePipeMode::Decrypt => PEER_FLAG_DECRYPT,
            SecurePipeMode::Encrypt => PEER_FLAG_ENCRYPT,
        };
        let compress_flag = {
            if config.use_compression {
                PEER_FLAG_COMPRESS_LZ4
            } else {
                0
            }
        };
        let flags: u16 = mode_flag | compress_flag;

        Self {
            protocol_version: PROTOCOL_VERSION,
            public_key,
            flags,
        }
    }

    pub fn derive_key(&self, priv_key: EphemeralSecret) -> SharedSecret {
        priv_key.diffie_hellman(&self.public_key)
    }

    pub fn get_config(&self) -> SecurePipeConfig {
        let mode = {
            if (self.flags & PEER_FLAG_DECRYPT) > 0 {
                SecurePipeMode::Decrypt
            } else {
                SecurePipeMode::Encrypt
            }
        };
        let use_compression = (self.flags & PEER_FLAG_COMPRESS_LZ4) > 0;
        SecurePipeConfig {
            use_compression,
            mode,
        }
    }

    pub fn check_peer_compatible(&self, other: &HandshakeMessage) -> anyhow::Result<()> {
        if self.protocol_version != other.protocol_version {
            return Err(anyhow!(format!(
                "Peer's protocol version {} is incompatible with local protocol version {}",
                other.protocol_version, self.protocol_version
            )));
        }
        self.get_config().check_peer_compatible(&other.get_config())
    }
}

pub trait StreamSerializable: Sized {
    fn write_to(&self, channel: &mut dyn Write) -> anyhow::Result<()>;
    fn read_from(channel: &mut dyn Read) -> anyhow::Result<Self>;
}

impl StreamSerializable for HandshakeMessage {
    fn write_to(&self, channel: &mut dyn Write) -> anyhow::Result<()> {
        channel.write_all(self.protocol_version.to_be_bytes().as_slice())?;
        channel.write_all(self.flags.to_be_bytes().as_slice())?;
        channel.write_all(self.public_key.as_bytes())?;
        channel.write_all([0u8; 29].as_slice())?; // 29 byte padding for future use
        Ok(())
    }

    fn read_from(channel: &mut dyn Read) -> anyhow::Result<Self> {
        let mut src = [0u8; 64];
        channel.read_exact(&mut src)?;

        let protocol_version = u8::from_be_bytes(src[0..1].try_into()?);
        if protocol_version != PROTOCOL_VERSION {
            return Err(anyhow!(format!(
                "Peer uses incompatible protocol version {} (our version is {})",
                protocol_version, PROTOCOL_VERSION
            )));
        }

        let flags = u16::from_be_bytes(src[1..3].try_into()?);
        let public_key_buffer: [u8; 32] = src[3..35].try_into()?;
        let public_key = PublicKey::from(public_key_buffer);
        let message = Self {
            public_key,
            protocol_version,
            flags,
        };
        Ok(message)
    }
}

#[cfg(test)]
mod test {
    use aes_gcm::aead::{OsRng, rand_core::RngCore};
    use x25519_dalek::PublicKey;

    use crate::{
        buffer::BufferedPipe,
        connection::{
            SecurePipeConfig,
            config::SecurePipeMode,
            handshake::{HandshakeMessage, StreamSerializable},
        },
    };

    #[test]
    fn test_query_enc_comp() {
        let mut public_key = [0u8; 32];
        OsRng.try_fill_bytes(&mut public_key).expect("RNG failed");

        let config = SecurePipeConfig::new(SecurePipeMode::Encrypt, true);
        let message = HandshakeMessage::new(PublicKey::from(public_key), config.clone());
        assert_eq!(message.get_config(), config);
    }

    #[test]
    fn test_query_dec_comp() {
        let mut public_key = [0u8; 32];
        OsRng.try_fill_bytes(&mut public_key).expect("RNG failed");

        let config = SecurePipeConfig::new(SecurePipeMode::Decrypt, true);
        let message = HandshakeMessage::new(PublicKey::from(public_key), config.clone());
        assert_eq!(message.get_config(), config);
    }

    #[test]
    fn test_query_enc_raw() {
        let mut public_key = [0u8; 32];
        OsRng.try_fill_bytes(&mut public_key).expect("RNG failed");

        let config = SecurePipeConfig::new(SecurePipeMode::Encrypt, false);
        let message = HandshakeMessage::new(PublicKey::from(public_key), config.clone());
        assert_eq!(message.get_config(), config);
    }

    #[test]
    fn test_query_dec_raw() {
        let mut public_key = [0u8; 32];
        OsRng.try_fill_bytes(&mut public_key).expect("RNG failed");

        let config = SecurePipeConfig::new(SecurePipeMode::Decrypt, false);
        let message = HandshakeMessage::new(PublicKey::from(public_key), config.clone());
        assert_eq!(message.get_config(), config);
    }

    #[test]
    fn test_readback() {
        let mut public_key = [0u8; 32];
        OsRng.try_fill_bytes(&mut public_key).expect("RNG failed");

        let config = SecurePipeConfig::new(SecurePipeMode::Encrypt, true);
        let message = HandshakeMessage::new(PublicKey::from(public_key), config);

        let mut buffer = BufferedPipe::new(256);

        message.write_to(&mut buffer).expect("Write failed");
        let read = HandshakeMessage::read_from(&mut buffer).expect("Readback failed");

        assert_eq!(message, read);
    }
}
