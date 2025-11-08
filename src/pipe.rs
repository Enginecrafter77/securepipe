const DEFAULT_BUFFER_SIZE: usize = 4096;

use std::io::{self, Read, Write};

use aes_gcm::{AeadCore, Aes256Gcm, KeyInit, aead::{AeadMutInPlace, rand_core::SeedableRng}};

use crate::{rng::StdRngWrapper};

pub trait Pipe {
    fn pump(&mut self) -> io::Result<usize>;

    fn pump_all(&mut self) -> io::Result<()> {
        loop {
            if self.pump()? == 0 {
                return Ok(());
            }
        }
    }
}

pub struct EncryptPipe<'a> {
    cipher: Aes256Gcm,
    rng: StdRngWrapper,
    buffer: Vec<u8>,
    src: &'a mut dyn Read,
    dst: &'a mut dyn Write,
    pub read_length: usize,
}

pub struct DecryptPipe<'a> {
    cipher: Aes256Gcm,
    rng: StdRngWrapper,
    buffer: Vec<u8>,
    len_buffer: [u8; 4],
    src: &'a mut dyn Read,
    dst: &'a mut dyn Write,
}

impl<'a> EncryptPipe<'a> {
    pub fn new(key: &[u8; 32], seed: &[u8; 32], src: &'a mut dyn Read, dst: &'a mut dyn Write) -> Self {
        return Self {
            cipher: Aes256Gcm::new(key.into()),
            rng: StdRngWrapper::from_seed(seed.clone()),
            buffer: Vec::new(),
            read_length: DEFAULT_BUFFER_SIZE,
            src,
            dst
        }
    }
}

impl<'a> Pipe for EncryptPipe<'a> {
    fn pump(&mut self) -> io::Result<usize> {
        let nonce = Aes256Gcm::generate_nonce(&mut self.rng);

        self.buffer.resize(self.read_length, 0);
        
        let read_bytes = self.src.read(self.buffer.as_mut())?;
        if read_bytes == 0 {
            self.dst.write_all((0 as u32).to_be_bytes().as_slice())?;
            return Ok(0);
        }
        self.buffer.resize(read_bytes, 0);
        self.cipher.encrypt_in_place(&nonce, b"", &mut self.buffer).expect("Encryption failed");

        self.dst.write_all((self.buffer.len() as u32).to_be_bytes().as_slice())?;
        self.dst.write_all(self.buffer.as_slice())?;

        return Ok(self.buffer.len());
    }
}

impl<'a> DecryptPipe<'a> {
    pub fn new(key: &[u8; 32], seed: &[u8; 32], src: &'a mut dyn Read, dst: &'a mut dyn Write) -> Self {
        return Self {
            cipher: Aes256Gcm::new(key.into()),
            rng: StdRngWrapper::from_seed(seed.clone()),
            buffer: Vec::new(),
            len_buffer: [0u8; 4],
            src,
            dst
        }
    }
}

impl<'a> Pipe for DecryptPipe<'a> {
    fn pump(&mut self) -> io::Result<usize> {
        let nonce = Aes256Gcm::generate_nonce(&mut self.rng);

        self.src.read_exact(&mut self.len_buffer)?;
        let block_length = u32::from_be_bytes(self.len_buffer) as usize;
        if block_length == 0 {
            return Ok(0);
        }

        self.buffer.resize(block_length, 0);
        self.src.read_exact(self.buffer.as_mut())?;

        self.cipher.decrypt_in_place(&nonce, b"", &mut self.buffer).expect("Decryption failed");
        self.dst.write_all(&self.buffer.as_slice())?;

        return Ok(self.buffer.len());
    }
}
