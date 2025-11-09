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

#[cfg(test)]
mod test {
    use std::io::{self, Read, Write};

    use rand::{TryRngCore, rngs::OsRng};

    use crate::pipe::{DecryptPipe, EncryptPipe, Pipe};

    struct BufferedPipe {
        buffer: Vec<u8>,
        size: usize,
        read_ptr: usize,
        write_ptr: usize
    }

    impl BufferedPipe {
        fn new(size: usize) -> Self {
            let mut buffer = Vec::new();
            buffer.resize(size, 0u8);
            return Self { buffer, size, read_ptr: 0, write_ptr: 0 };
        }

        fn available(&self) -> usize {
            return self.write_ptr - self.read_ptr;
        }

        fn free(&self) -> usize {
            return self.size - self.available();
        }
    }

    impl Read for BufferedPipe {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let read_len = buf.len().min(self.available());
            for i in 0..read_len {
                buf[i] = self.buffer.get(self.read_ptr % self.size).copied().expect("Invalid index");
                self.read_ptr += 1;
            }
            return Ok(read_len);
        }

        fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
            if buf.len() > self.available() {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "Buffer underflow"));
            }
            assert!(buf.len() <= self.available());
            self.read(buf)?;
            return Ok(());
        }
    }

    impl Write for BufferedPipe {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let write_len = buf.len().min(self.free());
            for i in 0..write_len {
                let slot = self.buffer.get_mut(self.write_ptr % self.size).expect("Invalid index");
                *slot = buf[i];
                self.write_ptr += 1;
            }
            return Ok(write_len);
        }

        fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
            if buf.len() > self.free() {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "Buffer overflow"));
            }
            self.write(buf)?;
            return Ok(());
        }
    
        fn flush(&mut self) -> std::io::Result<()> {
            // NOOP
            return Ok(());
        }
    }

    #[test]
    fn test_buffered_pipe_simple() {
        let mut orig = [0u8; 32];
        let mut piped = [0u8; 32];
        OsRng.try_fill_bytes(&mut orig).expect("RNG failed");

        let mut pipe = BufferedPipe::new(256);

        pipe.write_all(&orig).expect("Pipe write failed");
        pipe.read_exact(&mut piped).expect("Pipe read failed");
        assert_eq!(orig, piped);
    }

    #[test]
    fn test_buffered_pipe_looping() {
        let mut orig = [0u8; 32];
        let mut piped = [0u8; 32];
        OsRng.try_fill_bytes(&mut orig).expect("RNG failed");

        let mut pipe = BufferedPipe::new(256);

        for _ in 0..16 {
            pipe.write_all(&orig).expect("Pipe write failed");
            pipe.read_exact(&mut piped).expect("Pipe read failed");
            assert_eq!(orig, piped);
        }
    }

    #[test]
    fn test_buffered_pipe_overflow_cap() {
        let orig = [42u8; 32];

        let mut pipe = BufferedPipe::new(16);
        let written = pipe.write(&orig).expect("Pipe write failed");

        assert_eq!(written, 16);
    }

    #[test]
    fn test_buffered_pipe_overflow_err() {
        let orig = [42u8; 32];

        let mut pipe = BufferedPipe::new(16);
        let written = pipe.write_all(&orig);

        assert!(written.is_err());
    }

    #[test]
    fn test_buffered_pipe_underflow_cap() {
        let orig = [42u8; 32];
        let mut piped = [0u8; 64];

        let mut pipe = BufferedPipe::new(256);
        pipe.write_all(&orig).expect("Pipe write failed");
        let read = pipe.read(&mut piped).expect("Pipe read failed");

        assert_eq!(read, 32);
    }

    #[test]
    fn test_buffered_pipe_underflow_err() {
        let orig = [42u8; 32];
        let mut piped = [0u8; 64];

        let mut pipe = BufferedPipe::new(256);
        pipe.write_all(&orig).expect("Pipe write failed");
        let res = pipe.read_exact(&mut piped);

        assert!(res.is_err());
    }

    #[test]
    fn test_encryption_pipe_simple() {
        let mut key = [0u8; 32];
        let mut seed = [0u8; 32];

        OsRng.try_fill_bytes(&mut key).expect("RNG failed");
        OsRng.try_fill_bytes(&mut seed).expect("RNG failed");

        let mut in_pipe = BufferedPipe::new(256);
        let mut sec_pipe = BufferedPipe::new(256);
        let mut out_pipe = BufferedPipe::new(256);

        in_pipe.write_all(b"Hello world!").expect("In pipe write failed");

        // Encrypt stage
        {
            let mut enc_pipe = EncryptPipe::new(&key, &seed, &mut in_pipe, &mut sec_pipe);
            enc_pipe.pump_all().expect("Encryption failed");
        }

        // Decrypt stage
        {
            let mut dec_pipe = DecryptPipe::new(&key, &seed, &mut sec_pipe, &mut out_pipe);
            dec_pipe.pump_all().expect("Decryption failed");
        }

        let mut out = String::new();
        out_pipe.read_to_string(&mut out).expect("Output readback failed");

        assert_eq!("Hello world!", out);
    }

    #[test]
    fn test_encryption_pipe_looped() {
        let mut key = [0u8; 32];
        let mut seed = [0u8; 32];

        OsRng.try_fill_bytes(&mut key).expect("RNG failed");
        OsRng.try_fill_bytes(&mut seed).expect("RNG failed");

        let mut in_pipe = BufferedPipe::new(256);
        let mut sec_pipe = BufferedPipe::new(256);
        let mut out_pipe = BufferedPipe::new(256);

        let mut input = Vec::new();
        let mut output = Vec::new();
        for _ in 0..256 {
            let in_length = (OsRng.try_next_u32().expect("RNG failed") % 200) as usize;
            input.resize(in_length, 0);
            output.resize(in_length, 0);
            OsRng.try_fill_bytes(input.as_mut_slice()).expect("RNG failed");

            in_pipe.write_all(input.as_slice()).expect("In pipe write failed");

            // Encrypt stage
            {
                let mut enc_pipe = EncryptPipe::new(&key, &seed, &mut in_pipe, &mut sec_pipe);
                enc_pipe.pump_all().expect("Encryption failed");
            }

            // Decrypt stage
            {
                let mut dec_pipe = DecryptPipe::new(&key, &seed, &mut sec_pipe, &mut out_pipe);
                dec_pipe.pump_all().expect("Decryption failed");
            }

            let read_len = out_pipe.read(output.as_mut_slice()).expect("Output readback failed");

            assert_eq!(read_len, in_length);
            assert_eq!(input, output);
        }
    }
}