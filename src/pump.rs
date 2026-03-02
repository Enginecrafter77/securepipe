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

const DEFAULT_MESSAGE_BLOCK_SIZE: usize = 32 * 1024;

use std::io::{Read, Write};

use lz4::block::CompressionMode;

use crate::filter::{
    BlockFilter,
    compress::{LZ4DecodingFilter, LZ4EncodingFilter},
    crypt::{Aes256Key, DecryptFilter, EncryptFilter},
};

pub trait Pump {
    fn pump(&mut self) -> anyhow::Result<usize>;

    fn pump_all(&mut self) -> anyhow::Result<()> {
        loop {
            if self.pump()? == 0 {
                return Ok(());
            }
        }
    }
}

pub struct EncodingPump<'a> {
    src: &'a mut dyn Read,
    dst: &'a mut dyn Write,
    buffer: Vec<u8>,
    encryptor: EncryptFilter,
    compressor: LZ4EncodingFilter,
    pub message_block_size: usize,
    pub compression: bool,
}

pub struct DecodingPump<'a> {
    src: &'a mut dyn Read,
    dst: &'a mut dyn Write,
    buffer: Vec<u8>,
    decryptor: DecryptFilter,
    decompressor: LZ4DecodingFilter,
    pub compression: bool,
}

impl<'a> EncodingPump<'a> {
    pub fn new(key: &Aes256Key, src: &'a mut dyn Read, dst: &'a mut dyn Write) -> Self {
        Self {
            src,
            dst,
            buffer: Vec::with_capacity(DEFAULT_MESSAGE_BLOCK_SIZE),
            encryptor: EncryptFilter::new(key),
            compressor: LZ4EncodingFilter::new(CompressionMode::DEFAULT),
            message_block_size: DEFAULT_MESSAGE_BLOCK_SIZE,
            compression: false,
        }
    }
}

impl<'a> DecodingPump<'a> {
    pub fn new(key: &Aes256Key, src: &'a mut dyn Read, dst: &'a mut dyn Write) -> Self {
        Self {
            src,
            dst,
            buffer: Vec::with_capacity(DEFAULT_MESSAGE_BLOCK_SIZE),
            decryptor: DecryptFilter::new(key),
            decompressor: LZ4DecodingFilter::new(),
            compression: false,
        }
    }
}

impl<'a> Pump for EncodingPump<'a> {
    fn pump(&mut self) -> anyhow::Result<usize> {
        self.buffer.resize(self.message_block_size, 0);

        let read_bytes = self.src.read(&mut self.buffer)?;
        if read_bytes == 0 {
            self.dst.write_all(0u32.to_be_bytes().as_slice())?;
            return Ok(0);
        }
        self.buffer.resize(read_bytes, 0);

        if self.compression {
            self.compressor.transform(&mut self.buffer)?;
        }
        self.encryptor.transform(&mut self.buffer)?;

        let block_length = self.buffer.len();
        self.dst
            .write_all((block_length as u32).to_be_bytes().as_slice())?;
        self.dst.write_all(&self.buffer)?;

        Ok(block_length)
    }
}

impl<'a> Pump for DecodingPump<'a> {
    fn pump(&mut self) -> anyhow::Result<usize> {
        let mut len_buf = [0u8; 4];
        self.src.read_exact(&mut len_buf)?;
        let block_len = u32::from_be_bytes(len_buf);
        if block_len == 0 {
            return Ok(0);
        }
        self.buffer.resize(block_len as usize, 0);
        self.src.read_exact(&mut self.buffer)?;

        self.decryptor.transform(&mut self.buffer)?;
        if self.compression {
            self.decompressor.transform(&mut self.buffer)?;
        }

        self.dst.write_all(&self.buffer)?;

        Ok(self.buffer.len())
    }
}

#[cfg(test)]
mod test {
    use std::io::{Read, Write};

    use rand::{TryRngCore, rngs::OsRng};

    use crate::{
        buffer::BufferedPipe,
        pump::{DecodingPump, EncodingPump, Pump},
    };

    #[test]
    fn test_encryption_pipe_simple() {
        let mut key = [0u8; 32];
        OsRng.try_fill_bytes(&mut key).expect("RNG failed");

        let mut in_pipe = BufferedPipe::new(256);
        let mut sec_pipe = BufferedPipe::new(256);
        let mut out_pipe = BufferedPipe::new(256);

        in_pipe
            .write_all(b"Hello world!")
            .expect("In pipe write failed");

        // Encrypt stage
        {
            let mut enc_pipe = EncodingPump::new(&key, &mut in_pipe, &mut sec_pipe);
            enc_pipe.pump_all().expect("Encryption failed");
        }

        // Decrypt stage
        {
            let mut dec_pipe = DecodingPump::new(&key, &mut sec_pipe, &mut out_pipe);
            dec_pipe.pump_all().expect("Decryption failed");
        }

        let mut out = String::new();
        out_pipe
            .read_to_string(&mut out)
            .expect("Output readback failed");

        assert_eq!("Hello world!", out);
    }

    #[test]
    fn test_encryption_pipe_looped() {
        let mut key = [0u8; 32];
        OsRng.try_fill_bytes(&mut key).expect("RNG failed");

        let mut in_pipe = BufferedPipe::new(1024);
        let mut sec_pipe = BufferedPipe::new(2048);
        let mut out_pipe = BufferedPipe::new(1024);

        let mut input = Vec::new();
        let mut output = Vec::new();
        for _ in 0..256 {
            let in_length = (OsRng.try_next_u32().expect("RNG failed") % 1020) as usize + 4;
            input.resize(in_length, 0);
            output.resize(in_length, 0);
            OsRng
                .try_fill_bytes(input.as_mut_slice())
                .expect("RNG failed");

            in_pipe
                .write_all(input.as_slice())
                .expect("In pipe write failed");

            // Encrypt stage
            {
                let mut enc_pipe = EncodingPump::new(&key, &mut in_pipe, &mut sec_pipe);
                enc_pipe.pump_all().expect("Encryption failed");
            }

            // Decrypt stage
            {
                let mut dec_pipe = DecodingPump::new(&key, &mut sec_pipe, &mut out_pipe);
                dec_pipe.pump_all().expect("Decryption failed");
            }

            let read_len = out_pipe
                .read(output.as_mut_slice())
                .expect("Output readback failed");

            assert_eq!(read_len, in_length);
            assert_eq!(input, output);
        }
    }
}
