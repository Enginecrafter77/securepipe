use std::cmp::max;

use lz4::block::CompressionMode;

use crate::filter::BlockFilter;

pub struct LZ4EncodingFilter {
    mode: CompressionMode,
    buffer: Vec<u8>,
}

pub struct LZ4DecodingFilter {
    buffer: Vec<u8>,
}

impl LZ4EncodingFilter {
    pub fn new(mode: CompressionMode) -> Self {
        Self {
            mode,
            buffer: Vec::new(),
        }
    }
}

impl LZ4DecodingFilter {
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }
}

impl BlockFilter for LZ4EncodingFilter {
    fn transform(&mut self, buf: &mut Vec<u8>) -> anyhow::Result<()> {
        self.buffer.resize(buf.len(), 0);
        self.buffer.copy_from_slice(buf);

        let uncompressed_size = buf.len();
        buf.resize(max(buf.len() * 2, 256) + 4, 0);
        let compressed_size =
            lz4::block::compress_to_buffer(&self.buffer, Some(self.mode), false, &mut buf[4..])?;
        buf[0..4].copy_from_slice((uncompressed_size as u32).to_be_bytes().as_slice());
        buf.resize(compressed_size + 4, 0);
        Ok(())
    }
}

impl BlockFilter for LZ4DecodingFilter {
    fn transform(&mut self, buf: &mut Vec<u8>) -> anyhow::Result<()> {
        let mut uc_buf = [0u8; 4];
        uc_buf.copy_from_slice(&buf[0..4]);
        let uncompressed_size = u32::from_be_bytes(uc_buf);

        self.buffer.resize(buf.len() - 4, 0);
        self.buffer.copy_from_slice(&buf[4..]);

        buf.resize(uncompressed_size as usize, 0);
        lz4::block::decompress_to_buffer(&self.buffer, Some(uncompressed_size as i32), buf)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::io::Write;

    use lz4::block::CompressionMode;
    use rand::{TryRngCore, rngs::OsRng};

    use crate::filter::{
        BlockFilter,
        compress::{LZ4DecodingFilter, LZ4EncodingFilter},
    };

    #[test]
    fn test_simple_transaction() {
        let mut dec = LZ4DecodingFilter::new();
        let mut enc = LZ4EncodingFilter::new(CompressionMode::FAST(8));

        let msg = b"Hello world";
        let mut buffer = Vec::with_capacity(256);

        buffer.write_all(msg).expect("Buffer preload failed");
        enc.transform(&mut buffer).expect("Encode failed");
        dec.transform(&mut buffer).expect("Decode failed");

        assert_eq!(msg, buffer.as_slice());
    }

    #[test]
    fn test_randomized_transactions() {
        let mut dec = LZ4DecodingFilter::new();
        let mut enc = LZ4EncodingFilter::new(CompressionMode::FAST(8));

        let mut msg = [0u8; 128];
        let mut buffer = Vec::with_capacity(256);

        for _ in 0..256 {
            OsRng.try_fill_bytes(&mut msg).expect("RNG failed");
            buffer.clear();
            buffer.write_all(&msg).expect("Buffer preload failed");
            enc.transform(&mut buffer).expect("Encode failed");
            dec.transform(&mut buffer).expect("Decode failed");
            assert_eq!(msg, buffer.as_slice());
        }
    }

    #[test]
    fn test_encode_decode_empty_buffer() {
        let mut dec = LZ4DecodingFilter::new();
        let mut enc = LZ4EncodingFilter::new(CompressionMode::FAST(8));

        let msg = b"";
        let mut buffer = Vec::with_capacity(16);

        buffer.write_all(msg).expect("Buffer preload failed");
        enc.transform(&mut buffer).expect("Encode failed");
        dec.transform(&mut buffer).expect("Decode failed");

        assert_eq!(msg, buffer.as_slice());
    }

    #[test]
    fn test_tiny_encode_decode() {
        let mut dec = LZ4DecodingFilter::new();
        let mut enc = LZ4EncodingFilter::new(CompressionMode::FAST(8));

        let msg = b"A";
        let mut buffer = Vec::with_capacity(16);

        buffer.write_all(msg).expect("Buffer preload failed");
        enc.transform(&mut buffer).expect("Encode failed");
        dec.transform(&mut buffer).expect("Decode failed");

        assert_eq!(msg, buffer.as_slice());
    }

    #[test]
    fn test_repetetive_encode_decode() {
        let mut dec = LZ4DecodingFilter::new();
        let mut enc = LZ4EncodingFilter::new(CompressionMode::FAST(8));

        let msg = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let mut buffer = Vec::with_capacity(64);

        buffer.write_all(msg).expect("Buffer preload failed");
        enc.transform(&mut buffer).expect("Encode failed");
        dec.transform(&mut buffer).expect("Decode failed");

        assert_eq!(msg, buffer.as_slice());
    }
}
