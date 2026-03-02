use aes_gcm::{Aes256Gcm, KeyInit, aead::AeadMutInPlace};
use anyhow::anyhow;

use crate::{filter::BlockFilter, nonce::Nonce};

pub type Aes256Key = [u8; 32];

pub struct EncryptFilter {
    cipher: Aes256Gcm,
    nonce: Nonce,
}

pub struct DecryptFilter {
    cipher: Aes256Gcm,
    nonce: Nonce,
}

impl EncryptFilter {
    pub fn new(key: &Aes256Key) -> Self {
        Self {
            cipher: Aes256Gcm::new(key.into()),
            nonce: Nonce::default(),
        }
    }
}

impl DecryptFilter {
    pub fn new(key: &Aes256Key) -> Self {
        Self {
            cipher: Aes256Gcm::new(key.into()),
            nonce: Nonce::default(),
        }
    }
}

impl BlockFilter for EncryptFilter {
    fn transform(&mut self, buf: &mut Vec<u8>) -> anyhow::Result<()> {
        self.cipher
            .encrypt_in_place(self.nonce.as_aes(), b"", buf)
            .map_err(|_| anyhow!("Encryption failed"))?;
        self.nonce.increment();
        Ok(())
    }
}

impl BlockFilter for DecryptFilter {
    fn transform(&mut self, buf: &mut Vec<u8>) -> anyhow::Result<()> {
        self.cipher
            .decrypt_in_place(self.nonce.as_aes(), b"", buf)
            .map_err(|_| anyhow!("Decryption failed"))?;
        self.nonce.increment();
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::io::Write;

    use rand::{TryRngCore, rngs::OsRng};

    use crate::filter::{
        BlockFilter,
        crypt::{DecryptFilter, EncryptFilter},
    };

    #[test]
    fn test_simple_transaction() {
        let mut key = [0u8; 32];
        OsRng.try_fill_bytes(&mut key).expect("RNG failed");

        let mut dec = DecryptFilter::new(&key);
        let mut enc = EncryptFilter::new(&key);

        let msg = b"Hello world";
        let mut buffer = Vec::with_capacity(256);

        buffer.write_all(msg).expect("Buffer preload failed");
        enc.transform(&mut buffer).expect("Encrypt failed");
        dec.transform(&mut buffer).expect("Decrypt failed");

        assert_eq!(msg, buffer.as_slice());
    }

    #[test]
    fn test_randomized_transactions() {
        let mut key = [0u8; 32];
        OsRng.try_fill_bytes(&mut key).expect("RNG failed");

        let mut dec = DecryptFilter::new(&key);
        let mut enc = EncryptFilter::new(&key);

        let mut msg = [0u8; 128];
        let mut buffer = Vec::with_capacity(256);

        for _ in 0..256 {
            OsRng.try_fill_bytes(&mut msg).expect("RNG failed");
            buffer.clear();
            buffer.write_all(&msg).expect("Buffer preload failed");
            enc.transform(&mut buffer).expect("Encrypt failed");
            dec.transform(&mut buffer).expect("Decrypt failed");
            assert_eq!(msg, buffer.as_slice());
        }
    }
}
