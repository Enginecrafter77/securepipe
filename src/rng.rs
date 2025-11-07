use std::num::NonZeroU32;

use aes_gcm::aead::rand_core::{CryptoRng, RngCore, SeedableRng, Error as AesRandError};
use rand::{RngCore as RandRngCore, TryRngCore as RandTryRngCore, SeedableRng as RandSeedableRng, rngs::StdRng};

pub struct StdRngWrapper {
    wrapped: StdRng
}

impl SeedableRng for StdRngWrapper {
    type Seed = [u8; 32];

    fn from_seed(seed: Self::Seed) -> Self {
        return Self { wrapped: StdRng::from_seed(seed) };
    }
}

impl CryptoRng for StdRngWrapper {}

impl RngCore for StdRngWrapper {
    fn next_u32(&mut self) -> u32 {
        return self.wrapped.next_u32();
    }

    fn next_u64(&mut self) -> u64 {
        return self.wrapped.next_u64();
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        return self.wrapped.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), AesRandError> {
        self.wrapped.try_fill_bytes(dest).map_err(|_| {
            return AesRandError::from(NonZeroU32::new(42).unwrap());
        })?;
        return Ok(());
    }
}
