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
