use std::{cmp::Ordering, ops::Add};

use aes_gcm::aead::consts::U12;

#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub struct Nonce {
    bytes: [u8; 12],
}

const NONCE_MASK: u128 = 0xFFFFFFFFFFFFFFFFFFFFFFFF;

impl Nonce {
    pub fn from_bytes(bytes: [u8; 12]) -> Self {
        Self { bytes }
    }

    pub fn as_slice(&self) -> &[u8; 12] {
        &self.bytes
    }

    pub fn as_slice_mut(&mut self) -> &mut [u8; 12] {
        &mut self.bytes
    }

    pub fn increment(&mut self) {
        let mut carry = true;
        let mut index = 11;
        while carry {
            let (new_val, new_carry) = self.bytes[index].carrying_add(0, carry);
            self.bytes[index] = new_val;
            carry = new_carry;
            index -= 1;
        }
    }

    #[allow(deprecated)] // not our fault that aes_gcm uses old GenericArray library
    pub fn as_aes(&self) -> &aes_gcm::Nonce<U12> {
        aes_gcm::Nonce::from_slice(&self.bytes)
    }
}

impl From<u128> for Nonce {
    fn from(value: u128) -> Self {
        if value > NONCE_MASK {
            panic!("Nonce value overflow");
        }

        let mut bytes = [0u8; 12];
        for (i, slot) in bytes.iter_mut().enumerate() {
            *slot = ((value >> ((11 - i) * 8)) & 0xFF) as u8;
        }
        Self { bytes }
    }
}

impl From<Nonce> for u128 {
    fn from(value: Nonce) -> Self {
        let mut result = 0u128;
        for byte in value.bytes.into_iter() {
            result <<= 8;
            result |= byte as u128;
        }
        result
    }
}

impl Ord for Nonce {
    fn cmp(&self, other: &Self) -> Ordering {
        for i in 0usize..12usize {
            let res = self.bytes[i].cmp(&other.bytes[i]);
            if res != Ordering::Equal {
                return res;
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for Nonce {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Add for Nonce {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        let mut carry = false;
        for i in 0usize..12usize {
            let old_a = &mut self.bytes[11 - i];
            let old_b = rhs.bytes[11 - i];

            let (new_val, new_carry) = (*old_a).carrying_add(old_b, carry);
            *old_a = new_val;
            carry = new_carry;
        }
        if carry {
            panic!("Nonce add overflow");
        }
        self
    }
}

#[cfg(test)]
mod test {
    use rand::{TryRngCore, rand_core::OsError, rngs::OsRng};

    use crate::nonce::Nonce;

    fn random_u96() -> Result<u128, OsError> {
        let mut bytes = [0u8; 16];
        OsRng.try_fill_bytes(&mut bytes)?;
        Ok(u128::from_ne_bytes(bytes) & 0xFFFFFFFFFFFFFFFFFFFFFFFFu128)
    }

    #[test]
    fn test_from_u128_static() {
        let num = 0x216489f54987cab987e21f57u128;
        let num_bytes: Vec<u8> = num.to_be_bytes().into_iter().skip(4).collect();

        let nonce = Nonce::from(num);
        let nonce_bytes: Vec<u8> = nonce.as_slice().to_vec();

        assert_eq!(num_bytes, nonce_bytes);
    }

    #[test]
    fn test_from_u128_random() {
        for _ in 0..256 {
            let num = random_u96().expect("Generating random u128 number failed");
            let num_bytes: Vec<u8> = num.to_be_bytes().into_iter().skip(4).collect();

            let nonce = Nonce::from(num);
            let nonce_bytes: Vec<u8> = nonce.as_slice().to_vec();

            assert_eq!(num_bytes, nonce_bytes);
        }
    }

    #[test]
    fn test_to_from_u128_static() {
        let num = 0x10u128;
        let nonce = Nonce::from(num);
        let rec = u128::from(nonce);
        assert_eq!(num, rec);
    }

    #[test]
    fn test_to_from_u128_random() {
        for _ in 0..256 {
            let num = random_u96().unwrap();
            assert_eq!(num, u128::from(Nonce::from(num)));
        }
    }

    #[test]
    fn test_compare_gt_static() {
        assert!(Nonce::from(548798413216487546u128) > Nonce::from(148798413216487546u128));
    }

    #[test]
    fn test_compare_ge_static() {
        assert!(Nonce::from(548798413216487546u128) >= Nonce::from(148798413216487546u128));
        assert!(Nonce::from(548798413216487546u128) >= Nonce::from(548798413216487546u128));
    }

    #[test]
    fn test_compare_eq_static() {
        assert!(Nonce::from(548798413216487546u128) == Nonce::from(548798413216487546u128));
    }

    #[test]
    fn test_compare_le_static() {
        assert!(Nonce::from(148798413216487546u128) <= Nonce::from(548798413216487546u128));
        assert!(Nonce::from(148798413216487546u128) <= Nonce::from(148798413216487546u128));
    }

    #[test]
    fn test_compare_lt_static() {
        assert!(Nonce::from(148798413216487546u128) < Nonce::from(548798413216487546u128));
    }

    #[test]
    fn test_compare_random() {
        for _ in 0..256 {
            let n1 = random_u96().unwrap();
            let n2 = random_u96().unwrap();
            let nc1 = Nonce::from(n1);
            let nc2 = Nonce::from(n2);

            assert_eq!(n1.cmp(&n2), nc1.cmp(&nc2));
        }
    }

    #[test]
    fn test_add_simple() {
        let n1 = Nonce::from(0x111111111111111111111111u128);
        let n2 = Nonce::from(0x222222222222222222222222u128);
        assert_eq!(u128::from(n1 + n2), 0x333333333333333333333333u128);
    }

    #[test]
    fn test_add_carry() {
        let n1 = Nonce::from(199999999999999999u128);
        let n2 = Nonce::from(100000000000000001u128);
        assert_eq!(u128::from(n1 + n2), 300000000000000000u128);
    }

    #[test]
    fn test_add_random() {
        for _ in 0..256 {
            let n1 = random_u96().unwrap() >> 1;
            let n2 = random_u96().unwrap() >> 1;
            let nc1 = Nonce::from(n1);
            let nc2 = Nonce::from(n2);
            assert_eq!(n1 + n2, u128::from(nc1 + nc2));
        }
    }

    #[test]
    fn test_sequence_add() {
        let mut last_nonce = Nonce::from(0);
        for i in 0..4096 {
            assert_eq!(i as u128, u128::from(last_nonce));
            last_nonce.increment();
        }
    }
}
