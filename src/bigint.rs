use num_bigint::{BigInt, Sign};
use std::ops;

pub(crate) struct Integer {
    value: BigInt,
}

impl Integer {
    #[inline(always)]
    fn from_bigint(bigint: BigInt) -> Self {
        Self { value: bigint }
    }

    #[inline(always)]
    pub fn to_padded_32_byte_array_le(&self) -> [u8; 32] {
        let value = self.value.to_bytes_le().1;

        let value = {
            let mut c = [0u8; 32];
            c[0..value.len()].clone_from_slice(&value);
            c
        };

        value
    }

    #[inline(always)]
    pub fn to_bytes_le(&self) -> Vec<u8> {
        self.value.to_bytes_le().1
    }

    #[inline(always)]
    pub fn modpow(&self, exponent: &Self, modulus: &Self) -> Self {
        Self::from_bigint(self.value.modpow(&exponent.value, &modulus.value))
    }

    #[inline(always)]
    pub fn from_bytes_le(v: &[u8]) -> Self {
        Self::from_bigint(BigInt::from_bytes_le(Sign::Plus, v))
    }
}

impl From<u8> for Integer {
    fn from(v: u8) -> Self {
        Self::from_bigint(BigInt::from(v))
    }
}

impl ops::Mul<Integer> for Integer {
    type Output = Self;

    fn mul(self, rhs: Integer) -> Self::Output {
        Self::from_bigint(self.value * rhs.value)
    }
}

impl ops::Add<Integer> for Integer {
    type Output = Self;

    fn add(self, rhs: Integer) -> Self::Output {
        Self::from_bigint(self.value + rhs.value)
    }
}

impl ops::Sub<Integer> for Integer {
    type Output = Self;

    fn sub(self, rhs: Integer) -> Self::Output {
        Self::from_bigint(self.value - rhs.value)
    }
}

impl ops::Rem<Integer> for Integer {
    type Output = Self;

    fn rem(self, rhs: Integer) -> Self::Output {
        Self::from_bigint(self.value % rhs.value)
    }
}
