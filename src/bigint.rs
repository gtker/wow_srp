use crate::primes::LargeSafePrime;
#[cfg(all(not(feature = "rug"), feature = "num-bigint"))]
use num_bigint::{BigInt, Sign};
#[cfg(all(feature = "rug", not(feature = "num-bigint")))]
use rug::integer::Order;
#[cfg(all(feature = "rug", not(feature = "num-bigint")))]
use rug::Integer as RugInt;
use std::ops;

pub(crate) struct Integer {
    #[cfg(all(not(feature = "rug"), feature = "num-bigint"))]
    value: BigInt,
    #[cfg(all(feature = "rug", not(feature = "num-bigint")))]
    value: RugInt,
}

#[cfg(all(not(feature = "rug"), feature = "num-bigint"))]
impl Integer {
    #[inline(always)]
    const fn from_bigint(bigint: BigInt) -> Self {
        Self { value: bigint }
    }

    #[inline(always)]
    pub fn to_padded_32_byte_array_le(&self) -> [u8; 32] {
        let value = self.value.to_bytes_le().1;

        let mut array = [0_u8; 32];
        array[0..value.len()].clone_from_slice(&value);

        array
    }

    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        self.value == BigInt::from(0)
    }

    #[inline(always)]
    pub fn mod_large_safe_prime_is_zero(&self, large_safe_prime: &LargeSafePrime) -> bool {
        (&self.value % large_safe_prime.to_bigint().value) == BigInt::from(0)
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

#[cfg(all(feature = "rug", not(feature = "num-bigint")))]
impl Integer {
    #[inline(always)]
    const fn from_bigint(bigint: RugInt) -> Self {
        Self { value: bigint }
    }

    #[inline(always)]
    pub fn to_padded_32_byte_array_le(&self) -> [u8; 32] {
        let value = self.value.to_digits(Order::LsfLe);

        let mut array = [0_u8; 32];
        array[0..value.len()].clone_from_slice(&value);

        array
    }

    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        self.value == RugInt::from(0)
    }

    #[inline(always)]
    pub fn mod_large_safe_prime_is_zero(&self, large_safe_prime: &LargeSafePrime) -> bool {
        (&self.value % large_safe_prime.to_bigint().value) == RugInt::from(0)
    }

    #[inline(always)]
    pub fn to_bytes_le(&self) -> Vec<u8> {
        self.value.to_digits(Order::LsfLe)
    }

    #[inline(always)]
    pub fn modpow(&self, exponent: &Self, modulus: &Self) -> Self {
        Self::from_bigint(
            self.value
                .clone()
                .secure_pow_mod(&exponent.value, &modulus.value),
        )
    }

    #[inline(always)]
    pub fn from_bytes_le(v: &[u8]) -> Self {
        Self::from_bigint(RugInt::from_digits(&v, Order::LsfLe))
    }
}
#[cfg(all(not(feature = "rug"), feature = "num-bigint"))]
impl From<u8> for Integer {
    fn from(v: u8) -> Self {
        Self::from_bigint(BigInt::from(v))
    }
}

#[cfg(all(feature = "rug", not(feature = "num-bigint")))]
impl From<u8> for Integer {
    fn from(v: u8) -> Self {
        Self::from_bigint(RugInt::from(v))
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
