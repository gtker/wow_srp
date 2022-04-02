use crate::primes::LargeSafePrime;
#[cfg(all(feature = "srp-default-math", not(feature = "srp-fast-math")))]
use num_bigint::{BigInt, Sign};
#[cfg(feature = "srp-fast-math")]
use rug::integer::Order;
#[cfg(feature = "srp-fast-math")]
use rug::Integer as RugInt;
use std::ops;

#[cfg(not(any(feature = "srp-fast-math", feature = "srp-default-math")))]
compile_error!("Either the 'srp-fast-math' feature or the 'srp-default-math' feature must be enabled.\n\n The features exclusively select an arbitrary integer library.\n Use 'srp-default-math' if you want no-dependency compilation, but slow execution speed. Use 'srp-fast-math' if you want exceptional execution speed but external dependencies.");

pub(crate) struct Integer {
    #[cfg(all(feature = "srp-default-math", not(feature = "srp-fast-math")))]
    value: BigInt,
    #[cfg(feature = "srp-fast-math")]
    value: RugInt,
}

impl Integer {
    pub fn to_padded_32_byte_array_le(&self) -> [u8; 32] {
        let value = self.to_bytes_le();

        let mut array = [0_u8; 32];
        array[0..value.len()].clone_from_slice(&value);

        array
    }

    pub fn is_zero(&self) -> bool {
        self.value == Integer::from(0).value
    }

    pub fn mod_large_safe_prime_is_zero(&self, large_safe_prime: &LargeSafePrime) -> bool {
        (&self.value % large_safe_prime.to_bigint().value) == Integer::from(0).value
    }

    #[cfg(feature = "srp-fast-math")]
    pub fn to_bytes_le(&self) -> Vec<u8> {
        self.value.to_digits(Order::LsfLe)
    }
    #[cfg(all(feature = "srp-default-math", not(feature = "srp-fast-math")))]
    pub fn to_bytes_le(&self) -> Vec<u8> {
        self.value.to_bytes_le().1
    }

    #[cfg(feature = "srp-fast-math")]
    pub fn modpow(&self, exponent: &Self, modulus: &Self) -> Self {
        Self::from_bigint(
            self.value
                .clone()
                .secure_pow_mod(&exponent.value, &modulus.value),
        )
    }
    #[cfg(all(feature = "srp-default-math", not(feature = "srp-fast-math")))]
    pub fn modpow(&self, exponent: &Self, modulus: &Self) -> Self {
        Self::from_bigint(self.value.modpow(&exponent.value, &modulus.value))
    }

    #[cfg(feature = "srp-fast-math")]
    pub fn from_bytes_le(v: &[u8]) -> Self {
        Self::from_bigint(RugInt::from_digits(&v, Order::LsfLe))
    }
    #[cfg(all(feature = "srp-default-math", not(feature = "srp-fast-math")))]
    pub fn from_bytes_le(v: &[u8]) -> Self {
        Self::from_bigint(BigInt::from_bytes_le(Sign::Plus, v))
    }

    #[cfg(feature = "srp-fast-math")]
    const fn from_bigint(bigint: RugInt) -> Self {
        Self { value: bigint }
    }
    #[cfg(all(feature = "srp-default-math", not(feature = "srp-fast-math")))]
    const fn from_bigint(bigint: BigInt) -> Self {
        Self { value: bigint }
    }
}

impl From<u8> for Integer {
    #[cfg(feature = "srp-fast-math")]
    fn from(v: u8) -> Self {
        Self::from_bigint(RugInt::from(v))
    }

    #[cfg(all(not(feature = "srp-fast-math"), feature = "srp-default-math"))]
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
