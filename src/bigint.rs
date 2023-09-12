use crate::primes::LargeSafePrime;
use core::ops;
#[cfg(all(feature = "srp-default-math", not(feature = "srp-fast-math")))]
use num_bigint::BigInt;
#[cfg(feature = "srp-fast-math")]
use rug::integer::Order;
#[cfg(feature = "srp-fast-math")]
use rug::Integer as BigInt;

pub(crate) struct Integer {
    value: BigInt,
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

    pub fn to_bytes_le(&self) -> Vec<u8> {
        #[cfg(feature = "srp-fast-math")]
        {
            self.value.to_digits(Order::LsfLe)
        }
        #[cfg(all(feature = "srp-default-math", not(feature = "srp-fast-math")))]
        {
            self.value.to_bytes_le().1
        }
    }

    pub fn modpow(&self, exponent: &Self, modulus: &Self) -> Self {
        #[cfg(feature = "srp-fast-math")]
        {
            Self::from_bigint(
                self.value
                    .clone()
                    .secure_pow_mod(&exponent.value, &modulus.value),
            )
        }
        #[cfg(all(feature = "srp-default-math", not(feature = "srp-fast-math")))]
        {
            Self::from_bigint(self.value.modpow(&exponent.value, &modulus.value))
        }
    }

    pub fn from_bytes_le(v: &[u8]) -> Self {
        #[cfg(all(feature = "srp-default-math", not(feature = "srp-fast-math")))]
        {
            Self::from_bigint(BigInt::from_bytes_le(num_bigint::Sign::Plus, v))
        }
        #[cfg(feature = "srp-fast-math")]
        {
            Self::from_bigint(BigInt::from_digits(v, Order::LsfLe))
        }
    }

    const fn from_bigint(bigint: BigInt) -> Self {
        Self { value: bigint }
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
