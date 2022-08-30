use crate::header_crypto::encrypt::EncrypterHalf;
use crate::header_crypto::Decrypter;
use crate::SESSION_KEY_LENGTH;

/// Decryption part of a [`HeaderCrypto`](crate::header_crypto::HeaderCrypto).
///
/// Intended to be kept with the reader half of a connection.
///
/// Use the [`Decrypter`] functions to decrypt.
#[derive(Debug)]
pub struct DecrypterHalf {
    pub(crate) session_key: [u8; SESSION_KEY_LENGTH as usize],
    pub(crate) index: u8,
    pub(crate) previous_value: u8,
}

impl Decrypter for DecrypterHalf {
    /// Use either [the client](Decrypter::read_and_decrypt_client_header)
    /// or [the server](Decrypter::read_and_decrypt_server_header)
    /// [`Read`](std::io::Read) functions, or
    /// [the client](Decrypter::decrypt_client_header)
    /// or [the server](Decrypter::decrypt_server_header) array functions.
    fn decrypt(&mut self, data: &mut [u8]) {
        decrypt(
            data,
            &self.session_key,
            &mut self.index,
            &mut self.previous_value,
        );
    }
}

impl DecrypterHalf {
    /// Tests whether both halves originate from the same
    /// [`HeaderCrypto`](crate::header_crypto::HeaderCrypto)
    /// and can be [`EncrypterHalf::unsplit`].
    ///
    /// Same as [`EncrypterHalf::is_pair_of`], provided for convenience/readability.
    pub fn is_pair_of(&self, other: &EncrypterHalf) -> bool {
        other.is_pair_of(self)
    }

    pub(crate) const fn new(session_key: [u8; SESSION_KEY_LENGTH as usize]) -> Self {
        Self {
            session_key,
            index: 0,
            previous_value: 0
        }
    }
}

// Separate function to prevent duplicating logic in full and half versions.
// The half version isn't used in order to allow the full version to only have
// one session key instead of 2, saving 32 bytes.
pub(crate) fn decrypt(
    data: &mut [u8],
    session_key: &[u8; SESSION_KEY_LENGTH as usize],
    index: &mut u8,
    previous_value: &mut u8,
) {
    for encrypted in data {
        // unencrypted = (encrypted - previous_value) ^ session_key[index]
        let unencrypted = encrypted.wrapping_sub(*previous_value) ^ session_key[*index as usize];

        // Use session key as circular buffer
        *index = (*index + 1) % SESSION_KEY_LENGTH as u8;

        *previous_value = *encrypted;
        *encrypted = unencrypted;
    }
}
