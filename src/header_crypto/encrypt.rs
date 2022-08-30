use crate::error::UnsplitCryptoError;
use crate::header_crypto::decrypt::DecrypterHalf;
use crate::header_crypto::{Encrypter, HeaderCrypto};
use crate::SESSION_KEY_LENGTH;

/// Encryption part of a [`HeaderCrypto`].
///
/// Intended to be kept with the writer half of a connection.
///
/// Use the [`Encrypter`] functions to encrypt.
#[derive(Debug)]
pub struct EncrypterHalf {
    pub(crate) session_key: [u8; SESSION_KEY_LENGTH as usize],
    pub(crate) index: u8,
    pub(crate) previous_value: u8,
}

impl Encrypter for EncrypterHalf {
    /// Use either [the client](Encrypter::write_encrypted_client_header)
    /// or [the server](Encrypter::write_encrypted_server_header)
    /// [`Write`](std::io::Write) functions, or
    /// [the client](Encrypter::encrypt_client_header)
    /// or [the server](Encrypter::encrypt_server_header) array functions.
    fn encrypt(&mut self, data: &mut [u8]) {
        encrypt(
            data,
            self.session_key,
            &mut self.index,
            &mut self.previous_value,
        );
    }
}

impl EncrypterHalf {
    /// Tests whether both halves originate from the same [`HeaderCrypto`]
    /// and can be [`EncrypterHalf::unsplit`].
    pub fn is_pair_of(&self, other: &DecrypterHalf) -> bool {
        self.session_key == other.session_key
    }

    pub(crate) const fn new(session_key: [u8; SESSION_KEY_LENGTH as usize]) -> Self {
        Self {
            session_key,
            index: 0,
            previous_value: 0
        }
    }

    /// Unsplits the two halves.
    ///
    /// # Errors
    ///
    /// This will error if the two halfs do not originate from the same
    /// [`HeaderCrypto::split`].
    /// This is a logic bug and should either lead
    /// to panic or some other highly visible event.
    /// If [`EncrypterHalf::is_pair_of`] returns [`true`] this will not
    /// error.
    pub fn unsplit(self, decrypter: DecrypterHalf) -> Result<HeaderCrypto, UnsplitCryptoError> {
        if !self.is_pair_of(&decrypter) {
            return Err(UnsplitCryptoError {});
        }

        Ok(HeaderCrypto {
            decrypt: DecrypterHalf {
                session_key: self.session_key,
                index: decrypter.index,
                previous_value: decrypter.previous_value
            },
            encrypt: EncrypterHalf {
                session_key: self.session_key,
                index: self.index,
                previous_value: self.previous_value,
            }
        })
    }
}

// Separate function to prevent duplicating logic in full and half versions.
// The half version isn't used in order to allow the full version to only have
// one session key instead of 2, saving 32 bytes.
pub(crate) fn encrypt(
    data: &mut [u8],
    session_key: [u8; SESSION_KEY_LENGTH as usize],
    index: &mut u8,
    previous_value: &mut u8,
) {
    for unencrypted in data {
        // x = (d ^ session_key[index]) + previous_value
        let encrypted = (*unencrypted ^ session_key[*index as usize]).wrapping_add(*previous_value);

        // Use the session key as a circular buffer
        *index = (*index + 1) % SESSION_KEY_LENGTH as u8;

        *unencrypted = encrypted;
        *previous_value = encrypted;
    }
}
