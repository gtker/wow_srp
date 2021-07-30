use crate::header_crypto::decrypt::DecrypterHalf;
use crate::header_crypto::{Encrypter, HeaderCrypto};
use crate::SESSION_KEY_LENGTH;

#[derive(Debug)]
pub struct EncrypterHalf {
    pub(crate) session_key: [u8; SESSION_KEY_LENGTH as usize],
    pub(crate) index: u8,
    pub(crate) previous_value: u8,
}

impl Encrypter for EncrypterHalf {
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
    pub fn is_pair_of(&self, other: &DecrypterHalf) -> bool {
        self.session_key == other.session_key
    }

    pub fn unsplit(self, decrypter: DecrypterHalf) -> HeaderCrypto {
        if !self.is_pair_of(&decrypter) {
            panic!("Unrelated `DecrypterHalf` passed to `EncrypterHalf::unsplit`.")
        }

        HeaderCrypto {
            session_key: self.session_key,
            encrypt_index: self.index,
            encrypt_previous_value: self.previous_value,
            decrypt_index: decrypter.index,
            decrypt_previous_value: decrypter.previous_value,
        }
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
