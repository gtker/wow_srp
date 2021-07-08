use crate::header_crypto::encrypt::EncrypterHalf;
use crate::header_crypto::Decrypter;
use crate::SESSION_KEY_LENGTH;

#[derive(Debug)]
pub struct DecrypterHalf {
    pub(crate) session_key: [u8; SESSION_KEY_LENGTH as usize],
    pub(crate) index: u8,
    pub(crate) previous_value: u8,
}

impl Decrypter for DecrypterHalf {
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
    pub fn is_pair_of(&self, other: &EncrypterHalf) -> bool {
        self.session_key == other.session_key
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
