use crate::key::SHA1_HASH_LENGTH;
use crate::rc4::Rc4;
use crate::SESSION_KEY_LENGTH;
use core::fmt::Debug;
use hmac::{Hmac, Mac};
use sha1::Sha1;

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) struct InnerCrypto {
    inner: Rc4,
}

pub const KEY_LENGTH: u8 = 16;

impl InnerCrypto {
    pub(crate) fn apply(&mut self, data: &mut [u8]) {
        self.inner.apply_keystream(data);
    }

    pub(crate) fn new(
        session_key: [u8; SESSION_KEY_LENGTH as usize],
        key: &[u8; KEY_LENGTH as usize],
    ) -> Self {
        let mut inner = Rc4::new(&create_wrath_hmac_key(session_key, key));

        // This variant is actually RC4-drop1024
        let mut pad_data = [0_u8; 1024];

        inner.apply_keystream(&mut pad_data);

        Self { inner }
    }
}

pub(crate) fn create_wrath_hmac_key(
    session_key: [u8; SESSION_KEY_LENGTH as usize],
    key: &[u8; KEY_LENGTH as usize],
) -> [u8; SHA1_HASH_LENGTH as usize] {
    let mut hmac: Hmac<Sha1> = Hmac::<Sha1>::new_from_slice(key.as_slice()).unwrap();
    hmac.update(session_key.as_slice());

    hmac.finalize().into_bytes().into()
}

#[cfg(test)]
mod test {
    use crate::hex::hex_decode_array;
    use crate::wrath_header::inner_crypto::create_wrath_hmac_key;

    #[test]
    fn create_wrath_hmac_key_test() {
        let contents = include_str!("../../../tests/encryption/create_wrath_hmac_key.txt");

        for line in contents.lines() {
            let mut line = line.split_whitespace();

            let session_key = hex_decode_array(line.next().unwrap());
            let key = hex_decode_array(line.next().unwrap());
            let expected = hex_decode_array(line.next().unwrap());
            let actual = create_wrath_hmac_key(session_key, &key);

            assert_eq!(actual, expected);
        }
    }
}
