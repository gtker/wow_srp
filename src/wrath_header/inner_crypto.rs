use crate::SESSION_KEY_LENGTH;
use rc4::consts::U20;
use rc4::{Rc4, StreamCipher};

use hmac::{Hmac, Mac};
use sha1::Sha1;

pub struct InnerCrypto {
    inner: Rc4<U20>,
}

pub const KEY_LENGTH: u8 = 16;

impl InnerCrypto {
    pub fn apply(&mut self, data: &mut [u8]) {
        self.inner.apply_keystream(data);
    }

    pub(crate) fn new(
        session_key: [u8; SESSION_KEY_LENGTH as usize],
        key: &[u8; KEY_LENGTH as usize],
    ) -> Self {
        let mut hmac: Hmac<Sha1> = Hmac::<Sha1>::new_from_slice(key.as_slice()).unwrap();
        hmac.update(&session_key);
        let hmac = hmac.finalize();

        let mut inner = {
            use rc4::KeyInit;
            Rc4::new_from_slice(&hmac.into_bytes()).unwrap()
        };

        // This variant is actually RC4-drop1024
        let mut pad_data = [0_u8; 1024];

        inner.apply_keystream(&mut pad_data);

        Self { inner }
    }
}
