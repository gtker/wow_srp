// Bespoke Rc4 implementation since it's not very complex and the available library places limitations
// in the form of pointer indirection and available derives.

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(super) struct Rc4 {
    state: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    pub(super) fn new(key: &[u8]) -> Self {
        let mut state = Self {
            state: [0; 256],
            i: 0,
            j: 0,
        };

        state.key_scheduling_algorithm(key);

        state
    }

    // Decode one without advancing keystream
    pub(super) fn peek_keystream(&self, s: u8) -> u8 {
        s ^ self.peek_pseudo_random_generation()
    }

    pub(super) fn apply_keystream(&mut self, stream: &mut [u8]) {
        for s in stream {
            let v = self.pseudo_random_generation();
            let old_s = *s;
            *s = old_s ^ v;
        }
    }

    // https://en.wikipedia.org/wiki/RC4#Key-scheduling_algorithm_(KSA)
    fn key_scheduling_algorithm(&mut self, key: &[u8]) {
        self.state.iter_mut().enumerate().for_each(|(i, x)| {
            *x = i as u8;
        });

        let i_iter = 0..256_usize;
        let key_iter = key.iter().cycle();

        let mut j = 0_u8;

        i_iter.zip(key_iter).for_each(|(i, k)| {
            j = j.wrapping_add(self.state[i]).wrapping_add(*k);

            self.state.swap(i, j.into());
        });
    }

    // https://en.wikipedia.org/wiki/RC4#Pseudo-random_generation_algorithm_(PRGA)
    fn pseudo_random_generation(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.s_i());

        self.state.swap(self.i.into(), self.j.into());

        let index: usize = self.s_i().wrapping_add(self.s_j()).into();

        self.state[index]
    }

    fn peek_pseudo_random_generation(&self) -> u8 {
        let i = self.i.wrapping_add(1);
        let j = self.j.wrapping_add(self.state[i as usize]);

        let index = self.state[i as usize].wrapping_add(self.state[j as usize]);

        // We don't actually swap the states like we're supposed to
        let index = if index == i {
            j
        } else if index == j {
            i
        } else {
            index
        } as usize;

        self.state[index]
    }

    const fn s_i(&self) -> u8 {
        self.state[self.i as usize]
    }

    const fn s_j(&self) -> u8 {
        self.state[self.j as usize]
    }
}

#[cfg(test)]
mod test {
    use crate::wrath_header::inner_crypto::rc4::Rc4;

    #[test]
    fn test_rc4() {
        // https://datatracker.ietf.org/doc/html/rfc6229
        let key = [1_u8, 2, 3, 4, 5];
        let mut data = [
            0_u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        let expected = [
            0xb2_u8, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27, 0xcc, 0xc3, 0x52, 0x4a, 0x0a, 0x11,
            0x18, 0xa8, 0x69, 0x82, 0x94, 0x4f, 0x18, 0xfc, 0x82, 0xd5, 0x89, 0xc4, 0x03, 0xa4,
            0x7a, 0x0d, 0x09, 0x19,
        ];

        let mut rc = Rc4::new(&key);
        rc.apply_keystream(&mut data);
        assert_eq!(data, expected);

        let key = [
            0x01_u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let mut data = [
            0_u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        let expected = [
            0xea_u8, 0xa6, 0xbd, 0x25, 0x88, 0x0b, 0xf9, 0x3d, 0x3f, 0x5d, 0x1e, 0x4c, 0xa2, 0x61,
            0x1d, 0x91, 0xcf, 0xa4, 0x5c, 0x9f, 0x7e, 0x71, 0x4b, 0x54, 0xbd, 0xfa, 0x80, 0x02,
            0x7c, 0xb1, 0x43, 0x80,
        ];

        let mut rc = Rc4::new(&key);
        rc.apply_keystream(&mut data);
        assert_eq!(data, expected);
    }

    #[test]
    fn test_peek() {
        let key = [1_u8, 2, 3, 4, 5];
        let mut data = [
            0_u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        let mut rc = Rc4::new(&key);

        for i in 0..data.len() {
            let s = rc.peek_keystream(data[i]);
            rc.apply_keystream(&mut data[i..i + 1]);
            assert_eq!(data[i], s);
        }
    }
}
