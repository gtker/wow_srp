pub fn hex_encode(b: &[u8]) -> String {
    hex_encode_upper(b).to_lowercase()
}

pub fn hex_encode_upper(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);

    for i in b {
        let be_nibble = numbers_to_letters(i >> 4);
        s.push(be_nibble);

        let le_nibble = numbers_to_letters(i & 0xF);
        s.push(le_nibble);
    }

    s
}

pub fn hex_decode(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);

    let mut key = Vec::with_capacity(s.len() / 2);

    for c in s.chars().collect::<Vec<char>>().chunks(2) {
        let be_nibble = letters_to_numbers(c[0]);
        let le_nibble = letters_to_numbers(c[1]);
        let value = (be_nibble << 4) | le_nibble;
        key.push(value);
    }

    key
}

fn letters_to_numbers(c: char) -> u8 {
    match c {
        '0' => 0x0,
        '1' => 0x1,
        '2' => 0x2,
        '3' => 0x3,
        '4' => 0x4,
        '5' => 0x5,
        '6' => 0x6,
        '7' => 0x7,
        '8' => 0x8,
        '9' => 0x9,
        'A' | 'a' => 0xa,
        'B' | 'b' => 0xb,
        'C' | 'c' => 0xc,
        'D' | 'd' => 0xd,
        'E' | 'e' => 0xe,
        'F' | 'f' => 0xf,
        _ => panic!("invalid hex letter"),
    }
}

fn numbers_to_letters(b: u8) -> char {
    match b {
        0x0 => '0',
        0x1 => '1',
        0x2 => '2',
        0x3 => '3',
        0x4 => '4',
        0x5 => '5',
        0x6 => '6',
        0x7 => '7',
        0x8 => '8',
        0x9 => '9',
        0xa => 'A',
        0xb => 'B',
        0xc => 'C',
        0xd => 'D',
        0xe => 'E',
        0xf => 'F',
        _ => panic!("invalid hex digit"),
    }
}
