pub fn hex_encode(b: &[u8]) -> String {
    hex::encode(b)
}

pub fn hex_encode_upper(b: &[u8]) -> String {
    hex::encode_upper(b)
}

pub fn hex_decode(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}
