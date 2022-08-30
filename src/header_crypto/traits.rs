/// Size in bytes of the client [world packet] header.
///
/// Always 6 bytes because the size is 2 bytes and the opcode is 4 bytes.
///
/// [world packet]: https://wowdev.wiki/World_Packet
pub const CLIENT_HEADER_LENGTH: u8 =
    (std::mem::size_of::<u16>() + std::mem::size_of::<u32>()) as u8;

/// Size in bytes of the server [world packet] header.
///
/// Always 4 bytes because the size is 2 bytes and the opcode is 2 bytes.
///
/// [world packet]: https://wowdev.wiki/World_Packet
pub const SERVER_HEADER_LENGTH: u8 =
    (std::mem::size_of::<u16>() + std::mem::size_of::<u16>()) as u8;
