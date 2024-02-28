//! Contains functionality related to checking the integrity of local files.
//!
//! In [CMD_AUTH_LOGON_CHALLENGE_Server](https://wowdev.wiki/CMD_AUTH_LOGON_CHALLENGE)
//! the server sends a salt used for checking the integrity of local game files.
//!
//! This, along with the full data of the platform specific files should be fed into
//!
//! * [`login_integrity_check_windows`] for Windows x86.
//! * [`login_integrity_check_mac`] for Mac x86 and PowerPC.
//! Note that different files are required for the different platforms.
//!
//! You can also concatenate all the files into one big buffer and use
//! [`login_integrity_check_generic`] for everything.
//!
//! In [CMD_AUTH_RECONNECT_PROOF_Client](https://wowdev.wiki/CMD_AUTH_RECONNECT_PROOF)
//! the client sends a 16 byte salt and a proof.
//! This should be passed into [`reconnect_integrity_check`].
//! Game files are not necessary for this check.
use crate::key::SHA1_HASH_LENGTH;
use crate::PUBLIC_KEY_LENGTH;
use hmac::digest::FixedOutput;
use hmac::{Hmac, Mac};
use rand::{thread_rng, RngCore};
use sha1::{Digest, Sha1};

/// Randomized salt value sent by the server in
/// [`CMD_AUTH_LOGON_CHALLENGE_Server`](https://wowdev.wiki/CMD_AUTH_LOGON_CHALLENGE).
///
/// This is just a convenience function for creating a random 16 byte array.
pub fn get_salt_value() -> [u8; crate::INTEGRITY_SALT_LENGTH as usize] {
    let mut key = [0_u8; crate::INTEGRITY_SALT_LENGTH as usize];
    thread_rng().fill_bytes(&mut key);
    key
}

/// Calculator for when you have appended all files into a single buffer.
pub fn login_integrity_check_generic(
    all_files: &[u8],
    checksum_salt: &[u8; crate::INTEGRITY_SALT_LENGTH as usize],
    client_public_key: &[u8; PUBLIC_KEY_LENGTH as usize],
) -> [u8; SHA1_HASH_LENGTH as usize] {
    let mut hmac: Hmac<Sha1> = Hmac::<Sha1>::new_from_slice(checksum_salt).unwrap();

    hmac.update(all_files);
    let checksum: [u8; SHA1_HASH_LENGTH as usize] = hmac.finalize_fixed().into();

    finalise(client_public_key, &checksum)
}

/// Calculator for Windows clients during logon.
///
/// This requires the Windows version of these files:
///
/// * `WoW.exe`
/// * `fmod.dll`
/// * `ijl15.dll`
/// * `dbghelp.dll`
/// * `unicows.dll`
///
pub fn login_integrity_check_windows(
    wow_exe: &[u8],
    fmod_dll: &[u8],
    ijl15_dll: &[u8],
    dbghelp_dll: &[u8],
    unicows_dll: &[u8],
    checksum_salt: &[u8; crate::INTEGRITY_SALT_LENGTH as usize],
    client_public_key: &[u8; PUBLIC_KEY_LENGTH as usize],
) -> [u8; SHA1_HASH_LENGTH as usize] {
    let checksum = checksum(
        checksum_salt,
        wow_exe,
        fmod_dll,
        ijl15_dll,
        dbghelp_dll,
        unicows_dll,
    );

    finalise(client_public_key, &checksum)
}

/// Calculator for Windows clients during logon.
///
/// This requires the Windows version of these files:
///
/// * `MacOS/World of Warcraft`
/// * `Info.plist`
/// * `Resources/Main.nib/objects.xib`
/// * `Resources/wow.icns`
/// * `PkgInfo`
///
pub fn login_integrity_check_mac(
    world_of_warcraft: &[u8],
    info_plist: &[u8],
    objects_xib: &[u8],
    wow_icns: &[u8],
    pkg_info: &[u8],
    checksum_salt: &[u8; crate::INTEGRITY_SALT_LENGTH as usize],
    client_public_key: &[u8; PUBLIC_KEY_LENGTH as usize],
) -> [u8; SHA1_HASH_LENGTH as usize] {
    let mut hmac: Hmac<Sha1> = Hmac::<Sha1>::new_from_slice(checksum_salt).unwrap();

    hmac.update(world_of_warcraft);
    hmac.update(info_plist);
    hmac.update(objects_xib);
    hmac.update(wow_icns);
    hmac.update(pkg_info);

    let checksum: [u8; SHA1_HASH_LENGTH as usize] = hmac.finalize_fixed().into();

    finalise(client_public_key, &checksum)
}

/// Calculator for all clients during reconnect.
///
/// The `proof_salt` is sent in the [CMD_AUTH_RECONNECT_PROOF_Client](https://wowdev.wiki/CMD_AUTH_RECONNECT_PROOF)
/// message.
pub fn reconnect_integrity_check(proof_salt: &[u8; 16]) -> [u8; SHA1_HASH_LENGTH as usize] {
    let zero_buffer = [0_u8; SHA1_HASH_LENGTH as usize];

    finalise(proof_salt, &zero_buffer)
}

fn checksum(
    seed: &[u8],
    wow_exe: &[u8],
    fmod_dll: &[u8],
    ijl15_dll: &[u8],
    dbghelp_dll: &[u8],
    unicows_dll: &[u8],
) -> [u8; 20] {
    let mut hmac: Hmac<Sha1> = Hmac::<Sha1>::new_from_slice(seed).unwrap();

    hmac.update(wow_exe);
    hmac.update(fmod_dll);
    hmac.update(ijl15_dll);
    hmac.update(dbghelp_dll);
    hmac.update(unicows_dll);

    hmac.finalize_fixed().into()
}

fn finalise(seed: &[u8], checksum: &[u8]) -> [u8; 20] {
    Sha1::new()
        .chain_update(seed)
        .chain_update(checksum)
        .finalize_fixed()
        .into()
}

#[cfg(test)]
mod test {
    use crate::hex::hex_decode;
    use crate::integrity::{
        finalise, login_integrity_check_generic, login_integrity_check_mac,
        login_integrity_check_windows, reconnect_integrity_check,
    };
    use std::convert::TryInto;

    #[test]
    fn real_1_12_reconnect() {
        const PROOF_DATA: [u8; 16] = [
            30, 163, 238, 241, 172, 245, 163, 15, 160, 137, 46, 32, 236, 186, 241, 218,
        ];
        const EXPECTED: [u8; 20] = [
            182, 155, 203, 154, 170, 50, 15, 36, 0, 235, 161, 113, 229, 2, 64, 21, 106, 246, 251, 2,
        ];

        assert_eq!(reconnect_integrity_check(&PROOF_DATA), EXPECTED);
    }

    #[test]
    fn ember() {
        const SALT: [u8; 32] = [
            0x88, 0xf7, 0x9e, 0xab, 0x68, 0xe7, 0x1e, 0xc9, 0xe2, 0xf4, 0xe4, 0x51, 0x66, 0x39,
            0xdc, 0x5d, 0x1d, 0x30, 0x0, 0xad, 0x15, 0xb0, 0xb4, 0xba, 0x1d, 0x58, 0xf7, 0x3b,
            0x58, 0xd1, 0xd2, 0x73,
        ];

        // HMAC-SHA1 of binary data and checksum salt
        const CHECKSUM_SALT_AND_DATA: [u8; 20] = [
            0xa5, 0x32, 0x7c, 0x48, 0xe4, 0xf7, 0x77, 0xb8, 0x4e, 0xa, 0xf0, 0x38, 0x68, 0x3f,
            0xfa, 0x33, 0x18, 0xdf, 0x12, 0xa8,
        ];

        const EXPECTED: [u8; 20] = [
            0x16, 0xea, 0x6, 0xf7, 0xd7, 0x75, 0xde, 0x25, 0xa2, 0xe, 0x7c, 0x54, 0x1d, 0xca, 0xa1,
            0xe9, 0xf7, 0x18, 0xa0, 0x34,
        ];
        assert_eq!(finalise(&SALT, &CHECKSUM_SALT_AND_DATA), EXPECTED);
    }

    #[test]
    fn reconnect_regression() {
        /*
        let contents = include_str!("../tests/integrity/reconnect_regression.txt");

        for line in contents.lines() {
            let mut split = line.split_whitespace();
            let key: [u8; 16] = hex_decode(split.next().unwrap()).try_into().unwrap();
            let expected: [u8; 20] = hex_decode(split.next().unwrap()).try_into().unwrap();

            let actual = reconnect_integrity_check(&key);

            assert_eq!(expected, actual);
        }
         */
    }

    #[test]
    fn mac_regression() {
        let contents = include_str!("../tests/integrity/mac_regression.txt");
        for line in contents.lines() {
            let mut line = line.split_whitespace();
            let world_of_warcraft = hex_decode(line.next().unwrap());
            let info_plist = hex_decode(line.next().unwrap());
            let objects_xib = hex_decode(line.next().unwrap());
            let wow_icns = hex_decode(line.next().unwrap());
            let pkg_info = hex_decode(line.next().unwrap());
            let checksum_salt = hex_decode(line.next().unwrap()).try_into().unwrap();
            let client_public_key = hex_decode(line.next().unwrap()).try_into().unwrap();
            let expected: [u8; 20] = hex_decode(line.next().unwrap()).try_into().unwrap();

            let actual = login_integrity_check_mac(
                &world_of_warcraft,
                &info_plist,
                &objects_xib,
                &wow_icns,
                &pkg_info,
                &checksum_salt,
                &client_public_key,
            );

            assert_eq!(expected, actual);
        }
    }

    #[test]
    fn windows_regression() {
        let contents = include_str!("../tests/integrity/windows_regression.txt");
        for line in contents.lines() {
            let mut line = line.split_whitespace();
            let wow_exe = hex_decode(line.next().unwrap());
            let fmod_dll = hex_decode(line.next().unwrap());
            let ijl15_dll = hex_decode(line.next().unwrap());
            let dbghelp_dll = hex_decode(line.next().unwrap());
            let unicows_dll = hex_decode(line.next().unwrap());
            let checksum_salt = hex_decode(line.next().unwrap()).try_into().unwrap();
            let client_public_key = hex_decode(line.next().unwrap()).try_into().unwrap();
            let expected: [u8; 20] = hex_decode(line.next().unwrap()).try_into().unwrap();

            let actual = login_integrity_check_windows(
                &wow_exe,
                &fmod_dll,
                &ijl15_dll,
                &dbghelp_dll,
                &unicows_dll,
                &checksum_salt,
                &client_public_key,
            );

            assert_eq!(expected, actual);
        }
    }

    #[test]
    fn generic_regression() {
        let contents = include_str!("../tests/integrity/generic_regression.txt");
        for line in contents.lines() {
            let mut line = line.split_whitespace();
            let all = hex_decode(line.next().unwrap());
            let checksum_salt = hex_decode(line.next().unwrap()).try_into().unwrap();
            let client_public_key = hex_decode(line.next().unwrap()).try_into().unwrap();
            let expected: [u8; 20] = hex_decode(line.next().unwrap()).try_into().unwrap();

            let actual = login_integrity_check_generic(&all, &checksum_salt, &client_public_key);

            assert_eq!(expected, actual);
        }
    }
}
