//! Hashes by RustCrypto, as fixed-size arrays: SHA-256 and SHA3-256 for
//! templates' Sha2Hash, Hash and sha256sum, HMAC-SHA256 for AWS's
//! signatures, SHA-1 for the AWS SDK's SSO cache file names.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Digest;

pub fn sha1(data: &[u8]) -> [u8; 20] {
    sha1::Sha1::digest(data).into()
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(data).into()
}

pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    sha3::Sha3_256::digest(data).into()
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key)
        .expect("HMAC takes a key of any length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests_known_values() {
        let found = [
            hex(&sha1(b"abc")),
            hex(&sha256(b"abc")),
            hex(&sha3_256(b"abc")),
            // RFC 4231, test case 2.
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
        ];
        assert_eq!(
            found,
            [
                "a9993e364706816aba3e25717850c26c9cd0d89d",
                concat!(
                    "ba7816bf8f01cfea414140de5dae2223",
                    "b00361a396177a9cb410ff61f20015ad"
                ),
                concat!(
                    "3a985da74fe225b2045c172d6bd390bd",
                    "855f086e3e9d525b46bfe24511431532"
                ),
                concat!(
                    "5bdcc146bf60754e6a042426089575c7",
                    "5a003f089d2739839dec58b964ec3843"
                ),
            ]
        );
    }
}
