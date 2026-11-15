//! Packet encryption (RFC 4253 section 6, RFC 4344, chacha20-poly1305@openssh.com).
//!
//! Supported: chacha20-poly1305@openssh.com, and aes256-ctr / aes128-ctr with
//! hmac-sha2-256 or hmac-sha2-512 (MAC over the plain packet).

use super::wire::protocol;
use crate::net::Reader;
use crate::Error;
use aes::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;

/// More than any packet this client asks for (SFTP data is requested in 32 KiB pieces).
pub const MAX_PACKET: usize = 256 * 1024;

pub const CIPHERS: [&str; 3] = ["chacha20-poly1305@openssh.com", "aes256-ctr", "aes128-ctr"];
pub const MACS: [&str; 2] = ["hmac-sha2-256", "hmac-sha2-512"];

pub fn key_length(cipher: &str) -> usize {
    match cipher {
        "chacha20-poly1305@openssh.com" => 64,
        "aes256-ctr" => 32,
        _ => 16,
    }
}
pub fn iv_length(cipher: &str) -> usize {
    if cipher == "chacha20-poly1305@openssh.com" { 0 } else { 16 }
}
pub fn mac_key_length(cipher: &str, mac: &str) -> usize {
    match (cipher, mac) {
        ("chacha20-poly1305@openssh.com", _) => 0,
        (_, "hmac-sha2-512") => 64,
        _ => 32,
    }
}

type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;
type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

enum Stream {
    Aes256(Aes256Ctr),
    Aes128(Aes128Ctr),
}

impl Stream {
    fn apply(&mut self, data: &mut [u8]) {
        match self {
            Stream::Aes256(cipher) => cipher.apply_keystream(data),
            Stream::Aes128(cipher) => cipher.apply_keystream(data),
        }
    }
}

enum MacKey {
    Sha256(Vec<u8>),
    Sha512(Vec<u8>),
}

impl MacKey {
    fn compute(&self, sequence: u32, packet: &[u8]) -> Vec<u8> {
        match self {
            MacKey::Sha256(key) => {
                let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("any key length works");
                mac.update(&sequence.to_be_bytes());
                mac.update(packet);
                mac.finalize().into_bytes().to_vec()
            }
            MacKey::Sha512(key) => {
                let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("any key length works");
                mac.update(&sequence.to_be_bytes());
                mac.update(packet);
                mac.finalize().into_bytes().to_vec()
            }
        }
    }
    fn length(&self) -> usize {
        match self {
            MacKey::Sha256(_) => 32,
            MacKey::Sha512(_) => 64,
        }
    }
}

/// One direction of the connection.
pub enum Cipher {
    Plain,
    ChaCha { main: [u8; 32], header: [u8; 32] },
    Ctr { stream: Stream2, mac: MacKey2 },
}

// Private types behind public aliases so `Cipher` can be named outside this module.
pub struct Stream2(Stream);
pub struct MacKey2(MacKey);

impl Cipher {
    pub fn new(cipher: &str, mac: &str, key: &[u8], iv: &[u8], mac_key: &[u8]) -> Result<Cipher, Error> {
        match cipher {
            "chacha20-poly1305@openssh.com" => Ok(Cipher::ChaCha {
                main: key[..32].try_into().unwrap(),
                header: key[32..64].try_into().unwrap(),
            }),
            "aes256-ctr" | "aes128-ctr" => {
                let stream = if cipher == "aes256-ctr" {
                    Stream::Aes256(Aes256Ctr::new_from_slices(key, iv).map_err(|_| protocol("bad key length"))?)
                } else {
                    Stream::Aes128(Aes128Ctr::new_from_slices(key, iv).map_err(|_| protocol("bad key length"))?)
                };
                let mac = match mac {
                    "hmac-sha2-256" => MacKey::Sha256(mac_key.to_vec()),
                    "hmac-sha2-512" => MacKey::Sha512(mac_key.to_vec()),
                    _ => return Err(protocol("no common integrity algorithm")),
                };
                Ok(Cipher::Ctr { stream: Stream2(stream), mac: MacKey2(mac) })
            }
            _ => Err(protocol("no common encryption algorithm")),
        }
    }

    fn block_size(&self) -> usize {
        match self {
            Cipher::Plain | Cipher::ChaCha { .. } => 8,
            Cipher::Ctr { .. } => 16,
        }
    }

    /// The bytes to send for `payload`. `padding` supplies random bytes.
    pub fn seal(&mut self, sequence: u32, payload: &[u8], padding: &mut dyn FnMut(&mut [u8])) -> Vec<u8> {
        let block = self.block_size();
        // With chacha20-poly1305 the length field is not part of the padded part.
        let counted = if matches!(self, Cipher::ChaCha { .. }) { 1 + payload.len() } else { 5 + payload.len() };
        let mut pad = block - counted % block;
        if pad < 4 {
            pad += block;
        }
        let mut packet = Vec::with_capacity(5 + payload.len() + pad + 64);
        packet.extend_from_slice(&((1 + payload.len() + pad) as u32).to_be_bytes());
        packet.push(pad as u8);
        packet.extend_from_slice(payload);
        let start = packet.len();
        packet.resize(start + pad, 0);
        padding(&mut packet[start..]);
        match self {
            Cipher::Plain => {}
            Cipher::ChaCha { main, header } => {
                let nonce = u64::from(sequence).to_be_bytes();
                let mut length_cipher = chacha20::ChaCha20Legacy::new(header.as_ref().into(), nonce.as_ref().into());
                length_cipher.apply_keystream(&mut packet[..4]);
                let mut cipher = chacha20::ChaCha20Legacy::new(main.as_ref().into(), nonce.as_ref().into());
                let mut poly_key = [0u8; 32];
                cipher.apply_keystream(&mut poly_key);
                cipher.seek(64u64);
                cipher.apply_keystream(&mut packet[4..]);
                let tag = poly_tag(&poly_key, &packet);
                packet.extend_from_slice(&tag);
            }
            Cipher::Ctr { stream, mac } => {
                let tag = mac.0.compute(sequence, &packet);
                stream.0.apply(&mut packet);
                packet.extend_from_slice(&tag);
            }
        }
        packet
    }

    /// Reads one packet and returns its payload.
    pub fn open(&mut self, sequence: u32, reader: &mut Reader) -> Result<Vec<u8>, Error> {
        let check_length = |length: usize, block: usize, counted: usize| {
            if length < 5 || length > MAX_PACKET || counted % block != 0 {
                return Err(protocol("the server sent a packet with an impossible length"));
            }
            Ok(())
        };
        let mut packet = match self {
            Cipher::Plain => {
                let head = reader.read_exact(4)?;
                let length = u32::from_be_bytes(head[..4].try_into().unwrap()) as usize;
                check_length(length, 8, length + 4)?;
                reader.read_exact(length)?
            }
            Cipher::ChaCha { main, header } => {
                let nonce = u64::from(sequence).to_be_bytes();
                let encrypted_length = reader.read_exact(4)?;
                let mut length_bytes: [u8; 4] = encrypted_length[..4].try_into().unwrap();
                let mut length_cipher = chacha20::ChaCha20Legacy::new(header.as_ref().into(), nonce.as_ref().into());
                length_cipher.apply_keystream(&mut length_bytes);
                let length = u32::from_be_bytes(length_bytes) as usize;
                check_length(length, 8, length)?;
                let mut body = reader.read_exact(length + 16)?;
                let tag = body.split_off(length);
                let mut cipher = chacha20::ChaCha20Legacy::new(main.as_ref().into(), nonce.as_ref().into());
                let mut poly_key = [0u8; 32];
                cipher.apply_keystream(&mut poly_key);
                let mut authenticated = encrypted_length;
                authenticated.extend_from_slice(&body);
                let expected = poly_tag(&poly_key, &authenticated);
                if !bool::from(expected.ct_eq(&tag)) {
                    return Err(protocol("a packet from the server failed the integrity check"));
                }
                cipher.seek(64u64);
                cipher.apply_keystream(&mut body);
                body
            }
            Cipher::Ctr { stream, mac } => {
                let mut first = reader.read_exact(16)?;
                stream.0.apply(&mut first);
                let length = u32::from_be_bytes(first[..4].try_into().unwrap()) as usize;
                check_length(length, 16, length + 4)?;
                let mut rest = reader.read_exact(length + 4 - 16)?;
                stream.0.apply(&mut rest);
                let tag = reader.read_exact(mac.0.length())?;
                let mut plain = first;
                plain.extend_from_slice(&rest);
                let expected = mac.0.compute(sequence, &plain);
                if !bool::from(expected.ct_eq(&tag)) {
                    return Err(protocol("a packet from the server failed the integrity check"));
                }
                plain.split_off(4)
            }
        };
        let pad = usize::from(packet[0]);
        if pad < 4 || pad + 1 > packet.len() {
            return Err(protocol("the server sent a packet with impossible padding"));
        }
        packet.truncate(packet.len() - pad);
        packet.remove(0);
        Ok(packet)
    }
}

fn poly_tag(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    use poly1305::universal_hash::KeyInit;
    poly1305::Poly1305::new(key.into()).compute_unpadded(data).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::Connection;

    struct Bytes(Vec<u8>);
    impl Connection for Bytes {
        fn read(&mut self, max: usize) -> Result<Vec<u8>, Error> {
            let count = max.min(self.0.len());
            Ok(self.0.drain(..count).collect())
        }
        fn write_all(&mut self, _: &[u8]) -> Result<(), Error> {
            Ok(())
        }
        fn start_tls(&mut self) -> Result<(), Error> {
            Ok(())
        }
    }

    fn pair(cipher: &str, mac: &str) -> (Cipher, Cipher) {
        let key = vec![0x11u8; key_length(cipher)];
        let iv = vec![0x22u8; iv_length(cipher)];
        let mac_key = vec![0x33u8; mac_key_length(cipher, mac)];
        (Cipher::new(cipher, mac, &key, &iv, &mac_key).unwrap(), Cipher::new(cipher, mac, &key, &iv, &mac_key).unwrap())
    }

    #[test]
    fn packets_survive_and_tampering_is_noticed() {
        let combinations = [
            ("chacha20-poly1305@openssh.com", ""),
            ("aes256-ctr", "hmac-sha2-256"),
            ("aes128-ctr", "hmac-sha2-512"),
        ];
        for (cipher, mac) in combinations {
            let (mut sender, mut receiver) = pair(cipher, mac);
            let mut wire = Vec::new();
            let payloads: Vec<Vec<u8>> = [1usize, 2, 7, 8, 15, 16, 17, 100, 40_000].iter().map(|n| vec![0xAB; *n]).collect();
            for (sequence, payload) in payloads.iter().enumerate() {
                let sealed = sender.seal(sequence as u32, payload, &mut |padding| padding.fill(0x5A));
                assert!(!sealed.windows(payload.len().max(4)).any(|w| w == &payload[..]) || payload.len() < 4, "{cipher}: plain text on the wire");
                wire.extend_from_slice(&sealed);
            }
            let mut reader = Reader::new(Box::new(Bytes(wire.clone())));
            for (sequence, payload) in payloads.iter().enumerate() {
                assert_eq!(&receiver.open(sequence as u32, &mut reader).unwrap(), payload, "{cipher}");
            }

            // One flipped bit anywhere in a packet, or a wrong sequence number, is refused.
            let packet = pair(cipher, mac).0.seal(0, b"sensitive", &mut |padding| padding.fill(0));
            for position in 0..packet.len() {
                let mut damaged = packet.clone();
                damaged[position] ^= 0x01;
                let mut reader = Reader::new(Box::new(Bytes(damaged)));
                assert!(pair(cipher, mac).1.open(0, &mut reader).is_err(), "{cipher}: byte {position}");
            }
            let mut reader = Reader::new(Box::new(Bytes(packet)));
            assert!(pair(cipher, mac).1.open(1, &mut reader).is_err(), "{cipher}: replayed under another number");
        }
    }

    #[test]
    fn plain_packets_have_valid_framing() {
        let mut plain = Cipher::Plain;
        let sealed = plain.seal(0, b"hello", &mut |padding| padding.fill(0));
        assert_eq!(sealed.len() % 8, 0);
        assert!(sealed[4] >= 4);
        let mut reader = Reader::new(Box::new(Bytes(sealed)));
        assert_eq!(Cipher::Plain.open(0, &mut reader).unwrap(), b"hello");
        // An absurd length is refused before anything is allocated for it.
        let mut reader = Reader::new(Box::new(Bytes(vec![0xFF, 0xFF, 0xFF, 0xF8, 0, 0, 0, 0])));
        assert!(Cipher::Plain.open(0, &mut reader).is_err());
    }
}
