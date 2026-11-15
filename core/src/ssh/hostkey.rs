//! Server host keys: checking the signature over the exchange hash, and the fingerprint
//! the user sees (same form as OpenSSH: "SHA256:" + base64 without padding).

use super::wire::{protocol, Parser};
use crate::Error;
use sha2::{Digest, Sha256, Sha512};

pub const ALGORITHMS: [&str; 4] = ["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256"];

pub fn fingerprint(key_blob: &[u8]) -> String {
    format!("SHA256:{}", base64_no_padding(&Sha256::digest(key_blob)))
}

fn base64_no_padding(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16) | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8) | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..=chunk.len() {
            out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

fn left_pad(bytes: &[u8], length: usize) -> Option<Vec<u8>> {
    if bytes.len() > length {
        return None;
    }
    let mut out = vec![0u8; length - bytes.len()];
    out.extend_from_slice(bytes);
    Some(out)
}

/// Checks that `signature` (as sent in the key exchange reply) is the signature of
/// `message` by the key in `key_blob`, using the negotiated `algorithm`.
pub fn verify(algorithm: &str, key_blob: &[u8], signature: &[u8], message: &[u8]) -> Result<(), Error> {
    let bad = || protocol("the server could not prove that it owns its host key");
    let mut key = Parser::new(key_blob);
    let key_type = key.text()?;
    let mut sig = Parser::new(signature);
    let sig_type = sig.text()?;
    let sig_blob = sig.string()?;
    if sig_type != algorithm {
        return Err(bad());
    }
    match algorithm {
        "ssh-ed25519" => {
            use ed25519_dalek::Verifier;
            if key_type != "ssh-ed25519" {
                return Err(bad());
            }
            let public: [u8; 32] = key.string()?.try_into().map_err(|_| bad())?;
            let public = ed25519_dalek::VerifyingKey::from_bytes(&public).map_err(|_| bad())?;
            let signature = ed25519_dalek::Signature::from_slice(sig_blob).map_err(|_| bad())?;
            public.verify(message, &signature).map_err(|_| bad())
        }
        "ecdsa-sha2-nistp256" => {
            use p256::ecdsa::signature::Verifier;
            if key_type != "ecdsa-sha2-nistp256" || key.text()? != "nistp256" {
                return Err(bad());
            }
            let public = p256::ecdsa::VerifyingKey::from_sec1_bytes(key.string()?).map_err(|_| bad())?;
            let mut parts = Parser::new(sig_blob);
            let r = left_pad(parts.mpint()?, 32).ok_or_else(bad)?;
            let s = left_pad(parts.mpint()?, 32).ok_or_else(bad)?;
            let r: [u8; 32] = r.try_into().unwrap();
            let s: [u8; 32] = s.try_into().unwrap();
            let signature = p256::ecdsa::Signature::from_scalars(r, s).map_err(|_| bad())?;
            public.verify(message, &signature).map_err(|_| bad())
        }
        "rsa-sha2-256" | "rsa-sha2-512" => {
            use rsa::signature::Verifier;
            if key_type != "ssh-rsa" {
                return Err(bad());
            }
            let e = rsa::BigUint::from_bytes_be(key.mpint()?);
            let n_bytes = key.mpint()?;
            // Keys below 2048 bits are not accepted.
            if n_bytes.len() < 256 || n_bytes.len() > 1024 {
                return Err(protocol("the server's RSA host key has an unacceptable size"));
            }
            let public = rsa::RsaPublicKey::new(rsa::BigUint::from_bytes_be(n_bytes), e).map_err(|_| bad())?;
            let padded = left_pad(sig_blob, n_bytes.len()).ok_or_else(bad)?;
            let signature = rsa::pkcs1v15::Signature::try_from(padded.as_slice()).map_err(|_| bad())?;
            if algorithm == "rsa-sha2-256" {
                rsa::pkcs1v15::VerifyingKey::<Sha256>::new(public).verify(message, &signature).map_err(|_| bad())
            } else {
                rsa::pkcs1v15::VerifyingKey::<Sha512>::new(public).verify(message, &signature).map_err(|_| bad())
            }
        }
        _ => Err(protocol("no common host key algorithm")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::wire::Writer;

    fn ed25519() -> (Vec<u8>, impl Fn(&[u8]) -> Vec<u8>) {
        use ed25519_dalek::Signer;
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let blob = Writer::new().string(b"ssh-ed25519").string(key.verifying_key().as_bytes()).0;
        let sign = move |message: &[u8]| {
            Writer::new().string(b"ssh-ed25519").string(&key.sign(message).to_bytes()).0
        };
        (blob, sign)
    }

    fn ecdsa() -> (Vec<u8>, impl Fn(&[u8]) -> Vec<u8>) {
        use p256::ecdsa::signature::Signer;
        let key = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
        let point = key.verifying_key().to_encoded_point(false);
        let blob = Writer::new().string(b"ecdsa-sha2-nistp256").string(b"nistp256").string(point.as_bytes()).0;
        let sign = move |message: &[u8]| {
            let signature: p256::ecdsa::Signature = key.sign(message);
            let (r, s) = signature.split_bytes();
            let inner = Writer::new().mpint(&r).mpint(&s).0;
            Writer::new().string(b"ecdsa-sha2-nistp256").string(&inner).0
        };
        (blob, sign)
    }

    #[test]
    fn only_the_owner_of_the_key_passes() {
        let message = b"exchange hash";
        let (ed_key, ed_sign) = ed25519();
        let (ec_key, ec_sign) = ecdsa();
        assert!(verify("ssh-ed25519", &ed_key, &ed_sign(message), message).is_ok());
        assert!(verify("ecdsa-sha2-nistp256", &ec_key, &ec_sign(message), message).is_ok());

        // A signature over something else, a damaged signature, another key's signature.
        assert!(verify("ssh-ed25519", &ed_key, &ed_sign(b"other"), message).is_err());
        assert!(verify("ecdsa-sha2-nistp256", &ec_key, &ec_sign(b"other"), message).is_err());
        let mut damaged = ed_sign(message);
        *damaged.last_mut().unwrap() ^= 1;
        assert!(verify("ssh-ed25519", &ed_key, &damaged, message).is_err());
        let mut damaged = ec_sign(message);
        *damaged.last_mut().unwrap() ^= 1;
        assert!(verify("ecdsa-sha2-nistp256", &ec_key, &damaged, message).is_err());
        // The signature must be of the negotiated kind and match the key's kind.
        assert!(verify("ecdsa-sha2-nistp256", &ed_key, &ed_sign(message), message).is_err());
        assert!(verify("ssh-ed25519", &ec_key, &ec_sign(message), message).is_err());
        assert!(verify("ssh-ed25519", &ed_key, &ec_sign(message), message).is_err());
        assert!(verify("rsa-sha2-256", &ed_key, &ed_sign(message), message).is_err());
        assert!(verify("ssh-dss", &ed_key, &ed_sign(message), message).is_err());
        // Garbage instead of key or signature.
        assert!(verify("ssh-ed25519", b"", &ed_sign(message), message).is_err());
        assert!(verify("ssh-ed25519", &ed_key, b"", message).is_err());
        assert!(verify("ssh-ed25519", &ed_key, &Writer::new().string(b"ssh-ed25519").string(&[0u8; 64]).0, message).is_err());
    }

    #[test]
    fn fingerprint_looks_like_openssh() {
        let (key, _) = ed25519();
        let fingerprint = fingerprint(&key);
        assert!(fingerprint.starts_with("SHA256:"));
        assert_eq!(fingerprint.len(), 7 + 43); // 32 bytes in base64 without padding
        assert_eq!(base64_no_padding(b"f"), "Zg");
        assert_eq!(base64_no_padding(b"fo"), "Zm8");
        assert_eq!(base64_no_padding(b"foobar"), "Zm9vYmFy");
    }
}
