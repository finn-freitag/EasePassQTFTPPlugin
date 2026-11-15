//! A small SSH client (RFC 4251-4254): just enough to log in with a password and run the
//! SFTP subsystem over one channel.
//!
//! Key exchange: curve25519-sha256, diffie-hellman-group14-sha256 (with OpenSSH's "strict
//! key exchange"). Host keys: Ed25519, ECDSA P-256, RSA (SHA-2). The caller decides whether
//! the server's host key is the expected one before any password is sent.

pub mod cipher;
pub mod hostkey;
pub mod wire;

use crate::net::{Network, Reader};
use crate::{Code, Error};
use cipher::Cipher;
use sha2::{Digest, Sha256};
use wire::{display, protocol, Parser, Writer};

const CLIENT_VERSION: &str = "SSH-2.0-EasePassQt_1.0";
const KEX: [&str; 3] = ["curve25519-sha256", "curve25519-sha256@libssh.org", "diffie-hellman-group14-sha256"];
const STRICT_CLIENT: &str = "kex-strict-c-v00@openssh.com";
const STRICT_SERVER: &str = "kex-strict-s-v00@openssh.com";
const LOCAL_WINDOW: u32 = 4 * 1024 * 1024;
const LOCAL_MAX_PACKET: u32 = 64 * 1024;

mod msg {
    pub const DISCONNECT: u8 = 1;
    pub const IGNORE: u8 = 2;
    pub const UNIMPLEMENTED: u8 = 3;
    pub const DEBUG: u8 = 4;
    pub const SERVICE_REQUEST: u8 = 5;
    pub const SERVICE_ACCEPT: u8 = 6;
    pub const EXT_INFO: u8 = 7;
    pub const KEXINIT: u8 = 20;
    pub const NEWKEYS: u8 = 21;
    pub const KEX_INIT: u8 = 30;
    pub const KEX_REPLY: u8 = 31;
    pub const USERAUTH_REQUEST: u8 = 50;
    pub const USERAUTH_FAILURE: u8 = 51;
    pub const USERAUTH_SUCCESS: u8 = 52;
    pub const USERAUTH_BANNER: u8 = 53;
    pub const USERAUTH_INFO_REQUEST: u8 = 60;
    pub const USERAUTH_INFO_RESPONSE: u8 = 61;
    pub const GLOBAL_REQUEST: u8 = 80;
    pub const REQUEST_FAILURE: u8 = 82;
    pub const CHANNEL_OPEN: u8 = 90;
    pub const CHANNEL_OPEN_CONFIRMATION: u8 = 91;
    pub const CHANNEL_OPEN_FAILURE: u8 = 92;
    pub const CHANNEL_WINDOW_ADJUST: u8 = 93;
    pub const CHANNEL_DATA: u8 = 94;
    pub const CHANNEL_EXTENDED_DATA: u8 = 95;
    pub const CHANNEL_EOF: u8 = 96;
    pub const CHANNEL_CLOSE: u8 = 97;
    pub const CHANNEL_REQUEST: u8 = 98;
    pub const CHANNEL_SUCCESS: u8 = 99;
    pub const CHANNEL_FAILURE: u8 = 100;
}

/// The 2048-bit MODP group of RFC 3526 (group 14).
const GROUP14_PRIME: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

pub struct Session<'a> {
    network: &'a dyn Network,
    reader: Reader,
    send: Cipher,
    receive: Cipher,
    send_sequence: u32,
    receive_sequence: u32,
    session_id: Vec<u8>,
    /// Host key blob of the server, proven by the key exchange.
    host_key: Vec<u8>,
    // The one channel.
    remote_channel: u32,
    remote_window: u64,
    remote_max_packet: usize,
    local_window: u32,
    incoming: Vec<u8>,
    closed: bool,
}

impl<'a> Session<'a> {
    /// Connects and exchanges keys. Nothing secret has been sent when this returns; check
    /// `host_key_fingerprint()` before calling `login`.
    pub fn connect(network: &'a dyn Network, host: &str, port: u16) -> Result<Session<'a>, Error> {
        let connection = network.connect(host, port, false)?;
        let mut session = Session {
            network,
            reader: Reader::new(connection),
            send: Cipher::Plain,
            receive: Cipher::Plain,
            send_sequence: 0,
            receive_sequence: 0,
            session_id: Vec::new(),
            host_key: Vec::new(),
            remote_channel: 0,
            remote_window: 0,
            remote_max_packet: 0,
            local_window: LOCAL_WINDOW,
            incoming: Vec::new(),
            closed: false,
        };
        session.reader.connection().write_all(format!("{CLIENT_VERSION}\r\n").as_bytes())?;
        let server_version = session.read_version()?;
        session.key_exchange(&server_version)?;
        Ok(session)
    }

    pub fn host_key_fingerprint(&self) -> String {
        hostkey::fingerprint(&self.host_key)
    }

    fn read_version(&mut self) -> Result<String, Error> {
        // A server may send other lines before its version (RFC 4253, 4.2).
        for _ in 0..32 {
            let line = self.reader.read_line(8192)?;
            if line.starts_with(b"SSH-") {
                let version = String::from_utf8_lossy(&line).into_owned();
                if !(version.starts_with("SSH-2.0-") || version.starts_with("SSH-1.99-")) {
                    return Err(protocol("the server only speaks an old SSH version"));
                }
                return Ok(version);
            }
        }
        Err(protocol("this is not an SSH server"))
    }

    fn send_packet(&mut self, payload: &[u8]) -> Result<(), Error> {
        let network = self.network;
        let packet = self.send.seal(self.send_sequence, payload, &mut |padding| network.random(padding));
        self.send_sequence = self.send_sequence.wrapping_add(1);
        self.reader.connection().write_all(&packet)
    }

    fn receive_raw(&mut self) -> Result<Vec<u8>, Error> {
        let payload = self.receive.open(self.receive_sequence, &mut self.reader)?;
        self.receive_sequence = self.receive_sequence.wrapping_add(1);
        if payload.is_empty() {
            return Err(protocol("the server sent an empty packet"));
        }
        Ok(payload)
    }

    /// The next packet that is not transport-level noise.
    fn receive_packet(&mut self) -> Result<Vec<u8>, Error> {
        loop {
            let payload = self.receive_raw()?;
            match payload[0] {
                msg::IGNORE | msg::DEBUG | msg::UNIMPLEMENTED | msg::EXT_INFO => continue,
                msg::DISCONNECT => return Err(disconnect_error(&payload)),
                msg::KEXINIT => return Err(protocol("the server asked for new keys in the middle of the transfer, which this plugin does not support")),
                _ => return Ok(payload),
            }
        }
    }

    fn key_exchange(&mut self, server_version: &str) -> Result<(), Error> {
        let mut cookie = [0u8; 16];
        self.network.random(&mut cookie);
        let mut kex_names: Vec<&str> = KEX.to_vec();
        kex_names.push(STRICT_CLIENT);
        let client_kexinit = Writer::new()
            .u8(msg::KEXINIT)
            .raw(&cookie)
            .name_list(&kex_names)
            .name_list(&hostkey::ALGORITHMS)
            .name_list(&cipher::CIPHERS)
            .name_list(&cipher::CIPHERS)
            .name_list(&cipher::MACS)
            .name_list(&cipher::MACS)
            .name_list(&["none"])
            .name_list(&["none"])
            .name_list(&[])
            .name_list(&[])
            .bool(false)
            .u32(0)
            .0;
        self.send_packet(&client_kexinit)?;

        // With strict key exchange the server's KEXINIT must be the very first packet.
        let server_kexinit = self.receive_raw()?;
        if server_kexinit[0] == msg::DISCONNECT {
            return Err(disconnect_error(&server_kexinit));
        }
        if server_kexinit[0] != msg::KEXINIT {
            return Err(protocol("the server did not start with a key exchange"));
        }
        let mut parser = Parser::new(&server_kexinit[1..]);
        parser.take(16)?;
        let server_kex = parser.name_list()?;
        let server_host_keys = parser.name_list()?;
        let server_ciphers_c2s = parser.name_list()?;
        let server_ciphers_s2c = parser.name_list()?;
        let server_macs_c2s = parser.name_list()?;
        let server_macs_s2c = parser.name_list()?;
        let server_compression_c2s = parser.name_list()?;
        let server_compression_s2c = parser.name_list()?;
        parser.name_list()?;
        parser.name_list()?;
        let first_packet_follows = parser.bool()?;

        let strict = server_kex.iter().any(|name| name == STRICT_SERVER);
        let kex = choose(&KEX, &server_kex, "key exchange")?;
        let host_key_algorithm = choose(&hostkey::ALGORITHMS, &server_host_keys, "host key")?;
        let cipher_c2s = choose(&cipher::CIPHERS, &server_ciphers_c2s, "encryption")?;
        let cipher_s2c = choose(&cipher::CIPHERS, &server_ciphers_s2c, "encryption")?;
        let mac_c2s = if cipher::mac_key_length(cipher_c2s, "") == 0 { "" } else { choose(&cipher::MACS, &server_macs_c2s, "integrity")? };
        let mac_s2c = if cipher::mac_key_length(cipher_s2c, "") == 0 { "" } else { choose(&cipher::MACS, &server_macs_s2c, "integrity")? };
        choose(&["none"], &server_compression_c2s, "compression")?;
        choose(&["none"], &server_compression_s2c, "compression")?;

        // The server guessed an algorithm and already sent its first packet for it.
        let guessed_wrong = first_packet_follows
            && (server_kex.first().map(String::as_str) != Some(kex)
                || server_host_keys.first().map(String::as_str) != Some(host_key_algorithm));
        if guessed_wrong {
            self.receive_raw()?;
        }

        // The key exchange itself.
        let mut secret_bytes = [0u8; 32];
        self.network.random(&mut secret_bytes);
        let (client_public, shared_secret, server_public, key_blob, signature);
        if kex.starts_with("curve25519") {
            let secret = x25519_dalek::StaticSecret::from(secret_bytes);
            let public = x25519_dalek::PublicKey::from(&secret);
            self.send_packet(&Writer::new().u8(msg::KEX_INIT).string(public.as_bytes()).0)?;
            let reply = self.kex_reply(strict)?;
            let mut parser = Parser::new(&reply[1..]);
            key_blob = parser.string()?.to_vec();
            let their: [u8; 32] = parser.string()?.try_into().map_err(|_| protocol("bad key exchange reply"))?;
            signature = parser.string()?.to_vec();
            let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(their));
            if !shared.was_contributory() {
                return Err(protocol("the server sent an invalid key exchange value"));
            }
            client_public = Writer::new().string(public.as_bytes()).0;
            server_public = Writer::new().string(&their).0;
            shared_secret = Writer::new().mpint(shared.as_bytes()).0;
        } else {
            use rsa::BigUint;
            let prime = BigUint::parse_bytes(GROUP14_PRIME.as_bytes(), 16).expect("constant");
            let one = BigUint::from(1u32);
            let x = BigUint::from_bytes_be(&secret_bytes);
            let e = BigUint::from(2u32).modpow(&x, &prime);
            self.send_packet(&Writer::new().u8(msg::KEX_INIT).mpint(&e.to_bytes_be()).0)?;
            let reply = self.kex_reply(strict)?;
            let mut parser = Parser::new(&reply[1..]);
            key_blob = parser.string()?.to_vec();
            let f = BigUint::from_bytes_be(parser.mpint()?);
            signature = parser.string()?.to_vec();
            if f <= one || f >= &prime - &one {
                return Err(protocol("the server sent an invalid key exchange value"));
            }
            let k = f.modpow(&x, &prime);
            client_public = Writer::new().mpint(&e.to_bytes_be()).0;
            server_public = Writer::new().mpint(&f.to_bytes_be()).0;
            shared_secret = Writer::new().mpint(&k.to_bytes_be()).0;
        }

        // The exchange hash binds versions, both KEXINITs, the host key and the secret.
        let exchange_hash = Sha256::digest(
            Writer::new()
                .string(CLIENT_VERSION.as_bytes())
                .string(server_version.as_bytes())
                .string(&client_kexinit)
                .string(&server_kexinit)
                .string(&key_blob)
                .raw(&client_public)
                .raw(&server_public)
                .raw(&shared_secret)
                .0,
        )
        .to_vec();
        hostkey::verify(host_key_algorithm, &key_blob, &signature, &exchange_hash)?;
        self.host_key = key_blob;
        self.session_id = exchange_hash.clone();

        self.send_packet(&[msg::NEWKEYS])?;
        let newkeys = if strict { self.receive_raw()? } else { self.receive_packet()? };
        if newkeys[0] != msg::NEWKEYS {
            return Err(protocol("the key exchange was not completed by the server"));
        }

        let derive = |letter: u8, length: usize| -> Vec<u8> {
            let mut key: Vec<u8> = Vec::new();
            while key.len() < length {
                let mut hash = Sha256::new();
                hash.update(&shared_secret);
                hash.update(&exchange_hash);
                if key.is_empty() {
                    hash.update([letter]);
                    hash.update(&self.session_id);
                } else {
                    hash.update(&key);
                }
                key.extend_from_slice(&hash.finalize());
            }
            key.truncate(length);
            key
        };
        let send = Cipher::new(
            cipher_c2s,
            mac_c2s,
            &derive(b'C', cipher::key_length(cipher_c2s)),
            &derive(b'A', cipher::iv_length(cipher_c2s)),
            &derive(b'E', cipher::mac_key_length(cipher_c2s, mac_c2s)),
        )?;
        let receive = Cipher::new(
            cipher_s2c,
            mac_s2c,
            &derive(b'D', cipher::key_length(cipher_s2c)),
            &derive(b'B', cipher::iv_length(cipher_s2c)),
            &derive(b'F', cipher::mac_key_length(cipher_s2c, mac_s2c)),
        )?;
        self.send = send;
        self.receive = receive;
        if strict {
            self.send_sequence = 0;
            self.receive_sequence = 0;
        }
        Ok(())
    }

    fn kex_reply(&mut self, strict: bool) -> Result<Vec<u8>, Error> {
        // Strict key exchange: nothing may be slipped in between.
        let reply = if strict { self.receive_raw()? } else { self.receive_packet()? };
        match reply[0] {
            msg::KEX_REPLY => Ok(reply),
            msg::DISCONNECT => Err(disconnect_error(&reply)),
            _ => Err(protocol("unexpected packet during the key exchange")),
        }
    }

    /// Logs in with user name and password ("password", or "keyboard-interactive" when the
    /// server only offers that).
    pub fn login(&mut self, user: &str, password: &str) -> Result<(), Error> {
        self.send_packet(&Writer::new().u8(msg::SERVICE_REQUEST).string(b"ssh-userauth").0)?;
        let accepted = self.receive_packet()?;
        if accepted[0] != msg::SERVICE_ACCEPT {
            return Err(protocol("the server does not offer a login"));
        }
        let wrong = || Error::new(Code::NotAllowed, "the server did not accept the user name or password");
        self.send_packet(
            &Writer::new()
                .u8(msg::USERAUTH_REQUEST)
                .string(user.as_bytes())
                .string(b"ssh-connection")
                .string(b"password")
                .bool(false)
                .string(password.as_bytes())
                .0,
        )?;
        let mut tried_interactive = false;
        let mut answered = false;
        loop {
            let reply = self.receive_packet()?;
            match reply[0] {
                msg::USERAUTH_SUCCESS => return Ok(()),
                msg::USERAUTH_BANNER => continue,
                msg::USERAUTH_FAILURE => {
                    let methods = Parser::new(&reply[1..]).name_list()?;
                    if tried_interactive || !methods.iter().any(|m| m == "keyboard-interactive") {
                        if !methods.iter().any(|m| m == "password" || m == "keyboard-interactive") {
                            return Err(Error::new(Code::NotAllowed, "the server does not allow a login with a password (only with a key file, which this plugin does not support)"));
                        }
                        return Err(wrong());
                    }
                    tried_interactive = true;
                    self.send_packet(
                        &Writer::new()
                            .u8(msg::USERAUTH_REQUEST)
                            .string(user.as_bytes())
                            .string(b"ssh-connection")
                            .string(b"keyboard-interactive")
                            .string(b"")
                            .string(b"")
                            .0,
                    )?;
                }
                // 60 is "change your password" after a password request and a question
                // after a keyboard-interactive request.
                msg::USERAUTH_INFO_REQUEST if tried_interactive => {
                    let mut parser = Parser::new(&reply[1..]);
                    parser.string()?;
                    parser.string()?;
                    parser.string()?;
                    let prompts = parser.u32()?;
                    // The password answers one question, once. Anything else (a second
                    // factor, a second round) cannot be answered by this plugin.
                    if prompts > 1 || (prompts == 1 && answered) {
                        return Err(Error::new(Code::NotAllowed, "the server asks for more than a password, which this plugin does not support"));
                    }
                    let mut response = Writer::new().u8(msg::USERAUTH_INFO_RESPONSE).u32(prompts);
                    if prompts == 1 {
                        response = response.string(password.as_bytes());
                        answered = true;
                    }
                    self.send_packet(&response.0)?;
                }
                msg::USERAUTH_INFO_REQUEST => {
                    return Err(Error::new(Code::NotAllowed, "the server wants the password to be changed first"))
                }
                _ => return Err(protocol("unexpected answer to the login")),
            }
        }
    }

    /// Opens the channel and starts the SFTP subsystem on it.
    pub fn open_sftp(&mut self) -> Result<(), Error> {
        self.send_packet(
            &Writer::new().u8(msg::CHANNEL_OPEN).string(b"session").u32(0).u32(LOCAL_WINDOW).u32(LOCAL_MAX_PACKET).0,
        )?;
        loop {
            let reply = self.receive_packet()?;
            match reply[0] {
                msg::CHANNEL_OPEN_CONFIRMATION => {
                    let mut parser = Parser::new(&reply[1..]);
                    parser.u32()?;
                    self.remote_channel = parser.u32()?;
                    self.remote_window = u64::from(parser.u32()?);
                    self.remote_max_packet = parser.u32()? as usize;
                    break;
                }
                msg::CHANNEL_OPEN_FAILURE => return Err(protocol("the server refused to open a session")),
                msg::GLOBAL_REQUEST => self.answer_global_request(&reply)?,
                _ => return Err(protocol("unexpected answer while opening a session")),
            }
        }
        if self.remote_max_packet < 1024 {
            return Err(protocol("the server only accepts tiny packets"));
        }
        self.send_packet(
            &Writer::new().u8(msg::CHANNEL_REQUEST).u32(self.remote_channel).string(b"subsystem").bool(true).string(b"sftp").0,
        )?;
        loop {
            let reply = self.receive_packet()?;
            match reply[0] {
                msg::CHANNEL_SUCCESS => return Ok(()),
                msg::CHANNEL_FAILURE => {
                    return Err(Error::new(Code::Unavailable, "the server does not offer SFTP for this account"))
                }
                _ => self.handle_channel_packet(&reply)?,
            }
        }
    }

    fn answer_global_request(&mut self, packet: &[u8]) -> Result<(), Error> {
        let mut parser = Parser::new(&packet[1..]);
        parser.string()?;
        if parser.bool()? {
            self.send_packet(&[msg::REQUEST_FAILURE])?;
        }
        Ok(())
    }

    /// Packets that can arrive at any time once the channel is open.
    fn handle_channel_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        let mut parser = Parser::new(&packet[1..]);
        match packet[0] {
            msg::GLOBAL_REQUEST => self.answer_global_request(packet)?,
            msg::CHANNEL_WINDOW_ADJUST => {
                parser.u32()?;
                self.remote_window += u64::from(parser.u32()?);
            }
            msg::CHANNEL_DATA => {
                parser.u32()?;
                let data = parser.string()?;
                if data.len() as u64 > u64::from(self.local_window) {
                    return Err(protocol("the server sent more data than allowed"));
                }
                self.local_window -= data.len() as u32;
                self.incoming.extend_from_slice(data);
                if self.local_window < LOCAL_WINDOW / 2 {
                    let add = LOCAL_WINDOW - self.local_window;
                    self.send_packet(&Writer::new().u8(msg::CHANNEL_WINDOW_ADJUST).u32(self.remote_channel).u32(add).0)?;
                    self.local_window = LOCAL_WINDOW;
                }
            }
            msg::CHANNEL_EXTENDED_DATA => {
                // stderr of the subsystem: counts against the window, otherwise ignored.
                parser.u32()?;
                parser.u32()?;
                let data = parser.string()?;
                self.local_window = self.local_window.saturating_sub(data.len() as u32);
            }
            msg::CHANNEL_REQUEST => {
                parser.u32()?;
                parser.string()?;
                if parser.bool()? {
                    self.send_packet(&Writer::new().u8(msg::CHANNEL_FAILURE).u32(self.remote_channel).0)?;
                }
            }
            msg::CHANNEL_EOF | msg::CHANNEL_CLOSE => self.closed = true,
            msg::CHANNEL_SUCCESS | msg::CHANNEL_FAILURE => {}
            _ => return Err(protocol("unexpected packet from the server")),
        }
        Ok(())
    }

    /// Sends bytes to the subsystem, respecting the server's window and packet size.
    pub fn channel_write(&mut self, data: &[u8]) -> Result<(), Error> {
        let mut rest = data;
        while !rest.is_empty() {
            while self.remote_window == 0 {
                if self.closed {
                    return Err(protocol("the server closed the session"));
                }
                let packet = self.receive_packet()?;
                self.handle_channel_packet(&packet)?;
            }
            let count = rest.len().min(self.remote_max_packet).min(self.remote_window as usize).min(32 * 1024);
            self.send_packet(&Writer::new().u8(msg::CHANNEL_DATA).u32(self.remote_channel).string(&rest[..count]).0)?;
            self.remote_window -= count as u64;
            rest = &rest[count..];
        }
        Ok(())
    }

    /// Exactly `count` bytes from the subsystem.
    pub fn channel_read(&mut self, count: usize) -> Result<Vec<u8>, Error> {
        while self.incoming.len() < count {
            if self.closed {
                return Err(protocol("the server closed the session"));
            }
            let packet = self.receive_packet()?;
            self.handle_channel_packet(&packet)?;
        }
        let rest = self.incoming.split_off(count);
        Ok(std::mem::replace(&mut self.incoming, rest))
    }

    /// Says goodbye; errors do not matter any more.
    pub fn close(mut self) {
        let _ = self.send_packet(&Writer::new().u8(msg::CHANNEL_CLOSE).u32(self.remote_channel).0);
        let _ = self.send_packet(&Writer::new().u8(msg::DISCONNECT).u32(11).string(b"done").string(b"").0);
    }
}

fn choose<'x>(ours: &[&'x str], theirs: &[String], what: &str) -> Result<&'x str, Error> {
    ours.iter()
        .copied()
        .find(|name| theirs.iter().any(|their| their == name))
        .ok_or_else(|| Error::new(Code::Unavailable, format!("SSH: this plugin and the server have no {what} method in common")))
}

fn disconnect_error(packet: &[u8]) -> Error {
    let mut parser = Parser::new(&packet[1..]);
    let _ = parser.u32();
    let reason = parser.text().unwrap_or_default();
    protocol(format!("the server ended the connection: {}", display(&reason)))
}
