//! SFTP version 3 (draft-ietf-secsh-filexfer-02) over the SSH session: read a file, and
//! replace a file by writing a temporary file next to it and renaming it over the original.

use crate::net::Network;
use crate::ssh::wire::{display, protocol, Parser, Writer};
use crate::ssh::Session;
use crate::{Code, Error, Target, MAX_DATABASE_BYTES};

const INIT: u8 = 1;
const VERSION: u8 = 2;
const OPEN: u8 = 3;
const CLOSE: u8 = 4;
const READ: u8 = 5;
const WRITE: u8 = 6;
const REMOVE: u8 = 13;
const RENAME: u8 = 18;
const EXTENDED: u8 = 200;
const STATUS: u8 = 101;
const HANDLE: u8 = 102;
const DATA: u8 = 103;

const FX_OK: u32 = 0;
const FX_EOF: u32 = 1;
const FX_NO_SUCH_FILE: u32 = 2;
const FX_PERMISSION_DENIED: u32 = 3;

const FXF_READ: u32 = 1;
const FXF_WRITE: u32 = 2;
const FXF_CREAT: u32 = 8;
const FXF_TRUNC: u32 = 16;

const CHUNK: usize = 32 * 1024;
/// Requests sent before their answers are read.
const PIPELINE: usize = 8;

pub struct Sftp<'a> {
    session: Session<'a>,
    next_id: u32,
    posix_rename: bool,
}

/// What `connect` found out about the server's identity.
pub struct Connected<'a> {
    pub sftp: Sftp<'a>,
    /// Fingerprint of the server's host key, e.g. "SHA256:...".
    pub fingerprint: String,
}

/// Connects, checks the host key through `accept`, logs in and starts SFTP.
/// `accept` sees the fingerprint BEFORE the password is sent.
pub fn connect<'a>(
    network: &'a dyn Network,
    target: &Target,
    accept: &dyn Fn(&str) -> Result<(), Error>,
) -> Result<Connected<'a>, Error> {
    let mut session = Session::connect(network, &target.host, target.port)?;
    let fingerprint = session.host_key_fingerprint();
    accept(&fingerprint)?;
    session.login(&target.username, &target.password)?;
    session.open_sftp()?;
    let mut sftp = Sftp { session, next_id: 1, posix_rename: false };
    sftp.send(Writer::new().u8(INIT).u32(3))?;
    let (kind, body) = sftp.receive()?;
    if kind != VERSION {
        return Err(protocol("the server did not answer like an SFTP server"));
    }
    let mut parser = Parser::new(&body);
    if parser.u32()? < 3 {
        return Err(Error::new(Code::Unavailable, "the server only offers an old SFTP version"));
    }
    while !parser.is_empty() {
        let name = parser.text()?;
        let data = parser.text()?;
        if name == "posix-rename@openssh.com" && data == "1" {
            sftp.posix_rename = true;
        }
    }
    Ok(Connected { sftp, fingerprint })
}

impl Sftp<'_> {
    fn send(&mut self, packet: Writer) -> Result<(), Error> {
        let framed = Writer::new().string(&packet.0).0;
        self.session.channel_write(&framed)
    }

    fn receive(&mut self) -> Result<(u8, Vec<u8>), Error> {
        let head = self.session.channel_read(4)?;
        let length = u32::from_be_bytes(head[..4].try_into().unwrap()) as usize;
        if length == 0 || length > 256 * 1024 {
            return Err(protocol("the server sent an SFTP packet with an impossible length"));
        }
        let mut body = self.session.channel_read(length)?;
        let kind = body.remove(0);
        Ok((kind, body))
    }

    fn id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    /// The answer to request `id` (answers arrive in the order of the requests).
    fn answer(&mut self, id: u32) -> Result<(u8, Vec<u8>), Error> {
        let (kind, body) = self.receive()?;
        let mut parser = Parser::new(&body);
        if parser.u32()? != id {
            return Err(protocol("the server answered a different request"));
        }
        Ok((kind, parser.rest().to_vec()))
    }

    fn status(kind: u8, body: &[u8]) -> Result<(u32, String), Error> {
        if kind != STATUS {
            return Err(protocol("unexpected SFTP answer"));
        }
        let mut parser = Parser::new(body);
        let code = parser.u32()?;
        let message = if parser.is_empty() { String::new() } else { parser.text()? };
        Ok((code, display(&message)))
    }

    fn failure(code: u32, message: &str, what: &str) -> Error {
        let detail = if message.is_empty() { String::new() } else { format!(" ({message})") };
        match code {
            FX_NO_SUCH_FILE => Error::new(Code::NotFound, format!("{what}: there is no such file on the server{detail}")),
            FX_PERMISSION_DENIED => Error::new(Code::NotAllowed, format!("{what}: the server denies access{detail}")),
            _ => Error::new(Code::Unavailable, format!("{what}: the server reported error {code}{detail}")),
        }
    }

    fn expect_ok(&mut self, id: u32, what: &str) -> Result<(), Error> {
        let (kind, body) = self.answer(id)?;
        match Self::status(kind, &body)? {
            (FX_OK, _) => Ok(()),
            (code, message) => Err(Self::failure(code, &message, what)),
        }
    }

    fn open(&mut self, path: &str, flags: u32, what: &str) -> Result<Vec<u8>, Error> {
        let id = self.id();
        self.send(Writer::new().u8(OPEN).u32(id).string(path.as_bytes()).u32(flags).u32(0))?;
        let (kind, body) = self.answer(id)?;
        if kind == HANDLE {
            return Ok(Parser::new(&body).string()?.to_vec());
        }
        let (code, message) = Self::status(kind, &body)?;
        Err(Self::failure(code, &message, what))
    }

    fn close_handle(&mut self, handle: &[u8], what: &str) -> Result<(), Error> {
        let id = self.id();
        self.send(Writer::new().u8(CLOSE).u32(id).string(handle))?;
        self.expect_ok(id, what)
    }

    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>, Error> {
        let what = "reading the database";
        let handle = self.open(path, FXF_READ, what)?;
        let mut file: Vec<u8> = Vec::new();
        loop {
            // Ask for several pieces at once. If one comes back short (allowed even in the
            // middle of a file) or the end is reached, the answers behind it are dropped
            // and the next round starts where the file really continues.
            let mut requests = Vec::new();
            for i in 0..PIPELINE {
                let id = self.id();
                let offset = (file.len() + i * CHUNK) as u64;
                self.send(Writer::new().u8(READ).u32(id).string(&handle).u64(offset).u32(CHUNK as u32))?;
                requests.push((id, offset));
            }
            let mut stop = false;
            let mut end = false;
            let mut failed: Option<Error> = None;
            for (id, offset) in requests {
                let (kind, body) = self.answer(id)?;
                if stop {
                    continue;
                }
                if kind == DATA {
                    let data = Parser::new(&body).string()?;
                    if offset != file.len() as u64 || data.len() > CHUNK {
                        return Err(protocol("the server sent the file out of order"));
                    }
                    file.extend_from_slice(data);
                    if file.len() > MAX_DATABASE_BYTES {
                        failed = Some(Error::new(Code::TooLarge, "the file is larger than 2 MiB"));
                        stop = true;
                    } else if data.len() < CHUNK {
                        stop = true;
                    }
                } else {
                    stop = true;
                    match Self::status(kind, &body)? {
                        (FX_EOF, _) => end = true,
                        (code, message) => failed = Some(Self::failure(code, &message, what)),
                    }
                }
            }
            if let Some(error) = failed {
                let _ = self.close_handle(&handle, what);
                return Err(error);
            }
            if end {
                break;
            }
        }
        self.close_handle(&handle, what)?;
        Ok(file)
    }

    /// Replaces `path` with `data`: writes `path` + ".eptmp" and renames it over `path`, so
    /// a broken connection never leaves half a database behind.
    pub fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), Error> {
        let what = "saving the database";
        let temporary = format!("{path}.eptmp");
        let handle = self.open(&temporary, FXF_WRITE | FXF_CREAT | FXF_TRUNC, what)?;
        let written = self.write_all(&handle, data, what);
        let closed = self.close_handle(&handle, what);
        if let Err(error) = written.and(closed) {
            let _ = self.remove(&temporary);
            return Err(error);
        }
        let renamed = self.rename_over(&temporary, path, what);
        if renamed.is_err() {
            let _ = self.remove(&temporary);
        }
        renamed
    }

    fn write_all(&mut self, handle: &[u8], data: &[u8], what: &str) -> Result<(), Error> {
        let mut offset = 0usize;
        while offset < data.len() {
            let mut ids = Vec::new();
            for _ in 0..PIPELINE {
                if offset >= data.len() {
                    break;
                }
                let end = (offset + CHUNK).min(data.len());
                let id = self.id();
                self.send(Writer::new().u8(WRITE).u32(id).string(handle).u64(offset as u64).string(&data[offset..end]))?;
                ids.push(id);
                offset = end;
            }
            let mut failed: Option<Error> = None;
            for id in ids {
                let (kind, body) = self.answer(id)?;
                match Self::status(kind, &body)? {
                    (FX_OK, _) => {}
                    (code, message) => failed = failed.or(Some(Self::failure(code, &message, what))),
                }
            }
            if let Some(error) = failed {
                return Err(error);
            }
        }
        Ok(())
    }

    fn remove(&mut self, path: &str) -> Result<(), Error> {
        let id = self.id();
        self.send(Writer::new().u8(REMOVE).u32(id).string(path.as_bytes()))?;
        self.expect_ok(id, "removing a file")
    }

    fn rename_over(&mut self, from: &str, to: &str, what: &str) -> Result<(), Error> {
        if self.posix_rename {
            // Replaces the target in one step.
            let id = self.id();
            self.send(
                Writer::new()
                    .u8(EXTENDED)
                    .u32(id)
                    .string(b"posix-rename@openssh.com")
                    .string(from.as_bytes())
                    .string(to.as_bytes()),
            )?;
            return self.expect_ok(id, what);
        }
        // Plain SFTP 3 rename does not replace an existing file.
        let id = self.id();
        self.send(Writer::new().u8(RENAME).u32(id).string(from.as_bytes()).string(to.as_bytes()))?;
        if self.expect_ok(id, what).is_ok() {
            return Ok(());
        }
        match self.remove(to) {
            Ok(()) => {}
            Err(error) if error.code == Code::NotFound => {}
            Err(error) => return Err(error),
        }
        let id = self.id();
        self.send(Writer::new().u8(RENAME).u32(id).string(from.as_bytes()).string(to.as_bytes()))?;
        self.expect_ok(id, what)
    }

    /// For tests: behave as if the server had no "posix-rename" extension.
    #[doc(hidden)]
    pub fn without_posix_rename(&mut self) {
        self.posix_rename = false;
    }

    pub fn close(self) {
        self.session.close();
    }
}
