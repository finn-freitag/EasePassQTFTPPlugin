//! What the protocols need from the outside world. In the plugin this is Ease Pass (which
//! checks every connection against the plugin's allowed servers); in tests it is the
//! operating system or a script.

use crate::{Code, Error};

pub trait Connection {
    /// Up to `max` bytes; an empty result means the other side closed the connection.
    fn read(&mut self, max: usize) -> Result<Vec<u8>, Error>;
    fn write_all(&mut self, data: &[u8]) -> Result<(), Error>;
    /// Switches the open connection to TLS (certificate checked against the host name).
    fn start_tls(&mut self) -> Result<(), Error>;
}

pub trait Network {
    fn connect(&self, host: &str, port: u16, tls: bool) -> Result<Box<dyn Connection>, Error>;
    /// Cryptographically secure random bytes.
    fn random(&self, bytes: &mut [u8]);
}

/// Reads exact amounts and lines from a connection.
pub struct Reader {
    connection: Box<dyn Connection>,
    buffer: Vec<u8>,
    start: usize,
}

impl Reader {
    pub fn new(connection: Box<dyn Connection>) -> Self {
        Reader { connection, buffer: Vec::new(), start: 0 }
    }

    pub fn connection(&mut self) -> &mut dyn Connection {
        self.connection.as_mut()
    }

    /// Bytes that were received but not consumed yet (must be empty before start_tls).
    pub fn buffered(&self) -> usize {
        self.buffer.len() - self.start
    }

    fn fill(&mut self) -> Result<(), Error> {
        if self.start > 0 && self.start == self.buffer.len() {
            self.buffer.clear();
            self.start = 0;
        }
        let chunk = self.connection.read(64 * 1024)?;
        if chunk.is_empty() {
            return Err(Error::new(Code::Network, "the server closed the connection"));
        }
        self.buffer.extend_from_slice(&chunk);
        Ok(())
    }

    pub fn read_exact(&mut self, count: usize) -> Result<Vec<u8>, Error> {
        while self.buffered() < count {
            self.fill()?;
        }
        let out = self.buffer[self.start..self.start + count].to_vec();
        self.start += count;
        Ok(out)
    }

    /// One line without its line end. Lines longer than `max` are an error.
    pub fn read_line(&mut self, max: usize) -> Result<Vec<u8>, Error> {
        loop {
            if let Some(position) = self.buffer[self.start..].iter().position(|b| *b == b'\n') {
                let mut line = self.buffer[self.start..self.start + position].to_vec();
                self.start += position + 1;
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(line);
            }
            if self.buffered() > max {
                return Err(Error::new(Code::Network, "the server sent an over-long line"));
            }
            self.fill()?;
        }
    }

    /// Everything until the other side closes, at most `max` bytes.
    pub fn read_to_end(&mut self, max: usize) -> Result<Vec<u8>, Error> {
        let mut out = self.buffer[self.start..].to_vec();
        self.buffer.clear();
        self.start = 0;
        loop {
            let chunk = self.connection.read(64 * 1024)?;
            if chunk.is_empty() {
                return Ok(out);
            }
            if out.len() + chunk.len() > max {
                return Err(Error::new(Code::TooLarge, "the file is larger than 2 MiB"));
            }
            out.extend_from_slice(&chunk);
        }
    }
}
