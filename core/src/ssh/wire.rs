//! SSH data types (RFC 4251, section 5): building and parsing packets.

use crate::{Code, Error};

pub fn protocol(message: impl Into<String>) -> Error {
    Error::new(Code::Network, format!("SSH: {}", message.into()))
}

#[derive(Default)]
pub struct Writer(pub Vec<u8>);

impl Writer {
    pub fn new() -> Self {
        Writer(Vec::new())
    }
    pub fn u8(mut self, value: u8) -> Self {
        self.0.push(value);
        self
    }
    pub fn bool(self, value: bool) -> Self {
        self.u8(u8::from(value))
    }
    pub fn u32(mut self, value: u32) -> Self {
        self.0.extend_from_slice(&value.to_be_bytes());
        self
    }
    pub fn u64(mut self, value: u64) -> Self {
        self.0.extend_from_slice(&value.to_be_bytes());
        self
    }
    pub fn raw(mut self, bytes: &[u8]) -> Self {
        self.0.extend_from_slice(bytes);
        self
    }
    pub fn string(self, bytes: &[u8]) -> Self {
        self.u32(bytes.len() as u32).raw(bytes)
    }
    pub fn name_list(self, names: &[&str]) -> Self {
        self.string(names.join(",").as_bytes())
    }
    /// A non-negative number given as big-endian bytes.
    pub fn mpint(self, magnitude: &[u8]) -> Self {
        let trimmed = &magnitude[magnitude.iter().position(|b| *b != 0).unwrap_or(magnitude.len())..];
        if trimmed.first().is_some_and(|b| b & 0x80 != 0) {
            self.u32(trimmed.len() as u32 + 1).u8(0).raw(trimmed)
        } else {
            self.string(trimmed)
        }
    }
}

pub struct Parser<'a> {
    data: &'a [u8],
}

impl<'a> Parser<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Parser { data }
    }
    pub fn rest(&self) -> &'a [u8] {
        self.data
    }
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
    pub fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        if self.data.len() < count {
            return Err(protocol("the server sent a packet that is too short"));
        }
        let (head, tail) = self.data.split_at(count);
        self.data = tail;
        Ok(head)
    }
    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    pub fn bool(&mut self) -> Result<bool, Error> {
        Ok(self.u8()? != 0)
    }
    pub fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn string(&mut self) -> Result<&'a [u8], Error> {
        let length = self.u32()? as usize;
        self.take(length)
    }
    pub fn text(&mut self) -> Result<String, Error> {
        Ok(String::from_utf8_lossy(self.string()?).into_owned())
    }
    pub fn name_list(&mut self) -> Result<Vec<String>, Error> {
        let text = self.text()?;
        Ok(text.split(',').filter(|n| !n.is_empty()).map(str::to_string).collect())
    }
    /// The magnitude of a non-negative mpint, without leading zeros.
    pub fn mpint(&mut self) -> Result<&'a [u8], Error> {
        let bytes = self.string()?;
        if bytes.first().is_some_and(|b| b & 0x80 != 0) {
            return Err(protocol("the server sent a negative number"));
        }
        Ok(&bytes[bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len())..])
    }
}

/// Text from the server for an error message: one line, no control characters.
pub fn display(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).take(200).collect()
}
