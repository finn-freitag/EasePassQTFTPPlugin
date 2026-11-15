//! FTP (RFC 959) and FTP over TLS (RFC 4217): read a file, and replace a file by uploading
//! a temporary file next to it and renaming it over the original.
//!
//! Passive mode only. The data connection always goes to the server named in the settings,
//! never to an address the server sends (that is also what Ease Pass allows the plugin).

use crate::net::{Connection, Network, Reader};
use crate::{Code, Error, Mode, Target, MAX_DATABASE_BYTES};

/// Implicit FTPS: TLS from the first byte (instead of "AUTH TLS" on a plain connection).
const IMPLICIT_TLS_PORT: u16 = 990;

struct Reply {
    code: u16,
    text: String,
}

pub struct Ftp<'a> {
    network: &'a dyn Network,
    control: Reader,
    host: String,
    secure: bool,
}

fn display(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).take(200).collect()
}

fn unexpected(what: &str, reply: &Reply) -> Error {
    let code = match reply.code {
        530 | 532 => Code::NotAllowed,
        550 | 553 if what.starts_with("reading") => Code::NotFound,
        550 | 553 | 552 => Code::NotAllowed,
        421 | 425 | 426 | 450 | 451 | 452 => Code::Unavailable,
        _ => Code::Unavailable,
    };
    Error::new(code, format!("{what}: the server answered \"{} {}\"", reply.code, display(&reply.text)))
}

impl<'a> Ftp<'a> {
    pub fn connect(network: &'a dyn Network, target: &Target) -> Result<Ftp<'a>, Error> {
        let secure = target.mode == Mode::Ftps;
        let implicit = secure && target.port == IMPLICIT_TLS_PORT;
        let connection = network.connect(&target.host, target.port, implicit)?;
        let mut ftp = Ftp { network, control: Reader::new(connection), host: target.host.clone(), secure };
        let greeting = ftp.read_reply()?;
        if greeting.code != 220 {
            return Err(unexpected("connecting", &greeting));
        }
        if secure && !implicit {
            let reply = ftp.command("AUTH TLS")?;
            if reply.code != 234 {
                return Err(Error::new(Code::Unavailable, format!("the server does not offer FTPS (it answered \"{} {}\"); the password was not sent", reply.code, display(&reply.text))));
            }
            // Nothing the server sent in the clear may be taken for an answer given under TLS.
            if ftp.control.buffered() != 0 {
                return Err(Error::new(Code::Network, "the server sent data before the encryption started"));
            }
            ftp.control.connection().start_tls()?;
        }
        let reply = ftp.command(&format!("USER {}", target.username))?;
        let reply = match reply.code {
            230 => reply,
            331 => ftp.command(&format!("PASS {}", target.password))?,
            _ => return Err(unexpected("logging in", &reply)),
        };
        match reply.code {
            230 | 202 => {}
            530 | 430 => return Err(Error::new(Code::NotAllowed, "the server did not accept the user name or password")),
            _ => return Err(unexpected("logging in", &reply)),
        }
        if secure {
            // Protect the data connections too.
            for command in ["PBSZ 0", "PROT P"] {
                let reply = ftp.command(command)?;
                if reply.code != 200 {
                    return Err(unexpected("switching on encryption for the file transfer", &reply));
                }
            }
        }
        let reply = ftp.command("TYPE I")?;
        if reply.code != 200 {
            return Err(unexpected("switching to binary transfer", &reply));
        }
        Ok(ftp)
    }

    fn read_reply(&mut self) -> Result<Reply, Error> {
        let bad = || Error::new(Code::Network, "this does not look like an FTP server");
        let first = self.control.read_line(4096)?;
        if first.len() < 3 || !first[..3].iter().all(u8::is_ascii_digit) {
            return Err(bad());
        }
        let code: u16 = std::str::from_utf8(&first[..3]).ok().and_then(|c| c.parse().ok()).ok_or_else(bad)?;
        let mut text = String::from_utf8_lossy(first.get(4..).unwrap_or(&[])).into_owned();
        if first.get(3) == Some(&b'-') {
            // Multi-line reply: ends with "<same code><space>".
            for _ in 0..200 {
                let line = self.control.read_line(4096)?;
                if line.len() >= 4 && line[..3] == first[..3] && line[3] == b' ' {
                    text = String::from_utf8_lossy(&line[4..]).into_owned();
                    return Ok(Reply { code, text });
                }
            }
            return Err(bad());
        }
        Ok(Reply { code, text })
    }

    fn command(&mut self, command: &str) -> Result<Reply, Error> {
        self.control.connection().write_all(format!("{command}\r\n").as_bytes())?;
        let mut reply = self.read_reply()?;
        // 1xx is not the final answer for commands without a data connection.
        while (100..200).contains(&reply.code) && !is_transfer(command) {
            reply = self.read_reply()?;
        }
        Ok(reply)
    }

    /// Opens the data connection for the next transfer (not yet encrypted).
    fn passive(&mut self) -> Result<Box<dyn Connection>, Error> {
        let reply = self.command("EPSV")?;
        let port = if reply.code == 229 {
            parse_epsv(&reply.text)
        } else {
            let reply = self.command("PASV")?;
            if reply.code != 227 {
                return Err(unexpected("opening the data connection", &reply));
            }
            parse_pasv(&reply.text)
        };
        let port = port.ok_or_else(|| Error::new(Code::Network, "the server named no usable port for the data connection"))?;
        self.network.connect(&self.host, port, false)
    }

    fn finish_transfer(&mut self, what: &str) -> Result<(), Error> {
        let reply = self.read_reply()?;
        if reply.code != 226 && reply.code != 250 {
            return Err(unexpected(what, &reply));
        }
        Ok(())
    }

    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>, Error> {
        let what = "reading the database";
        let mut data = self.passive()?;
        let reply = self.command(&format!("RETR {path}"))?;
        if reply.code != 150 && reply.code != 125 {
            return Err(unexpected(what, &reply));
        }
        if self.secure {
            data.start_tls()?;
        }
        let mut reader = Reader::new(data);
        let file = reader.read_to_end(MAX_DATABASE_BYTES);
        drop(reader);
        // Only a transfer the server calls complete counts: a cut connection must not
        // pass as a (shorter) database.
        self.finish_transfer(what)?;
        file
    }

    fn store(&mut self, path: &str, content: &[u8], what: &str) -> Result<(), Error> {
        let mut data = self.passive()?;
        let reply = self.command(&format!("STOR {path}"))?;
        if reply.code != 150 && reply.code != 125 {
            return Err(unexpected(what, &reply));
        }
        if self.secure {
            data.start_tls()?;
        }
        for chunk in content.chunks(64 * 1024) {
            data.write_all(chunk)?;
        }
        drop(data); // closing the data connection ends the file
        self.finish_transfer(what)
    }

    /// Replaces `path` with `content`: uploads `path` + ".eptmp" and renames it over `path`.
    pub fn write_file(&mut self, path: &str, content: &[u8]) -> Result<(), Error> {
        let what = "saving the database";
        let temporary = format!("{path}.eptmp");
        self.store(&temporary, content, what)?;
        // The upload must have arrived completely before it replaces the database.
        let size = self.command(&format!("SIZE {temporary}"))?;
        if size.code == 213 && size.text.trim().parse::<usize>().ok() != Some(content.len()) {
            let _ = self.command(&format!("DELE {temporary}"));
            return Err(Error::new(Code::Network, "saving the database: the upload arrived incomplete; the database on the server was not changed"));
        }
        let renamed = self.rename(&temporary, path);
        let result = match renamed {
            Ok(()) => Ok(()),
            Err(_) => {
                // Some servers do not rename over an existing file.
                let deleted = self.command(&format!("DELE {path}"))?;
                if deleted.code != 250 && deleted.code != 550 {
                    Err(unexpected(what, &deleted))
                } else {
                    self.rename(&temporary, path)
                }
            }
        };
        if result.is_err() {
            let _ = self.command(&format!("DELE {temporary}"));
        }
        result
    }

    fn rename(&mut self, from: &str, to: &str) -> Result<(), Error> {
        let what = "saving the database";
        let reply = self.command(&format!("RNFR {from}"))?;
        if reply.code != 350 {
            return Err(unexpected(what, &reply));
        }
        let reply = self.command(&format!("RNTO {to}"))?;
        if reply.code != 250 {
            return Err(unexpected(what, &reply));
        }
        Ok(())
    }

    pub fn close(mut self) {
        let _ = self.command("QUIT");
    }
}

fn is_transfer(command: &str) -> bool {
    command.starts_with("RETR ") || command.starts_with("STOR ")
}

/// "Entering Extended Passive Mode (|||50000|)"
fn parse_epsv(text: &str) -> Option<u16> {
    let inside = text.get(text.find('(')? + 1..text.rfind(')')?)?;
    let delimiter = inside.chars().next()?;
    let parts: Vec<&str> = inside.split(delimiter).collect();
    if parts.len() != 5 {
        return None;
    }
    parts[3].parse::<u16>().ok().filter(|port| *port != 0)
}

/// "Entering Passive Mode (192,168,1,2,195,80)": only the port is used.
fn parse_pasv(text: &str) -> Option<u16> {
    let start = text.find(|c: char| c.is_ascii_digit())?;
    let numbers: Vec<u16> = text[start..]
        .split(|c: char| !c.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .take(6)
        .map(|part| part.parse::<u16>().ok().filter(|n| *n <= 255))
        .collect::<Option<Vec<u16>>>()?;
    if numbers.len() != 6 {
        return None;
    }
    Some(numbers[4] * 256 + numbers[5]).filter(|port| *port != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passive_answers() {
        assert_eq!(parse_epsv("Entering Extended Passive Mode (|||50000|)"), Some(50000));
        assert_eq!(parse_epsv("Extended Passive Mode (!!!21!)"), Some(21));
        assert_eq!(parse_epsv("(|||0|)"), None);
        assert_eq!(parse_epsv("(|||70000|)"), None);
        assert_eq!(parse_epsv("no port"), None);
        assert_eq!(parse_pasv("Entering Passive Mode (192,168,1,2,195,80)."), Some(195 * 256 + 80));
        assert_eq!(parse_pasv("Entering Passive Mode 10,0,0,1,0,21"), Some(21));
        assert_eq!(parse_pasv("Entering Passive Mode (192,168,1,2,195)"), None);
        assert_eq!(parse_pasv("Entering Passive Mode (192,168,1,2,300,1)"), None);
        assert_eq!(parse_pasv("(1,2,3,4,0,0)"), None);
    }
}
