//! Logic of the plugin, independent of the WebAssembly interface so it can be tested
//! natively: one Ease Pass database file on an FTP, FTPS or SFTP server.
//!
//! The server is only contacted when the database is opened or saved, never when Ease
//! Pass lists the databases. The plugin only ever handles the ENCRYPTED database file.

pub mod ftp;
pub mod net;
pub mod sftp;
pub mod ssh;

use net::Network;
use serde::{Deserialize, Serialize};

pub const PROVIDER_NAME: &str = "FTP, FTPS or SFTP server";
pub const DATABASE_ID: &str = "database";
/// Ease Pass can move about 2.5 MiB of database through a plugin in one call (every byte
/// crosses the plugin boundary twice); 2 MiB is the limit this plugin promises.
pub const MAX_DATABASE_BYTES: usize = 2 * 1024 * 1024;
const KEY_CONFIG: &str = "config";

pub const CONFIG_SCHEMA: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{"mode":{"type":"string","title":"Protocol","description":"SFTP and FTPS are encrypted. With plain FTP your user name and password travel unprotected.","enum":["SFTP","FTPS","FTP"],"default":"SFTP","propertyOrder":1},"host":{"type":"string","title":"Server","description":"For example sftp.example.com","default":"","maxLength":253,"propertyOrder":2},"port":{"type":"integer","title":"Port","description":"0 uses the usual port (SFTP 22, FTP and FTPS 21). With FTPS, port 990 means encryption from the first byte.","minimum":0,"maximum":65535,"default":0,"propertyOrder":3},"username":{"type":"string","title":"User name","default":"","maxLength":255,"propertyOrder":4},"password":{"type":"string","format":"password","title":"Password","default":"","maxLength":1024,"propertyOrder":5},"remote_path":{"type":"string","title":"Path of the database file on the server","description":"For example /home/me/passwords.epdb. The file must already exist there.","default":"","maxLength":1024,"propertyOrder":6},"server_key":{"type":"string","title":"Server key (SFTP)","description":"Filled in after the first successful connection. Ease Pass refuses to log in if the server shows a different key. Empty this field to accept the key the server shows now.","default":"","maxLength":100,"propertyOrder":7}}}"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    InvalidArgument,
    NotFound,
    NotAllowed,
    Unavailable,
    TooLarge,
    Network,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub code: Code,
    pub message: String,
}

impl Error {
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Error { code, message: message.into() }
    }
}

/// The plugin's private settings store in Ease Pass.
pub trait Storage {
    fn get_string(&self, key: &str) -> Result<Option<String>, Error>;
    fn set_string(&self, key: &str, value: &str) -> Result<(), Error>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode {
    #[serde(rename = "SFTP")]
    Sftp,
    #[serde(rename = "FTPS")]
    Ftps,
    #[serde(rename = "FTP")]
    Ftp,
}

impl Mode {
    fn label(self) -> &'static str {
        match self {
            Mode::Sftp => "SFTP",
            Mode::Ftps => "FTPS",
            Mode::Ftp => "FTP",
        }
    }
    fn default_port(self) -> u16 {
        if self == Mode::Sftp { 22 } else { 21 }
    }
}

/// The form of the settings (see CONFIG_SCHEMA), also what is stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub mode: Mode,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub remote_path: String,
    pub server_key: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            mode: Mode::Sftp,
            host: String::new(),
            port: 0,
            username: String::new(),
            password: String::new(),
            remote_path: String::new(),
            server_key: String::new(),
        }
    }
}

/// A checked configuration: where and how to connect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub mode: Mode,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Database {
    pub id: String,
    pub name: String,
    pub description: String,
}

fn invalid(message: impl Into<String>) -> Error {
    Error::new(Code::InvalidArgument, message)
}

impl Config {
    fn is_empty(&self) -> bool {
        self.host.is_empty() && self.username.is_empty() && self.password.is_empty() && self.remote_path.is_empty()
    }

    /// Checks the settings. Control characters are refused everywhere: in FTP a line break
    /// inside a name would be a second command.
    pub fn target(&self) -> Result<Target, Error> {
        let clean = |text: &str| !text.chars().any(|c| c.is_control());
        let host = self.host.trim();
        if host.is_empty() {
            return Err(invalid("the server is missing"));
        }
        let host_ok = host.len() <= 253
            && !host.contains("://")
            && host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'));
        if !host_ok {
            return Err(invalid("the server must be a name or address like sftp.example.com (without sftp:// and without a path)"));
        }
        if self.username.is_empty() || !clean(&self.username) {
            return Err(invalid("the user name is missing or contains characters that are not allowed"));
        }
        if !clean(&self.password) {
            return Err(invalid("the password contains characters that are not allowed"));
        }
        let path = self.remote_path.trim();
        if path.is_empty() || !clean(path) || path.ends_with('/') {
            return Err(invalid("the path must name the database file on the server, for example /home/me/passwords.epdb"));
        }
        Ok(Target {
            mode: self.mode,
            host: host.to_string(),
            port: if self.port == 0 { self.mode.default_port() } else { self.port },
            username: self.username.clone(),
            password: self.password.clone(),
            path: path.to_string(),
        })
    }
}

pub fn load_config(storage: &dyn Storage) -> Result<Config, Error> {
    match storage.get_string(KEY_CONFIG)? {
        None => Ok(Config::default()),
        Some(json) => Ok(serde_json::from_str(&json).unwrap_or_default()),
    }
}

fn store_config(storage: &dyn Storage, config: &Config) -> Result<(), Error> {
    let json = serde_json::to_string(config).map_err(|e| Error::new(Code::Internal, e.to_string()))?;
    storage.set_string(KEY_CONFIG, &json)
}

pub fn get_config(storage: &dyn Storage) -> Result<String, Error> {
    serde_json::to_string(&load_config(storage)?).map_err(|e| Error::new(Code::Internal, e.to_string()))
}

pub fn set_config(storage: &dyn Storage, json: &str) -> Result<(), Error> {
    let mut config: Config =
        serde_json::from_str(json).map_err(|_| invalid("the settings do not have the expected form"))?;
    config.host = config.host.trim().to_string();
    config.remote_path = config.remote_path.trim().to_string();
    config.server_key = config.server_key.trim().to_string();
    if !config.server_key.is_empty() && !config.server_key.starts_with("SHA256:") {
        return Err(invalid("the server key must be empty or look like SHA256:..."));
    }
    // Everything empty = "no database" is fine; anything else must be complete.
    if !config.is_empty() {
        config.target()?;
        // A key belongs to one server: it is forgotten when the server changes.
        let previous = load_config(storage)?;
        let same_server = previous.host == config.host && previous.port == config.port && previous.mode == config.mode;
        if !same_server && config.server_key == previous.server_key {
            config.server_key = String::new();
        }
    }
    if config.mode != Mode::Sftp {
        config.server_key = String::new();
    }
    store_config(storage, &config)
}

fn database_of(target: &Target) -> Database {
    let file = target.path.rsplit('/').next().unwrap_or("");
    let stem = match file.rfind('.') {
        Some(dot) if dot > 0 => &file[..dot],
        _ => file,
    };
    let scheme = target.mode.label().to_ascii_lowercase();
    let slash = if target.path.starts_with('/') { "" } else { "/" };
    Database {
        id: DATABASE_ID.to_string(),
        name: format!("{} ({})", stem.chars().take(80).collect::<String>(), target.mode.label()),
        description: format!("{scheme}://{}:{}{slash}{}", target.host, target.port, target.path),
    }
}

/// The configured database, without contacting the server.
pub fn list_databases(storage: &dyn Storage) -> Result<Vec<Database>, Error> {
    let config = load_config(storage)?;
    Ok(config.target().ok().map(|target| vec![database_of(&target)]).unwrap_or_default())
}

fn target_of(storage: &dyn Storage, id: &str) -> Result<(Config, Target), Error> {
    let config = load_config(storage)?;
    match config.target() {
        Ok(target) if id == DATABASE_ID => Ok((config, target)),
        _ => Err(Error::new(Code::NotFound, "this database is not configured any more")),
    }
}

pub fn find_database(storage: &dyn Storage, id: &str) -> Result<Database, Error> {
    target_of(storage, id).map(|(_, target)| database_of(&target))
}

/// Connects by SFTP. The server's key must be the one remembered from the first
/// connection; the password is only sent after that check.
fn sftp_session<'a>(
    storage: &dyn Storage,
    network: &'a dyn Network,
    config: &Config,
    target: &Target,
) -> Result<sftp::Sftp<'a>, Error> {
    let expected = config.server_key.clone();
    let accept = move |fingerprint: &str| -> Result<(), Error> {
        if expected.is_empty() || expected == fingerprint {
            return Ok(());
        }
        Err(Error::new(
            Code::NotAllowed,
            format!(
                "the server shows a different key ({fingerprint}) than at the first connection ({expected}). Someone may be intercepting the connection; the password was not sent. If the server was set up anew, empty \"Server key\" in the plugin's settings."
            ),
        ))
    };
    let connected = sftp::connect(network, target, &accept)?;
    if config.server_key.is_empty() {
        // First successful login: remember the key from now on.
        let mut updated = config.clone();
        updated.server_key = connected.fingerprint.clone();
        store_config(storage, &updated)?;
    }
    Ok(connected.sftp)
}

pub fn read_database(storage: &dyn Storage, network: &dyn Network, id: &str) -> Result<Vec<u8>, Error> {
    let (config, target) = target_of(storage, id)?;
    let file = match target.mode {
        Mode::Sftp => {
            let mut sftp = sftp_session(storage, network, &config, &target)?;
            let file = sftp.read_file(&target.path);
            sftp.close();
            file?
        }
        Mode::Ftp | Mode::Ftps => {
            let mut ftp = ftp::Ftp::connect(network, &target)?;
            let file = ftp.read_file(&target.path);
            ftp.close();
            file?
        }
    };
    if file.is_empty() {
        return Err(Error::new(Code::Unavailable, "the file on the server is empty"));
    }
    Ok(file)
}

pub fn write_database(storage: &dyn Storage, network: &dyn Network, id: &str, data: &[u8]) -> Result<(), Error> {
    let (config, target) = target_of(storage, id)?;
    if data.is_empty() || data.len() > MAX_DATABASE_BYTES {
        return Err(Error::new(Code::TooLarge, "the database must have between 1 byte and 2 MiB"));
    }
    match target.mode {
        Mode::Sftp => {
            let mut sftp = sftp_session(storage, network, &config, &target)?;
            let result = sftp.write_file(&target.path, data);
            sftp.close();
            result
        }
        Mode::Ftp | Mode::Ftps => {
            let mut ftp = ftp::Ftp::connect(network, &target)?;
            let result = ftp.write_file(&target.path, data);
            ftp.close();
            result
        }
    }
}
