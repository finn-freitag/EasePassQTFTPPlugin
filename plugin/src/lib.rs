//! WebAssembly side of the plugin: connects `easepass_ftp_database_core` to the plugin
//! interface of Ease Pass Qt (easepass:plugin@1, type `database-source`).

wit_bindgen::generate!({
    path: "../wit",
    world: "easepass:plugin/database-source-plugin",
    generate_all,
});

use easepass::plugin::network::{tcp_close, tcp_connect, tcp_read, tcp_start_tls, tcp_write, TcpOptions};
use easepass::plugin::storage;
use easepass::plugin::types::{Error, ErrorCode};
use easepass_ftp_database_core as core;
use exports::easepass::plugin::database_source::{Availability, DatabaseInfo, Guest};

struct Plugin;
struct WasmStorage;
struct WasmNetwork;
struct WasmConnection(u32);

const TIMEOUT_MS: u32 = 30_000;

fn from_host(error: Error) -> core::Error {
    let code = match error.code {
        ErrorCode::InvalidArgument => core::Code::InvalidArgument,
        ErrorCode::NotFound => core::Code::NotFound,
        ErrorCode::NotAllowed => core::Code::NotAllowed,
        ErrorCode::TooLarge => core::Code::TooLarge,
        ErrorCode::Network | ErrorCode::Timeout => core::Code::Network,
        ErrorCode::Unavailable => core::Code::Unavailable,
        _ => core::Code::Internal,
    };
    core::Error::new(code, error.message)
}

fn to_host(error: core::Error) -> Error {
    let code = match error.code {
        core::Code::InvalidArgument => ErrorCode::InvalidArgument,
        core::Code::NotFound => ErrorCode::NotFound,
        core::Code::NotAllowed => ErrorCode::NotAllowed,
        core::Code::Unavailable => ErrorCode::Unavailable,
        core::Code::TooLarge => ErrorCode::TooLarge,
        core::Code::Network => ErrorCode::Network,
        core::Code::Internal => ErrorCode::Internal,
    };
    Error { code, message: error.message }
}

impl core::Storage for WasmStorage {
    fn get_string(&self, key: &str) -> Result<Option<String>, core::Error> {
        storage::get_string(key).map_err(from_host)
    }
    fn set_string(&self, key: &str, value: &str) -> Result<(), core::Error> {
        storage::set_string(key, value).map_err(from_host)
    }
}

impl core::net::Connection for WasmConnection {
    fn read(&mut self, max: usize) -> Result<Vec<u8>, core::Error> {
        tcp_read(self.0, max as u32).map_err(from_host)
    }
    fn write_all(&mut self, data: &[u8]) -> Result<(), core::Error> {
        let mut rest = data;
        while !rest.is_empty() {
            let written = tcp_write(self.0, rest).map_err(from_host)? as usize;
            if written == 0 || written > rest.len() {
                return Err(core::Error::new(core::Code::Network, "the connection does not accept data"));
            }
            rest = &rest[written..];
        }
        Ok(())
    }
    fn start_tls(&mut self) -> Result<(), core::Error> {
        tcp_start_tls(self.0).map_err(from_host)
    }
}

impl Drop for WasmConnection {
    fn drop(&mut self) {
        tcp_close(self.0);
    }
}

impl core::net::Network for WasmNetwork {
    fn connect(&self, host: &str, port: u16, tls: bool) -> Result<Box<dyn core::net::Connection>, core::Error> {
        let handle = tcp_connect(host, port, TcpOptions { tls, timeout_ms: Some(TIMEOUT_MS) }).map_err(from_host)?;
        Ok(Box::new(WasmConnection(handle)))
    }
    fn random(&self, bytes: &mut [u8]) {
        let random = wasi::random::random::get_random_bytes(bytes.len() as u64);
        // Never continue with predictable "random" bytes.
        assert_eq!(random.len(), bytes.len(), "the host returned too few random bytes");
        bytes.copy_from_slice(&random);
    }
}

fn info(database: core::Database) -> DatabaseInfo {
    DatabaseInfo {
        id: database.id,
        name: database.name,
        description: database.description,
        read_only: false,
        // Not asked here: listing must not use the network.
        availability: Availability::Unknown,
        last_modified: None,
    }
}

impl Guest for Plugin {
    fn config_schema() -> String {
        core::CONFIG_SCHEMA.into()
    }
    fn get_config() -> Result<String, Error> {
        core::get_config(&WasmStorage).map_err(to_host)
    }
    fn set_config(config_json: String) -> Result<(), Error> {
        core::set_config(&WasmStorage, &config_json).map_err(to_host)
    }
    fn list_databases() -> Result<Vec<DatabaseInfo>, Error> {
        Ok(core::list_databases(&WasmStorage).map_err(to_host)?.into_iter().map(info).collect())
    }
    fn get_database(id: String) -> Result<DatabaseInfo, Error> {
        core::find_database(&WasmStorage, &id).map(info).map_err(to_host)
    }
    fn read_database(id: String) -> Result<Vec<u8>, Error> {
        core::read_database(&WasmStorage, &WasmNetwork, &id).map_err(to_host)
    }
    fn write_database(id: String, data: Vec<u8>) -> Result<(), Error> {
        core::write_database(&WasmStorage, &WasmNetwork, &id, &data).map_err(to_host)
    }
    fn login(id: String) -> Result<(), Error> {
        core::find_database(&WasmStorage, &id).map(|_| ()).map_err(to_host)
    }
    fn logout(_id: String) -> Result<(), Error> {
        Ok(())
    }
}

export!(Plugin);
