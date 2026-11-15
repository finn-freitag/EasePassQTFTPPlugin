//! Settings and the list of databases (no server involved).

use easepass_ftp_database_core::*;
use std::cell::RefCell;
use std::collections::BTreeMap;

#[derive(Default)]
struct MemoryStorage(RefCell<BTreeMap<String, String>>);

impl Storage for MemoryStorage {
    fn get_string(&self, key: &str) -> Result<Option<String>, Error> {
        Ok(self.0.borrow().get(key).cloned())
    }
    fn set_string(&self, key: &str, value: &str) -> Result<(), Error> {
        self.0.borrow_mut().insert(key.into(), value.into());
        Ok(())
    }
}

fn form(mode: &str, host: &str, port: u32, user: &str, password: &str, path: &str, key: &str) -> String {
    serde_json::json!({"mode": mode, "host": host, "port": port, "username": user, "password": password,
        "remote_path": path, "server_key": key})
    .to_string()
}

#[test]
fn defaults_match_the_schema_and_mean_no_database() {
    let storage = MemoryStorage::default();
    let schema: serde_json::Value = serde_json::from_str(CONFIG_SCHEMA).unwrap();
    let default: serde_json::Value = serde_json::from_str(&get_config(&storage).unwrap()).unwrap();
    let properties = schema["properties"].as_object().unwrap();
    assert_eq!(properties.len(), default.as_object().unwrap().len());
    for (key, property) in properties {
        assert_eq!(default[key], property["default"], "{key}");
        assert!(property["propertyOrder"].is_u64(), "{key}");
    }
    assert_eq!(schema["properties"]["password"]["format"], "password");
    assert!(list_databases(&storage).unwrap().is_empty());
    // Saving the untouched form is fine and still means "no database".
    set_config(&storage, &default.to_string()).unwrap();
    assert!(list_databases(&storage).unwrap().is_empty());
    assert_eq!(find_database(&storage, DATABASE_ID).unwrap_err().code, Code::NotFound);
    storage.set_string("config", "damaged").unwrap();
    assert!(list_databases(&storage).unwrap().is_empty());
}

#[test]
fn the_database_is_named_after_file_and_protocol() {
    let storage = MemoryStorage::default();
    set_config(&storage, &form("SFTP", " sftp.example.com ", 0, "me", "pw", " /home/me/Family vault.epdb ", "")).unwrap();
    let databases = list_databases(&storage).unwrap();
    assert_eq!(databases.len(), 1);
    assert_eq!(databases[0].id, DATABASE_ID);
    assert_eq!(databases[0].name, "Family vault (SFTP)");
    assert_eq!(databases[0].description, "sftp://sftp.example.com:22/home/me/Family vault.epdb");
    assert!(!format!("{:?}", databases).contains("pw")); // the password is never part of it
    assert_eq!(find_database(&storage, "other").unwrap_err().code, Code::NotFound);

    set_config(&storage, &form("FTPS", "ftp.example.com", 990, "me", "pw", "vault.epdb", "")).unwrap();
    let database = list_databases(&storage).unwrap().remove(0);
    assert_eq!(database.name, "vault (FTPS)");
    assert_eq!(database.description, "ftps://ftp.example.com:990/vault.epdb");
    set_config(&storage, &form("FTP", "192.168.1.5", 0, "me", "", "/a/b.c.epdb", "")).unwrap();
    let database = list_databases(&storage).unwrap().remove(0);
    assert_eq!(database.name, "b.c (FTP)");
    assert_eq!(database.description, "ftp://192.168.1.5:21/a/b.c.epdb");
}

#[test]
fn settings_that_are_refused() {
    let storage = MemoryStorage::default();
    let good = form("SFTP", "sftp.example.com", 22, "me", "pw", "/vault.epdb", "");
    set_config(&storage, &good).unwrap();
    for bad in [
        form("SFTP", "", 22, "me", "pw", "/vault.epdb", ""),
        form("SFTP", "sftp://sftp.example.com", 22, "me", "pw", "/vault.epdb", ""),
        form("SFTP", "sftp.example.com/path", 22, "me", "pw", "/vault.epdb", ""),
        form("SFTP", "host name", 22, "me", "pw", "/vault.epdb", ""),
        form("SFTP", "sftp.example.com", 22, "", "pw", "/vault.epdb", ""),
        form("SFTP", "sftp.example.com", 22, "me", "pw", "", ""),
        form("SFTP", "sftp.example.com", 22, "me", "pw", "/folder/", ""),
        form("SFTP", "sftp.example.com", 70000, "me", "pw", "/vault.epdb", ""),
        form("SCP", "sftp.example.com", 22, "me", "pw", "/vault.epdb", ""),
        form("SFTP", "sftp.example.com", 22, "me", "pw", "/vault.epdb", "MD5:aa:bb"),
        // A line break would be a second FTP command.
        form("FTP", "ftp.example.com", 21, "me\r\nDELE x", "pw", "/vault.epdb", ""),
        form("FTP", "ftp.example.com", 21, "me", "pw\r\nDELE x", "/vault.epdb", ""),
        form("FTP", "ftp.example.com", 21, "me", "pw", "/vault.epdb\r\nDELE /other", ""),
        form("FTP", "ftp.exa\r\nmple.com", 21, "me", "pw", "/vault.epdb", ""),
        "{}".to_string(),
        "[]".to_string(),
    ] {
        let result = set_config(&storage, &bad);
        assert_eq!(result.map_err(|e| e.code), Err(Code::InvalidArgument), "{bad}");
    }
    // The good settings are still there.
    let value = |json: &str| serde_json::from_str::<serde_json::Value>(json).unwrap();
    assert_eq!(value(&get_config(&storage).unwrap()), value(&good));
}

#[test]
fn the_remembered_server_key_belongs_to_one_server() {
    let storage = MemoryStorage::default();
    let key = "SHA256:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
    set_config(&storage, &form("SFTP", "a.example.com", 22, "me", "pw", "/vault.epdb", key)).unwrap();
    assert_eq!(load_config(&storage).unwrap().server_key, key);
    // Other user, password or path on the same server: the key stays.
    set_config(&storage, &form("SFTP", "a.example.com", 22, "you", "pw2", "/other.epdb", key)).unwrap();
    assert_eq!(load_config(&storage).unwrap().server_key, key);
    // Another server or port: the key the form still carries is dropped ...
    set_config(&storage, &form("SFTP", "b.example.com", 22, "me", "pw", "/vault.epdb", key)).unwrap();
    assert_eq!(load_config(&storage).unwrap().server_key, "");
    set_config(&storage, &form("SFTP", "b.example.com", 22, "me", "pw", "/vault.epdb", key)).unwrap();
    set_config(&storage, &form("SFTP", "b.example.com", 2222, "me", "pw", "/vault.epdb", key)).unwrap();
    assert_eq!(load_config(&storage).unwrap().server_key, "");
    // ... unless the user typed a new one together with the new server.
    let other = "SHA256:ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkj";
    set_config(&storage, &form("SFTP", "c.example.com", 22, "me", "pw", "/vault.epdb", other)).unwrap();
    assert_eq!(load_config(&storage).unwrap().server_key, other);
    // FTP has no such key.
    set_config(&storage, &form("FTP", "c.example.com", 21, "me", "pw", "/vault.epdb", other)).unwrap();
    assert_eq!(load_config(&storage).unwrap().server_key, "");
}
