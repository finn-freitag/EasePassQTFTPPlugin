//! The protocols against real servers on this computer: an FTP server (pyftpdlib), SFTP
//! servers with different algorithms (asyncssh) and OpenSSH's sshd.
//!
//! The servers come with `nix develop`. Without them the tests are skipped with a note;
//! set EASEPASS_REQUIRE_SERVERS=1 (as CI does) to make that a failure.

use easepass_ftp_database_core::net::{Connection, Network};
use easepass_ftp_database_core::*;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct StdConnection(TcpStream);

impl Connection for StdConnection {
    fn read(&mut self, max: usize) -> Result<Vec<u8>, Error> {
        let mut buffer = vec![0u8; max];
        let count = self.0.read(&mut buffer).map_err(|e| Error::new(Code::Network, e.to_string()))?;
        buffer.truncate(count);
        Ok(buffer)
    }
    fn write_all(&mut self, data: &[u8]) -> Result<(), Error> {
        self.0.write_all(data).map_err(|e| Error::new(Code::Network, e.to_string()))
    }
    fn start_tls(&mut self) -> Result<(), Error> {
        Err(Error::new(Code::Internal, "no TLS in the native tests (FTPS is tested inside Ease Pass)"))
    }
}

struct StdNetwork;

impl Network for StdNetwork {
    fn connect(&self, host: &str, port: u16, tls: bool) -> Result<Box<dyn Connection>, Error> {
        assert!(!tls);
        let stream = TcpStream::connect((host, port)).map_err(|e| Error::new(Code::Network, e.to_string()))?;
        stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        stream.set_nodelay(true).unwrap();
        Ok(Box::new(StdConnection(stream)))
    }
    fn random(&self, bytes: &mut [u8]) {
        std::fs::File::open("/dev/urandom").unwrap().read_exact(bytes).unwrap();
    }
}

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

struct Servers {
    child: Child,
    root: PathBuf,
    info: serde_json::Value,
}

impl Drop for Servers {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn skip(why: &str) {
    if std::env::var("EASEPASS_REQUIRE_SERVERS").as_deref() == Ok("1") {
        panic!("test servers are required but missing: {why}");
    }
    eprintln!("SKIPPED: {why} (run inside `nix develop`)");
}

fn fresh_directory(name: &str) -> PathBuf {
    let directory = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(directory.join("root")).unwrap();
    directory
}

fn start_servers(name: &str) -> Option<Servers> {
    let directory = fresh_directory(name);
    let root = directory.join("root");
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/servers.py");
    let mut child = match Command::new("python3").arg(script).arg(&root).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn() {
        Ok(child) => child,
        Err(error) => {
            skip(&format!("python3 cannot be started ({error})"));
            return None;
        }
    };
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
    if line.trim().is_empty() {
        let mut errors = String::new();
        child.stderr.take().unwrap().read_to_string(&mut errors).unwrap();
        let _ = child.wait();
        skip(&format!("the test servers did not start: {}", errors.lines().last().unwrap_or("")));
        return None;
    }
    Some(Servers { child, root, info: serde_json::from_str(&line).unwrap() })
}

fn configure(storage: &MemoryStorage, mode: &str, port: u64, password: &str, path: &str, server_key: &str) {
    let json = serde_json::json!({"mode": mode, "host": "127.0.0.1", "port": port, "username": "tester",
        "password": password, "remote_path": path, "server_key": server_key});
    set_config(storage, &json.to_string()).unwrap();
}

fn stored_key(storage: &MemoryStorage) -> String {
    load_config(storage).unwrap().server_key
}

/// Bytes that are not a repeating pattern of the chunk size.
fn content(length: usize) -> Vec<u8> {
    let mut state: u32 = 0x2545F491 ^ length as u32;
    (0..length)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state >> 24) as u8
        })
        .collect()
}

const SIZES: [usize; 8] = [1, 1000, 32 * 1024 - 1, 32 * 1024, 32 * 1024 + 1, 8 * 32 * 1024, 300_001, 2 * 1024 * 1024 - 7];

fn files_in(root: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(root).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
    names.sort();
    names
}

/// Read, replace and read again with files of many sizes; nothing but the database is
/// left on the server.
fn round_trips(storage: &MemoryStorage, root: &Path) {
    let network = StdNetwork;
    for size in SIZES {
        let original = content(size);
        std::fs::write(root.join("vault.epdb"), &original).unwrap();
        assert_eq!(read_database(storage, &network, DATABASE_ID).unwrap(), original, "read {size}");
        let replacement = content(size + 7);
        write_database(storage, &network, DATABASE_ID, &replacement).unwrap();
        assert_eq!(std::fs::read(root.join("vault.epdb")).unwrap(), replacement, "write {size}");
        assert_eq!(read_database(storage, &network, DATABASE_ID).unwrap(), replacement, "read back {size}");
        assert_eq!(files_in(root), ["vault.epdb"], "no temporary file is left");
    }
}

#[test]
fn sftp_with_every_supported_algorithm_set() {
    let Some(servers) = start_servers("sftp-algorithms") else { return };
    for (variant, server) in servers.info["sftp"].as_object().unwrap() {
        eprintln!("-- {variant}");
        let storage = MemoryStorage::default();
        configure(&storage, "SFTP", server["port"].as_u64().unwrap(), "secret pass", "/vault.epdb", "");
        assert_eq!(stored_key(&storage), "");
        round_trips(&storage, &servers.root);
        // The key the server showed at the first login is remembered, in OpenSSH's form.
        assert_eq!(stored_key(&storage), server["fingerprint"].as_str().unwrap(), "{variant}");
    }
}

#[test]
fn sftp_refuses_a_changed_server_key_wrong_passwords_and_missing_files() {
    let Some(servers) = start_servers("sftp-errors") else { return };
    let network = StdNetwork;
    let port = servers.info["sftp"]["default"]["port"].as_u64().unwrap();
    let other_port = servers.info["sftp"]["interactive"]["port"].as_u64().unwrap();
    std::fs::write(servers.root.join("vault.epdb"), b"database").unwrap();

    // Wrong password: reported as such, and the unknown server's key is not remembered.
    let storage = MemoryStorage::default();
    configure(&storage, "SFTP", port, "wrong", "/vault.epdb", "");
    let error = read_database(&storage, &network, DATABASE_ID).unwrap_err();
    assert_eq!(error.code, Code::NotAllowed, "{}", error.message);
    assert!(error.message.contains("user name or password"), "{}", error.message);
    assert_eq!(stored_key(&storage), "");
    let storage = MemoryStorage::default();
    configure(&storage, "SFTP", other_port, "wrong", "/vault.epdb", "");
    assert_eq!(read_database(&storage, &network, DATABASE_ID).unwrap_err().code, Code::NotAllowed);

    // A different key than remembered: refused, for reading and for saving.
    let storage = MemoryStorage::default();
    let pinned = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    configure(&storage, "SFTP", port, "secret pass", "/vault.epdb", pinned);
    let error = read_database(&storage, &network, DATABASE_ID).unwrap_err();
    assert_eq!(error.code, Code::NotAllowed);
    assert!(error.message.contains("different key") && error.message.contains(pinned), "{}", error.message);
    assert_eq!(write_database(&storage, &network, DATABASE_ID, b"x").unwrap_err().code, Code::NotAllowed);
    assert_eq!(std::fs::read(servers.root.join("vault.epdb")).unwrap(), b"database");
    assert_eq!(stored_key(&storage), pinned);
    // Emptying the field accepts the server's current key again.
    configure(&storage, "SFTP", port, "secret pass", "/vault.epdb", "");
    assert_eq!(read_database(&storage, &network, DATABASE_ID).unwrap(), b"database");
    assert_eq!(stored_key(&storage), servers.info["sftp"]["default"]["fingerprint"].as_str().unwrap());

    // Missing file; saving into a missing folder leaves nothing behind.
    configure(&storage, "SFTP", port, "secret pass", "/nothing.epdb", &stored_key(&storage));
    assert_eq!(read_database(&storage, &network, DATABASE_ID).unwrap_err().code, Code::NotFound);
    configure(&storage, "SFTP", port, "secret pass", "/missing/vault.epdb", &stored_key(&storage));
    assert!(write_database(&storage, &network, DATABASE_ID, b"x").is_err());
    assert_eq!(files_in(&servers.root), ["vault.epdb"]);
    // An empty file is not handed to Ease Pass as a database.
    std::fs::write(servers.root.join("empty.epdb"), b"").unwrap();
    configure(&storage, "SFTP", port, "secret pass", "/empty.epdb", &stored_key(&storage));
    assert_eq!(read_database(&storage, &network, DATABASE_ID).unwrap_err().code, Code::Unavailable);

    // Not an SSH server at all (the FTP port).
    configure(&storage, "SFTP", servers.info["ftp"].as_u64().unwrap(), "secret pass", "/vault.epdb", "");
    assert_eq!(read_database(&storage, &network, DATABASE_ID).unwrap_err().code, Code::Network);
}

/// A server without OpenSSH's "posix-rename": the database is still replaced.
#[test]
fn sftp_replaces_the_file_without_the_rename_extension() {
    let Some(servers) = start_servers("sftp-rename") else { return };
    let target = Target {
        mode: Mode::Sftp,
        host: "127.0.0.1".into(),
        port: servers.info["sftp"]["default"]["port"].as_u64().unwrap() as u16,
        username: "tester".into(),
        password: "secret pass".into(),
        path: "/vault.epdb".into(),
    };
    std::fs::write(servers.root.join("vault.epdb"), b"old").unwrap();
    let network = StdNetwork;
    let mut connected = sftp::connect(&network, &target, &|_| Ok(())).unwrap();
    connected.sftp.without_posix_rename();
    connected.sftp.write_file("/vault.epdb", b"new content").unwrap();
    connected.sftp.write_file("/fresh.epdb", b"first version").unwrap(); // no file to replace
    connected.sftp.close();
    assert_eq!(std::fs::read(servers.root.join("vault.epdb")).unwrap(), b"new content");
    assert_eq!(files_in(&servers.root), ["fresh.epdb", "vault.epdb"]);
    // The check of the key happens before the login: a refusal ends the connection.
    let refused = sftp::connect(&network, &target, &|_| Err(Error::new(Code::NotAllowed, "no")));
    assert_eq!(refused.err().unwrap().message, "no");
}

#[test]
fn ftp_round_trips_and_errors() {
    let Some(servers) = start_servers("ftp") else { return };
    let network = StdNetwork;
    let port = servers.info["ftp"].as_u64().unwrap();
    let storage = MemoryStorage::default();
    configure(&storage, "FTP", port, "secret pass", "/vault.epdb", "");
    round_trips(&storage, &servers.root);
    // A path without leading slash is relative to the login folder.
    configure(&storage, "FTP", port, "secret pass", "vault.epdb", "");
    assert_eq!(read_database(&storage, &network, DATABASE_ID).unwrap().len(), SIZES[7] + 7);

    configure(&storage, "FTP", port, "wrong", "/vault.epdb", "");
    let error = read_database(&storage, &network, DATABASE_ID).unwrap_err();
    assert_eq!(error.code, Code::NotAllowed, "{}", error.message);
    configure(&storage, "FTP", port, "secret pass", "/nothing.epdb", "");
    assert_eq!(read_database(&storage, &network, DATABASE_ID).unwrap_err().code, Code::NotFound);
    let before = std::fs::read(servers.root.join("vault.epdb")).unwrap();
    configure(&storage, "FTP", port, "secret pass", "/missing/vault.epdb", "");
    assert!(write_database(&storage, &network, DATABASE_ID, b"x").is_err());
    assert_eq!(files_in(&servers.root), ["vault.epdb"]);
    assert_eq!(std::fs::read(servers.root.join("vault.epdb")).unwrap(), before);

    // FTPS against a server without TLS: refused before the password is sent.
    configure(&storage, "FTPS", port, "secret pass", "/vault.epdb", "");
    let error = read_database(&storage, &network, DATABASE_ID).unwrap_err();
    // (pyftpdlib's plain handler answers AUTH with 500.)
    assert!(error.message.contains("does not offer FTPS") && error.message.contains("password was not sent"), "{}", error.message);
    // Not an FTP server at all (an SSH port).
    configure(&storage, "FTP", servers.info["sftp"]["default"]["port"].as_u64().unwrap(), "secret pass", "/vault.epdb", "");
    assert_eq!(read_database(&storage, &network, DATABASE_ID).unwrap_err().code, Code::Network);
}

/// OpenSSH's own server. Without root it cannot check passwords, so this goes as far as
/// OpenSSH allows: version exchange, key exchange, host key proof, encrypted packets in
/// both directions (the login request and its refusal), for every cipher of this plugin.
#[test]
fn openssh_key_exchange_and_encryption() {
    let directory = fresh_directory("openssh");
    let key = directory.join("host_key");
    let keygen = Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", ""]).arg("-f").arg(&key).status();
    let sshd = Command::new("sh").args(["-c", "command -v sshd"]).output().ok().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    let (Ok(_), Some(sshd)) = (keygen, sshd.filter(|path| !path.is_empty())) else {
        skip("OpenSSH (sshd, ssh-keygen) is not installed");
        return;
    };
    let listed = Command::new("ssh-keygen").arg("-lf").arg(key.with_extension("pub")).output().unwrap();
    let listed = String::from_utf8_lossy(&listed.stdout).into_owned();
    let expected_fingerprint = listed.split_whitespace().nth(1).unwrap().to_string();

    let cases = [
        ("curve25519-sha256", "chacha20-poly1305@openssh.com", "hmac-sha2-256"),
        ("curve25519-sha256", "aes256-ctr", "hmac-sha2-256"),
        ("curve25519-sha256", "aes128-ctr", "hmac-sha2-512"),
        ("diffie-hellman-group14-sha256", "aes256-ctr", "hmac-sha2-512"),
        ("diffie-hellman-group14-sha256", "chacha20-poly1305@openssh.com", "hmac-sha2-256"),
    ];
    for (index, (kex, cipher, mac)) in cases.iter().enumerate() {
        let port = 20000 + (std::process::id() % 20000) as u16 + index as u16;
        let mut server = Command::new(&sshd)
            .args(["-D", "-e", "-f", "/dev/null", "-p", &port.to_string(), "-h"])
            .arg(&key)
            .args(["-o", "ListenAddress=127.0.0.1", "-o", "UsePAM=no", "-o", "PidFile=none", "-o", "StrictModes=no"])
            .args(["-o", &format!("KexAlgorithms={kex}"), "-o", &format!("Ciphers={cipher}"), "-o", &format!("MACs={mac}")])
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut session = None;
        for _ in 0..100 {
            match ssh::Session::connect(&StdNetwork, "127.0.0.1", port) {
                Ok(connected) => {
                    session = Some(Ok(connected));
                    break;
                }
                Err(error) if error.message.contains("refused") => std::thread::sleep(Duration::from_millis(50)),
                Err(error) => {
                    session = Some(Err(error));
                    break;
                }
            }
        }
        let result = (|| {
            let mut session = session.expect("sshd did not start")?;
            assert_eq!(session.host_key_fingerprint(), expected_fingerprint, "{kex} {cipher}");
            // Encrypted both ways: OpenSSH understands the request and we its answer.
            session.login("nobody-like-this", "wrong")
        })();
        let _ = server.kill();
        let _ = server.wait();
        let error = result.expect_err("a wrong password cannot log in");
        assert_eq!(error.code, Code::NotAllowed, "{kex} {cipher} {mac}: {}", error.message);
    }
}
