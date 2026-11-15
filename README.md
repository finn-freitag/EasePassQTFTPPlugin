# FTP/FTPS/SFTP Remote Database for Ease Pass Qt

A plugin for [Ease Pass Qt](https://github.com/finn-freitag/EasePassQt) that opens and
saves an Ease Pass database on your own FTP, FTPS or SFTP server. It is the Ease Pass Qt
version of the
[FTP Remote Database plugin](https://github.com/finn-freitag/EasePassFTPDatabaseSourcePlugin)
for the Windows app.

The server only ever receives the encrypted database file. The plugin never sees your
master password.

## Install

In Ease Pass Qt: **Settings > Plugins > Manage**, then install it from the store, or
download `com.finnfreitag.easepass.ftp-database.epplugin` from the
[releases](https://github.com/finn-freitag/EasePassQTDatabaseSourcePlugin/releases) and
choose **Install from file**.

Ease Pass shows what the plugin may do before it installs it: keep its own settings, and
connect to any server (you choose your server, so it cannot be limited to one).

## Settings

**Settings > Plugins > Remote database settings > FTP, FTPS or SFTP server**

| Field | Meaning |
| --- | --- |
| Protocol | `SFTP` (over SSH), `FTPS` (FTP with TLS) or `FTP`. With plain FTP your user name and password travel unprotected. |
| Server | Name or address, e.g. `sftp.example.com` (without `sftp://` and without a path). |
| Port | `0` uses the usual port (SFTP 22, FTP and FTPS 21). With FTPS, port 990 means TLS from the first byte ("implicit"); every other port uses `AUTH TLS` ("explicit"). |
| User name, Password | Your login on the server. |
| Path of the database file on the server | e.g. `/home/me/passwords.epdb`. |
| Server key (SFTP) | Filled in by the plugin, see below. |

**Copy an existing database file to the server first.** The plugin opens and replaces a
file; it does not create the first one.

The database then appears on the login page, named after the file ("passwords (SFTP)").

### The server key (SFTP)

At the first successful login the plugin remembers the fingerprint of the server's key
(the same `SHA256:...` text that `ssh` shows). From then on it refuses to log in, before
sending your password, if the server shows a different key. If you set the server up
anew, empty the field to accept the new key. You can also fill it in yourself before the
first connection (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the server).

## How it works

- **The server is only contacted when you open or save the database**, never when Ease
  Pass lists the databases.
- **Saving never leaves half a database behind.** The plugin uploads to
  `<name>.eptmp` next to the database and renames it over the original. With FTP it
  also asks the server for the size of the upload first and keeps the original if it is
  incomplete.
- **FTP** uses passive mode. The data connection always goes to the server from the
  settings, not to an address the server sends.
- **FTPS** requires an encrypted control and data connection, and a certificate that is
  valid for the server name (checked by Ease Pass; it cannot be switched off).
- **SFTP** is done by an SSH client inside the plugin (see below).

## Limits

- **Size limit: 2 MiB** per database (a limit of how Ease Pass Qt passes data to plugins).
- **One database per plugin** (the Windows plugin takes a list).
- **Login with a password only.** No key files, no second factor.
- **Servers in your own network** (192.168.x.x, a NAS, localhost) are blocked for plugins
  by default. Switch on "local network" for this plugin on the plugin page.
- **FTPS servers that insist on TLS session reuse** for the data connection (the default
  of vsftpd and ProFTPD; `require_ssl_reuse=NO` / `TLSOptions NoSessionReuseRequired`
  switch it off) were not tested and will probably refuse the transfer. Use SFTP there.
- **FTPS with a self-signed certificate** does not work: Ease Pass only accepts
  certificates your system trusts.
- **The password is stored in the plugin's private storage** on your computer, not
  encrypted. Anyone who can read your files can read it.
- **SSH:** key exchange `curve25519-sha256` or `diffie-hellman-group14-sha256`; server
  keys Ed25519, ECDSA P-256 or RSA (2048 bits and more, SHA-2 signatures); encryption
  `chacha20-poly1305@openssh.com`, `aes256-ctr` or `aes128-ctr` with `hmac-sha2-256/512`.
  Very old servers that offer none of these are refused. A server that asks for new keys
  in the middle of a transfer ends the transfer (does not happen with files this small).

## About the SSH code

Ease Pass plugins are WebAssembly and get plain network connections from the app, so the
plugin brings its own small SSH client (`core/src/ssh`) and SFTP client
(`core/src/sftp.rs`). The cryptographic primitives come from the RustCrypto and dalek
crates; the protocol around them is written here and has not been reviewed by anyone
else. What the tests check:

- every supported combination against real servers: OpenSSH (`sshd`) for key exchange,
  server key proof and each cipher, and asyncssh servers for the complete flow with
  Ed25519, ECDSA and RSA keys, both key exchanges, password and keyboard-interactive login
- files of many sizes (1 byte to 2 MiB) read, replaced and read back
- a changed server key, a wrong password and a missing file are refused; a changed key is
  refused before the password is sent
- a packet with one flipped bit, or replayed under another number, is refused for every
  cipher; a signature by another key, over other data or of another kind is refused
- OpenSSH's "strict key exchange" is used when the server offers it

## Build and test

Needs Rust with the `wasm32-unknown-unknown` target, `wasm-tools`, Python 3 and, for the
tests against real servers, `pyftpdlib`, `asyncssh`, `pyopenssl`, `openssl` and OpenSSH;
`nix develop` provides all of them.

```bash
tools/build.sh
```

This runs the tests, builds the WebAssembly component, checks that it has exactly the
plugin type and permissions of `expected.json` and writes
`dist/com.finnfreitag.easepass.ftp-database.epplugin` with its SHA-256. Without the test
servers the server tests are skipped with a note; `EASEPASS_REQUIRE_SERVERS=1` makes that
a failure.

- `core/` the plugin's logic as a normal Rust library, with tests (`cargo test`)
- `core/tests/servers.py` starts the FTP, FTPS and SFTP test servers (also handy for
  trying the plugin by hand)
- `plugin/` the WebAssembly side that connects it to Ease Pass
- `wit/`, `spec/`, `tools/check_component.py`, `tools/package.py` copied from the
  [plugin specification](https://github.com/finn-freitag/easepassqt-plugin-spec)

FTPS needs TLS from the app, so it is tested inside Ease Pass Qt
(`OfficialPluginsTest::testFtpPluginAgainstServers` there runs the packaged plugin against
the FTP, FTPS and SFTP servers of `servers.py`).

## License

MIT
