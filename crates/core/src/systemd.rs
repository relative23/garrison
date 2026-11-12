//! What Garrison's services and commands need of systemd: the path of
//! `systemctl`, and readiness for units of `Type=notify`.
//!
//! systemd counts such a unit as started once the service sends `READY=1` to
//! `$NOTIFY_SOCKET`. A service that exits before that fails its start, which
//! is how the installer notices a release that does not come up.

use std::ffi::OsStr;
use std::io;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};

/// Where every supported distribution has `systemctl`. It is called by this
/// path, never looked up in `PATH`.
pub const SYSTEMCTL: &str = "/usr/bin/systemctl";

/// Tell systemd the service is ready; outside systemd this does nothing.
pub fn ready() {
    if let Some(socket) = std::env::var_os("NOTIFY_SOCKET")
        && let Err(error) = notify(&socket, b"READY=1")
    {
        log::warn!("Could not tell systemd that the service is ready: {error}");
    }
}

/// One datagram to a socket path or, after a leading `@`, an abstract name.
fn notify(socket: &OsStr, message: &[u8]) -> io::Result<()> {
    let address = match socket.as_bytes().strip_prefix(b"@") {
        Some(name) => SocketAddr::from_abstract_name(name)?,
        None => SocketAddr::from_pathname(socket)?,
    };
    UnixDatagram::unbound()?.send_to_addr(message, &address)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::time::Duration;

    use super::*;

    /// The next datagram; one that never comes fails the test within seconds.
    fn received(listener: &UnixDatagram) -> Vec<u8> {
        listener
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut buffer = [0; 16];
        let length = listener.recv(&mut buffer).expect("nothing arrived");
        buffer[..length].to_vec()
    }

    #[test]
    fn readiness_reaches_a_path_and_an_abstract_socket() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("notify");
        let listener = UnixDatagram::bind(&path).unwrap();
        notify(path.as_os_str(), b"READY=1").unwrap();
        assert_eq!(received(&listener), b"READY=1");

        let name = format!("garrison-test-{}", std::process::id());
        let address = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let listener = UnixDatagram::bind_addr(&address).unwrap();
        notify(&OsString::from(format!("@{name}")), b"READY=1").unwrap();
        assert_eq!(received(&listener), b"READY=1");

        // Nobody listening is an error the caller logs, not a panic.
        assert!(notify(directory.path().join("absent").as_os_str(), b"READY=1").is_err());
    }
}
