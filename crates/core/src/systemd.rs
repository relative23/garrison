//! What Garrison's services and commands need of systemd: the path of
//! `systemctl`, readiness for units of `Type=notify`, and more time for a
//! oneshot unit's long step.
//!
//! systemd counts such a unit as started once the service sends `READY=1` to
//! `$NOTIFY_SOCKET`. A service that exits before that fails its start, which
//! is how the installer notices a release that does not come up.

use std::ffi::OsStr;
use std::io;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::time::Duration;

/// Where every supported distribution has `systemctl`. Whatever starts,
/// stops or changes units calls it by this path, so that no other
/// `systemctl` earlier in `PATH` takes part. The read-only questions of
/// `detect` and of the host-care check still find it in `PATH`, as they find
/// their other programs.
pub const SYSTEMCTL: &str = "/usr/bin/systemctl";

/// Tell systemd the service is ready; outside systemd this does nothing.
pub fn ready() {
    if let Some(socket) = std::env::var_os("NOTIFY_SOCKET")
        && let Err(error) = notify(&socket, b"READY=1")
    {
        log::warn!("Could not tell systemd that the service is ready: {error}");
    }
}

/// Ask systemd to end the unit's start no sooner than `by` from now, as a
/// oneshot unit's long step does, again before that time is up. The unit
/// must take the message (`NotifyAccess=main`); outside systemd, and where
/// it is not taken, its own time stands.
pub fn extend_timeout(by: Duration) {
    if let Some(socket) = std::env::var_os("NOTIFY_SOCKET")
        && let Err(error) = notify(&socket, &extended(by))
    {
        log::warn!("Could not ask systemd for more time: {error}");
    }
}

/// The message that asks for `by` more.
fn extended(by: Duration) -> Vec<u8> {
    format!("EXTEND_TIMEOUT_USEC={}", by.as_micros()).into_bytes()
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
        let mut buffer = [0; 64];
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

    /// systemd reads the time in whole microseconds (`sd_notify(3)`).
    #[test]
    fn more_time_is_asked_in_microseconds() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("notify");
        let listener = UnixDatagram::bind(&path).unwrap();
        notify(path.as_os_str(), &extended(Duration::from_secs(60))).unwrap();
        assert_eq!(received(&listener), b"EXTEND_TIMEOUT_USEC=60000000");
    }
}
