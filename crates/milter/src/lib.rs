//! The macro milter: Stalwart shows it each incoming message before taking
//! it, and it says whether the message carries an Office document with
//! macros.
//!
//! `scan` reads a message, `protocol` and `server` speak with the mail
//! server, and `sample` makes the harmless document the mail test sends.
//!
//! What the scan does not see: an archive with a password, or one that is
//! no zip archive; macro sheets of Excel 4.0 in an old `.xls` file, which
//! are no VBA project; the macros of an old `.ppt` file, which keeps them
//! compressed inside one of its streams; macros of other office suites'
//! own formats; a document behind a link; and what lies deeper in archives
//! than [`scan::DEPTH`].
//! A message larger than the configured size is taken unscanned.

pub mod protocol;
pub mod sample;
pub mod scan;
pub mod server;

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use garrison_core::config::{Config, MacroAction};

pub use server::Settings;

#[derive(Debug)]
pub enum Error {
    /// The configuration has no `[milter]` section.
    NotConfigured,
    Io(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NotConfigured => write!(formatter, "the configuration has no [milter] section"),
            Error::Io(error) => write!(formatter, "{error}"),
        }
    }
}

/// Listen on loopback for the mail server until the process is stopped.
pub fn run(config: &Config) -> Result<(), Error> {
    let milter = config.milter.as_ref().ok_or(Error::NotConfigured)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, milter.port)).map_err(Error::Io)?;
    log::info!("Macro milter listening on 127.0.0.1:{}", milter.port);
    garrison_core::systemd::ready();
    server::serve(
        &listener,
        Settings {
            tag: milter.action == MacroAction::Tag,
            max_bytes: usize::try_from(milter.max_message_bytes).unwrap_or(usize::MAX),
        },
    );
    Ok(())
}

/// Whether a milter answers on loopback `port`: the opening a mail server
/// sends, and a filter's answer to it. Setup asks this before it tells
/// Stalwart of the filter, and `garrison doctor` to see that it runs.
pub fn answers(port: u16, within: Duration) -> Result<(), String> {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let said = |error: std::io::Error| error.to_string();
    let mut stream = TcpStream::connect_timeout(&address, within).map_err(said)?;
    stream.set_read_timeout(Some(within)).map_err(said)?;
    stream.set_write_timeout(Some(within)).map_err(said)?;
    // Version 6, every action and every step on offer.
    let mut opening = vec![0, 0, 0, 13, b'O'];
    for value in [6_u32, 0x0000_01ff, 0x001f_ffff] {
        opening.extend_from_slice(&value.to_be_bytes());
    }
    stream.write_all(&opening).map_err(said)?;
    let mut answer = [0; 5];
    stream.read_exact(&mut answer).map_err(said)?;
    let _ = stream.write_all(&[0, 0, 0, 1, b'Q']);
    if answer[4] == b'O' {
        Ok(())
    } else {
        Err("what answers there is no milter".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_filter_answers_the_opening_and_nothing_else_passes_for_it() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            server::serve(
                &listener,
                Settings {
                    tag: false,
                    max_bytes: 1024,
                },
            );
        });
        let within = Duration::from_secs(5);
        assert_eq!(answers(port, within), Ok(()));
        // A second time: the first connection's end did not stop the filter.
        assert_eq!(answers(port, within), Ok(()));

        // Something else that listens and answers is no milter.
        let other = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let other_port = other.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut stream, _) = other.accept().unwrap();
            let _ = stream.write_all(b"220 mail.example.test ESMTP\r\n");
        });
        assert_eq!(
            answers(other_port, within),
            Err("what answers there is no milter".to_owned())
        );

        // Nothing listens: the reason is the system's.
        let free = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let free_port = free.local_addr().unwrap().port();
        drop(free);
        assert!(answers(free_port, Duration::from_millis(500)).is_err());
    }
}
