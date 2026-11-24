//! What a session with a mail server reads and says alike wherever Garrison
//! sends mail: the mail test and the notifications by mail.

use std::io::{BufRead, Read};

use crate::fetch::tls_error;

/// The longest line of a reply that is read.
const LONGEST: usize = 2048;

/// One reply of the server: its code and its last line. A line is read up to
/// `LONGEST`, so that a server that sends no end of line cannot fill memory.
pub fn reply(reader: &mut impl BufRead) -> Result<(u16, String), String> {
    loop {
        let mut data = Vec::new();
        let read = reader
            .take(LONGEST as u64 + 1)
            .read_until(b'\n', &mut data)
            // Over TLS, why TLS failed; any other error as it is.
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::InvalidData | std::io::ErrorKind::Other => tls_error(&error),
                _ => error.to_string(),
            })?;
        if read == 0 {
            return Err("the server closed the session".to_owned());
        }
        if read > LONGEST {
            return Err("the server's reply is too long".to_owned());
        }
        let text = String::from_utf8_lossy(&data);
        let line = text.trim_end();
        let code: u16 = line
            .get(..3)
            .and_then(|code| code.parse().ok())
            .ok_or("the server's reply is no SMTP reply")?;
        // `250-` goes on, `250 ` ends the reply.
        if line.as_bytes().get(3) != Some(&b'-') {
            return Ok((code, line.chars().take(200).collect()));
        }
    }
}

/// This installation's host as `public_origin` names it, without its
/// scheme and port: a greeting and a Message-ID name a host, never a port
/// (RFC 5321, 4.1.1.1; RFC 5322, 3.6.4). An IPv6 address keeps its brackets.
#[must_use]
pub fn host(origin: &str) -> &str {
    let name = origin.split_once("://").map_or(origin, |(_, name)| name);
    match name.strip_prefix('[') {
        Some(rest) => rest.find(']').map_or(name, |end| &name[..end + 2]),
        None => name.rsplit_once(':').map_or(name, |(host, _)| host),
    }
}

/// What a session greets with: the host, or an address as an address
/// literal, `[192.0.2.1]` or `[IPv6:2001:db8::1]` (RFC 5321, 4.1.3).
#[must_use]
pub fn greeting(host: &str) -> String {
    match host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        Some(address) => format!("[IPv6:{address}]"),
        None if host.parse::<std::net::Ipv4Addr>().is_ok() => format!("[{host}]"),
        None => host.to_owned(),
    }
}
