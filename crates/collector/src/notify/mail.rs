//! A notification as mail, submitted the way a mail program does it: signed
//! in as an account of the mail server, over TLS on the submission port.
//!
//! Mail handed to port 25 without signing in is a stranger's mail to the
//! server, and its spam filter files it accordingly. A message the server's
//! own account submits is delivered like any other of that account.

use std::io::{BufRead, BufReader, Read, Write};
use std::sync::Arc;
use std::time::Instant;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use garrison_core::time;
use rustls::RootCertStore;
use serde::{Deserialize, Serialize};

use super::secrets::Secret;
use crate::fetch::{WITHIN, secure_stream_until, tls_error};

/// Where the mail goes and who submits it.
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Mail {
    /// The mail server's name, as its certificate names it.
    pub host: String,
    /// The port for submission with TLS from the first byte.
    pub port: u16,
    pub user: String,
    /// Read from its credential, never kept with the rest.
    #[serde(skip)]
    pub password: Secret,
    pub from: String,
    pub to: String,
}

impl std::fmt::Debug for Mail {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The password stays out of logs and panic messages.
        formatter
            .debug_struct("Mail")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("from", &self.from)
            .field("to", &self.to)
            .finish_non_exhaustive()
    }
}

/// The longest line of a reply that is read.
const LONGEST: usize = 2048;

/// One reply of the server: its code and its last line. A line is read up to
/// `LONGEST`, so that a server that sends no end of line cannot fill memory.
fn reply(reader: &mut impl BufRead) -> Result<(u16, String), String> {
    loop {
        let mut data = Vec::new();
        let read = reader
            .take(LONGEST as u64 + 1)
            .read_until(b'\n', &mut data)
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

/// A header's value on one line; text beyond ASCII as an encoded word.
fn header(value: &str) -> String {
    let line: String = value
        .chars()
        .filter(|character| !character.is_control())
        .collect();
    if line.is_ascii() {
        line
    } else {
        format!("=?utf-8?B?{}?=", STANDARD.encode(line))
    }
}

/// A display name as one word: a quoted string, since a phrase of atoms
/// takes no colon or bracket, which a port and an IPv6 address bring (RFC
/// 5322, 3.2.3), or an encoded word for text beyond ASCII, which may not
/// stand within one (RFC 2047, 5).
fn display_name(value: &str) -> String {
    let line: String = value
        .chars()
        .filter(|character| !character.is_control())
        .collect();
    if line.is_ascii() {
        format!("\"{}\"", line.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        header(&line)
    }
}

/// This installation's host from `name`, as `public_origin` names it,
/// without its port: a greeting and a Message-ID name a host, never a port
/// (RFC 5321, 4.1.1.1; RFC 5322, 3.6.4).
fn host_name(name: &str) -> &str {
    match name.strip_prefix('[') {
        // An IPv6 address keeps the colons inside its brackets.
        Some(rest) => rest.find(']').map_or(name, |end| &name[..end + 2]),
        None => name.rsplit_once(':').map_or(name, |(host, _)| host),
    }
}

/// The message: its text in base64, so that any character and any length of
/// line arrives as it was written.
pub fn message(mail: &Mail, name: &str, subject: &str, text: &str, now: time::Timestamp) -> String {
    let encoded = STANDARD.encode(text);
    let lines: Vec<&str> = encoded
        .as_bytes()
        .chunks(76)
        .filter_map(|chunk| std::str::from_utf8(chunk).ok())
        .collect();
    format!(
        "From: {sender} <{from}>\r\nTo: <{to}>\r\nSubject: {subject}\r\nDate: {date}\r\n\
         Message-ID: <{stamp}.{unique:08x}@{host}>\r\nAuto-Submitted: auto-generated\r\n\
         MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Transfer-Encoding: base64\r\n\r\n{body}\r\n",
        host = host_name(name),
        sender = display_name(&format!("Garrison on {name}")),
        from = mail.from,
        to = mail.to,
        subject = header(subject),
        date = time::mail_date(now),
        stamp = now.as_second(),
        unique = encoded.bytes().fold(0u32, |sum, byte| sum
            .wrapping_mul(31)
            .wrapping_add(u32::from(byte))),
        body = lines.join("\r\n"),
    )
}

/// Submit one message. `name` is this installation's own host name.
pub fn submit(
    mail: &Mail,
    name: &str,
    subject: &str,
    text: &str,
    now: time::Timestamp,
    roots: &Arc<RootCertStore>,
) -> Result<(), String> {
    let until = Instant::now() + WITHIN;
    submit_until(mail, name, subject, text, now, roots, until)
}

/// The same, with the whole session done by `until`.
pub fn submit_until(
    mail: &Mail,
    name: &str,
    subject: &str,
    text: &str,
    now: time::Timestamp,
    roots: &Arc<RootCertStore>,
    until: Instant,
) -> Result<(), String> {
    // A password that cannot be used is said before anything is sent.
    mail.password.text()?;
    let stream = secure_stream_until(&mail.host, mail.port, roots, until)?;
    submit_over(stream, mail, name, &message(mail, name, subject, text, now))
}

/// The session itself, over a stream that is already secure: greeting,
/// sign-in, envelope and `message`.
pub fn submit_over(
    stream: impl Read + Write,
    mail: &Mail,
    name: &str,
    message: &str,
) -> Result<(), String> {
    let mut session = BufReader::new(stream);
    let login = STANDARD.encode(format!("\0{}\0{}", mail.user, mail.password.text()?));
    let steps = [
        (None, 220, "greet"),
        (Some(format!("EHLO {}\r\n", host_name(name))), 250, "greet"),
        (Some(format!("AUTH PLAIN {login}\r\n")), 235, "sign in"),
        (
            Some(format!("MAIL FROM:<{}>\r\n", mail.from)),
            250,
            "take the sender",
        ),
        (
            Some(format!("RCPT TO:<{}>\r\n", mail.to)),
            250,
            "take the recipient",
        ),
        (Some("DATA\r\n".to_owned()), 354, "take the message"),
        (Some(format!("{message}.\r\n")), 250, "take the message"),
    ];
    for (command, expected, step) in steps {
        if let Some(command) = command {
            let sent = session.get_mut().write_all(command.as_bytes());
            sent.and_then(|()| session.get_mut().flush())
                .map_err(|error| tls_error(&error))?;
        }
        let (code, said) = reply(&mut session)?;
        if code != expected {
            // What the server says to a sign-in may quote it; the code is enough.
            return Err(if step == "sign in" {
                format!("the mail server did not {step} ({code})")
            } else {
                format!("the mail server did not {step}: {said}")
            });
        }
    }
    let _ = session.get_mut().write_all(b"QUIT\r\n");
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;
