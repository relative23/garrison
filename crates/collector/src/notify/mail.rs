//! A notification as mail, submitted the way a mail program does it: signed
//! in as an account of the mail server, over TLS on the submission port.
//!
//! Mail handed to port 25 without signing in is a stranger's mail to the
//! server, and its spam filter files it accordingly. A message the server's
//! own account submits is delivered like any other of that account.

use std::io::{BufRead, BufReader, Read, Write};
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use garrison_core::time;
use rustls::RootCertStore;
use serde::{Deserialize, Serialize};

use crate::fetch::{secure_stream, tls_error};

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
    pub password: String,
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

/// One reply of the server: its code and its last line.
fn reply(reader: &mut impl BufRead) -> Result<(u16, String), String> {
    loop {
        let mut line = String::new();
        let read = reader
            .read_line(&mut line)
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::InvalidData | std::io::ErrorKind::Other => tls_error(&error),
                _ => error.to_string(),
            })?;
        if read == 0 || line.len() > 2048 {
            return Err("the server closed the session".to_owned());
        }
        let line = line.trim_end();
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
         Message-ID: <{stamp}.{unique:08x}@{name}>\r\nAuto-Submitted: auto-generated\r\n\
         MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Transfer-Encoding: base64\r\n\r\n{body}\r\n",
        sender = header(&format!("Garrison on {name}")),
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
    let stream = secure_stream(&mail.host, mail.port, roots)?;
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
    let login = STANDARD.encode(format!("\0{}\0{}", mail.user, mail.password));
    let steps = [
        (None, 220, "greet"),
        (Some(format!("EHLO {name}\r\n")), 250, "greet"),
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
