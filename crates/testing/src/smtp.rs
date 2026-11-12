//! A minimal SMTP client for the contract tests' lab mail.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

#[derive(Debug)]
pub struct Smtp {
    reader: BufReader<TcpStream>,
}

impl Smtp {
    /// Connect to port 25 and read the greeting, which must be 220.
    pub fn connect(host: &str) -> Smtp {
        let stream = TcpStream::connect((host, 25)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        let mut smtp = Smtp {
            reader: BufReader::new(stream),
        };
        let greeting = smtp.reply();
        assert!(greeting.starts_with("220"), "{greeting}");
        smtp
    }

    /// The last line of a (possibly multi-line) reply.
    pub fn reply(&mut self) -> String {
        loop {
            let mut text = String::new();
            self.reader.read_line(&mut text).unwrap();
            if text.as_bytes().get(3) != Some(&b'-') {
                return text;
            }
        }
    }

    /// One command and the last line of its reply.
    pub fn command(&mut self, line: &str) -> String {
        self.reader
            .get_mut()
            .write_all(format!("{line}\r\n").as_bytes())
            .unwrap();
        self.reply()
    }

    /// Send one message; every step must succeed.
    pub fn send(&mut self, from: &str, to: &str, message: &str) {
        for (line, code) in [
            ("EHLO contract.example.net".to_owned(), "250"),
            (format!("MAIL FROM:<{from}>"), "250"),
            (format!("RCPT TO:<{to}>"), "250"),
            ("DATA".to_owned(), "354"),
        ] {
            let reply = self.command(&line);
            assert!(reply.starts_with(code), "{line}: {reply}");
        }
        let reply = self.command(&format!("{message}\r\n."));
        assert!(reply.starts_with("250"), "DATA: {reply}");
    }
}
