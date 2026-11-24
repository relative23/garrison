//! One SMTP session that hands a test message to the server as a stranger
//! would, every step bounded in time and every reply in length.

use std::io::{BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use garrison_core::time;

use super::message::{Envelope, Test};
use super::{MailTest, Sent};
use crate::context::Context;
pub(super) use crate::smtp::reply;
use crate::smtp::{greeting, host};
use crate::timed::Timed;

/// One step of a session waits this long at most: the connection, one reply.
const TIMEOUT: Duration = Duration::from_secs(10);
/// A session has this long in all, so that a server that sends a line now
/// and then cannot hold the run.
pub(super) const SESSION: Duration = Duration::from_secs(20);
/// `Message queued with id 4b786a616e00000.` names the queue ID in hex; the
/// event history writes it as a number.
pub(super) fn queue_id(reply: &str) -> Option<String> {
    let hex = reply.rsplit_once("with id ")?.1.trim_end_matches('.');
    u64::from_str_radix(hex, 16).ok().map(|id| id.to_string())
}

impl MailTest {
    /// One session that hands `test` to the server, or its copy sent again
    /// where `again`, all of it within the session's time.
    pub(super) fn send(&self, context: &Context<'_>, test: Test, again: bool) -> Sent {
        let failed = |reply: String| Sent {
            reply,
            ..Sent::default()
        };
        let until = Instant::now() + self.session;
        let connected = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .ok()
            .and_then(|mut addresses| addresses.next())
            .ok_or_else(|| "no address".to_owned())
            .and_then(|address| {
                TcpStream::connect_timeout(&address, TIMEOUT.min(self.session))
                    .map_err(|error| error.to_string())
            });
        let stream = match connected {
            Ok(stream) => stream,
            Err(error) => return failed(format!("no session: {error}")),
        };
        let mut reader = BufReader::new(Timed::new(stream, until, TIMEOUT));
        let name = host(&context.deployment.public_origin);
        let message = test.message(&Envelope {
            from: if self.sender.is_empty() {
                &self.recipient
            } else {
                &self.sender
            },
            to: &self.recipient,
            date: time::mail_date(context.now),
            stamp: context.now.as_second(),
            host: name,
            again,
        });
        let steps = [
            (None, 220),
            (Some(format!("EHLO {}\r\n", greeting(name))), 250),
            (Some(format!("MAIL FROM:<{}>\r\n", self.sender)), 250),
            (Some(format!("RCPT TO:<{}>\r\n", self.recipient)), 250),
            (Some("DATA\r\n".to_owned()), 354),
            (Some(message), 250),
        ];
        let mut last = Sent::default();
        for (index, (command, expected)) in steps.iter().enumerate() {
            if let Some(command) = command
                && reader.get_mut().write_all(command.as_bytes()).is_err()
            {
                return failed("the server closed the session".to_owned());
            }
            match reply(&mut reader) {
                Ok((code, said)) => {
                    last = Sent {
                        queue: queue_id(&said).filter(|_| code == 250 && index == 5),
                        reply: said,
                        code,
                        at_data: index == 5,
                        ..Sent::default()
                    };
                    if code != *expected {
                        break;
                    }
                }
                Err(error) => return failed(error),
            }
        }
        let _ = reader.get_mut().write_all(b"QUIT\r\n");
        last
    }
}
