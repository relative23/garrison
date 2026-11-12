//! Test messages through the mail server itself: the antivirus test file
//! (EICAR) and the spam test text (GTUBE).
//!
//! Only where an operator names a recipient. At most once in the configured
//! hours, the provider hands both to the local SMTP listener the way a
//! stranger would, without signing in. A scanner must refuse the test file
//! while the session lasts. The spam text is refused there too, or accepted
//! and then filed as spam, which the event history shows under the queue ID
//! Stalwart named. Stalwart knows the spam text only as a message's subject
//! (a text in the body is ordinary mail to it), so the test message carries it
//! there and in the body, where other filters look. A test that goes wrong
//! leaves a harmless message in the recipient's mailbox, which is why that
//! mailbox is one made for it.
//!
//! Where the operator switches it on (`macro_document = true`), a third
//! message carries a document that a macro filter such as Garrison's milter
//! takes for one with macros; it must be refused like the test file.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use garrison_core::modules::ModuleId;
use garrison_core::observations::{Column, Evidence, Format, Observation, State, Table};
use garrison_core::sqlite::reading;
use garrison_core::time;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::context::{Collected, Context, Provider, Report};
use crate::options::{Checked, Options, fail};
use message::{Envelope, Test};

mod message;

const TIMEOUT: Duration = Duration::from_secs(10);
const MEMORY: &str = "mailtest";
/// How long Stalwart may take to file an accepted message.
const VERDICT_WITHIN: i64 = 900;

/// How the server answered one test, as the status database keeps it.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
struct Sent {
    /// The last reply of the session, or why there was none.
    reply: String,
    /// The reply's code; 0 if the session did not get that far.
    code: u16,
    /// The queue ID of an accepted message, as the event history writes it.
    queue: Option<String>,
    /// Whether the refusal came for the message itself, not earlier.
    at_data: bool,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
struct Kept {
    at: i64,
    eicar: Sent,
    gtube: Sent,
    /// The macro test, where the operator switched it on.
    #[serde(default)]
    macros: Option<Sent>,
}

#[derive(Debug)]
pub struct MailTest {
    recipient: String,
    sender: String,
    host: String,
    port: u16,
    every: i64,
    /// Whether the test document for a macro filter is sent too.
    macros: bool,
}

/// One reply of the server: its code and its last line.
fn reply(reader: &mut impl BufRead) -> Result<(u16, String), String> {
    loop {
        let mut line = String::new();
        let read = reader
            .read_line(&mut line)
            .map_err(|error| error.to_string())?;
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

/// `Message queued with id 4b786a616e00000.` names the queue ID in hex; the
/// event history writes it as a number.
fn queue_id(reply: &str) -> Option<String> {
    let hex = reply.rsplit_once("with id ")?.1.trim_end_matches('.');
    u64::from_str_radix(hex, 16).ok().map(|id| id.to_string())
}

impl MailTest {
    pub fn new(raw: &toml::Table) -> Checked<Self> {
        let options = Options::new(
            raw,
            &[
                "recipient",
                "sender",
                "host",
                "port",
                "every_hours",
                "macro_document",
            ],
        )?;
        let address = |text: &str| {
            text.len() <= 254
                && text.split_once('@').is_some_and(|(local, domain)| {
                    !local.is_empty()
                        && domain.contains('.')
                        && text.bytes().all(|byte| {
                            byte.is_ascii_graphic() && !b"<>\"\\,;:()[]".contains(&byte)
                        })
                })
        };
        let recipient = options.text("recipient", None)?;
        if !address(&recipient) {
            return fail("providers[mail-test].recipient must be a mail address");
        }
        let sender = options.optional_text("sender")?.unwrap_or_default();
        if !sender.is_empty() && !address(&sender) {
            return fail("providers[mail-test].sender must be a mail address");
        }
        let host = options.text("host", Some("127.0.0.1"))?;
        // An address, never a name to look up: the test messages go to the
        // mail server of this host, wherever on it that listens.
        if host != "localhost" && host.parse::<std::net::IpAddr>().is_err() {
            return fail("providers[mail-test].host must be an IP address of this host");
        }
        Ok(MailTest {
            recipient,
            sender,
            host,
            port: u16::try_from(options.integer("port", 25, 1, 65535)?).unwrap_or(25),
            every: options.integer("every_hours", 24, 1, 168)? * 3600,
            macros: options.flag("macro_document", false)?,
        })
    }

    /// One session that hands `test` to the server.
    fn send(&self, context: &Context<'_>, test: Test) -> Sent {
        let failed = |reply: String| Sent {
            reply,
            ..Sent::default()
        };
        let connected = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .ok()
            .and_then(|mut addresses| addresses.next())
            .ok_or_else(|| "no address".to_owned())
            .and_then(|address| {
                TcpStream::connect_timeout(&address, TIMEOUT).map_err(|error| error.to_string())
            });
        let stream = match connected {
            Ok(stream) => stream,
            Err(error) => return failed(format!("no session: {error}")),
        };
        let _ = stream.set_read_timeout(Some(TIMEOUT));
        let _ = stream.set_write_timeout(Some(TIMEOUT));
        let Ok(mut writer) = stream.try_clone() else {
            return failed("no session".to_owned());
        };
        let mut reader = BufReader::new(stream);
        let origin = &context.deployment.public_origin;
        let name = origin
            .split_once("://")
            .map_or(origin.as_str(), |(_, host)| host);
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
        });
        let steps = [
            (None, 220),
            (Some(format!("EHLO {name}\r\n")), 250),
            (Some(format!("MAIL FROM:<{}>\r\n", self.sender)), 250),
            (Some(format!("RCPT TO:<{}>\r\n", self.recipient)), 250),
            (Some("DATA\r\n".to_owned()), 354),
            (Some(message), 250),
        ];
        let mut last = Sent::default();
        for (index, (command, expected)) in steps.iter().enumerate() {
            if let Some(command) = command
                && writer.write_all(command.as_bytes()).is_err()
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
                    };
                    if code != *expected {
                        break;
                    }
                }
                Err(error) => return failed(error),
            }
        }
        let _ = writer.write_all(b"QUIT\r\n");
        last
    }

    /// What the event history says became of an accepted message.
    fn filed(context: &Context<'_>, queue: &str) -> Option<&'static str> {
        let db = reading(&context.events_database, Duration::from_secs(2))
            .ok()
            .flatten()?;
        let mut statement = db
            .prepare("SELECT type FROM events WHERE queue_id=? LIMIT 200")
            .ok()?;
        let kinds: Vec<String> = statement
            .query_map([queue], |row| row.get(0))
            .ok()?
            .filter_map(Result::ok)
            .collect();
        if kinds.iter().any(|kind| kind == "message-ingest.spam") {
            Some("spam")
        } else if kinds.iter().any(|kind| kind == "message-ingest.ham") {
            Some("ham")
        } else {
            None
        }
    }

    /// The result of one test: its state and what to say of it.
    fn judged(context: &Context<'_>, test: Test, sent: &Sent, at: i64) -> (State, String) {
        if sent.at_data && (400..600).contains(&sent.code) {
            return (State::Ok, format!("refused: {}", sent.reply));
        }
        if sent.code == 250 && sent.at_data {
            let unfiltered = match test {
                Test::Eicar => Some("accepted: no scanner refused the test file"),
                Test::Macro => Some("accepted: no filter refused the test document"),
                Test::Gtube => None,
            };
            if let Some(said) = unfiltered {
                return (State::Failed, said.to_owned());
            }
            let filed = sent
                .queue
                .as_deref()
                .and_then(|queue| Self::filed(context, queue));
            return match filed {
                Some("spam") => (State::Ok, "accepted and filed as spam".to_owned()),
                Some(_) => (
                    State::Failed,
                    "accepted and delivered as ordinary mail".to_owned(),
                ),
                None if context.now.as_second() - at <= VERDICT_WITHIN => (
                    State::Unknown,
                    "accepted; the event history does not show yet how it was filed".to_owned(),
                ),
                None => (
                    State::Unknown,
                    "accepted; the event history never showed how it was filed".to_owned(),
                ),
            };
        }
        // Refused before the message, or no session: the test did not happen.
        (State::Unknown, format!("not tested: {}", sent.reply))
    }
}

impl Provider for MailTest {
    fn name(&self) -> &'static str {
        "mail-test"
    }

    fn collect(&self, context: &Context<'_>) -> Collected {
        let now = context.now.as_second();
        let kept: Option<Kept> = context
            .memory
            .recall(MEMORY)
            .and_then(|text| serde_json::from_str(&text).ok())
            // A result from before the macro test was switched on or off is
            // not one of these tests.
            .filter(|kept: &Kept| {
                (0..self.every).contains(&(now - kept.at)) && kept.macros.is_some() == self.macros
            });
        let kept = kept.unwrap_or_else(|| {
            let kept = Kept {
                at: now,
                eicar: self.send(context, Test::Eicar),
                gtube: self.send(context, Test::Gtube),
                macros: self.macros.then(|| self.send(context, Test::Macro)),
            };
            if let Ok(text) = serde_json::to_string(&kept) {
                context.memory.keep(MEMORY, &text);
            }
            kept
        });
        let mut sent = vec![(Test::Eicar, &kept.eicar), (Test::Gtube, &kept.gtube)];
        sent.extend(kept.macros.as_ref().map(|sent| (Test::Macro, sent)));
        let results: Vec<(Test, (State, String))> = sent
            .into_iter()
            .map(|(test, sent)| (test, Self::judged(context, test, sent, kept.at)))
            .collect();
        let state = if results
            .iter()
            .any(|(_, (state, _))| *state == State::Failed)
        {
            State::Failed
        } else if results
            .iter()
            .any(|(_, (state, _))| *state == State::Unknown)
        {
            State::Unknown
        } else {
            State::Ok
        };
        let findings: Vec<String> = results
            .iter()
            .filter(|(_, (state, _))| *state != State::Ok)
            .map(|(test, (_, said))| format!("{}: {said}.", test.label()))
            .collect();
        let sent = time::Timestamp::from_second(kept.at)
            .ok()
            .map(time::isoformat);
        let column = |label: &str, format: Format| Column {
            label: label.to_owned(),
            format,
        };
        let mut report = Report::default();
        report.observations.push(
            Observation::new(
                "mailtest.results",
                self.name(),
                "Test messages",
                [ModuleId::Antivirus, ModuleId::Spam],
                Evidence::Probe,
                state,
                context.checked_at(),
                format!("SMTP to {}:{}", self.host, self.port),
            )?
            .with_scope(format!(
                "Garrison handed the test messages to the local SMTP listener without \
                 signing in, addressed to {}; the next test follows {} hours after this one.",
                self.recipient,
                self.every / 3600
            ))
            .with_table(Table {
                columns: vec![
                    column("Test", Format::Text),
                    column("Sent", Format::Datetime),
                    column("Result", Format::Text),
                ],
                rows: results
                    .iter()
                    .map(|(test, (_, said))| vec![json!(test.label()), json!(sent), json!(said)])
                    .collect(),
            })
            .with_findings(findings)
            .with_max_age(180),
        );
        Ok(report)
    }
}

#[cfg(test)]
mod tests;
