//! Test messages through the mail server itself: the antivirus test file
//! (EICAR) and the spam test text (GTUBE).
//!
//! Only where an operator names a recipient. At most once in the configured
//! hours, the provider hands both to the local SMTP listener the way a
//! stranger would, without signing in. A test that did not happen, because
//! no session came about, the server turned it away before the message or
//! only deferred the message (4xx), is no result to keep that long: it alone
//! is tried again after an hour. Stalwart defers a message where a milter
//! defers it, as a scanner that cannot scan does, or where it cannot reach
//! one whose entry says to defer then: a deferral is no verdict.
//!
//! A scanner must refuse the test file while the session lasts. The spam
//! text is refused there too, or accepted and then filed as spam, which the
//! event history shows under the queue ID Stalwart named. Stalwart knows the
//! spam text only as a message's subject (a text in the body is ordinary
//! mail to it), so the test message carries it there and in the body, where
//! other filters look. A test that goes wrong leaves a harmless message in
//! the recipient's mailbox, which is why that mailbox is one made for it.
//!
//! A refusal is a verdict only where the server takes mail that carries
//! nothing to refuse: a scanner that fails closed, as clamav-milter with
//! `OnFail Reject` while clamd is down, another milter or a policy of the
//! server refuses every message at its end. So a run in which the server
//! refused a test sends a harmless message after it, which lands in that
//! mailbox where the server takes it.
//!
//! Where the operator switches it on (`macro_document = true`), a third
//! message carries a document that a macro filter such as Garrison's milter
//! takes for one with macros; it must be refused like the test file.

use std::time::Duration;

use garrison_core::modules::ModuleId;
use garrison_core::observations::{Column, Evidence, Format, Observation, Required, State, Table};
use garrison_core::sqlite::reading;
use garrison_core::time;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::context::{Collected, Context, Provider, Report};
use crate::kept::cached;
use crate::options::{Checked, Options, fail};
use message::Test;
use session::SESSION;

mod message;
mod schedule;
mod session;

const MEMORY: &str = "mailtest";
/// How long Stalwart may take to file an accepted message.
const VERDICT_WITHIN: i64 = 900;
/// A test that did not happen is tried again after this long.
const AGAIN: i64 = 3600;
/// What a refusal of the harmless message means.
const REFUSES_ALL: &str = "The server refuses mail that carries nothing to refuse, as \
                           clamav-milter does with `OnFail Reject` while clamd is down, so no \
                           refusal of a test counts.";

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
    /// The second it was sent at. An earlier release kept one time for all
    /// tests; where this is missing, that time counts.
    #[serde(default)]
    at: Option<i64>,
    /// Whether it was not sent because the run's time was up: it is due in
    /// the next run.
    #[serde(default)]
    cut: bool,
}

impl Sent {
    /// Whether the test happened: the server took the message itself or
    /// refused it for good (5xx). A session that did not come that far, and
    /// a message the server only deferred (4xx), tested nothing.
    fn happened(&self) -> bool {
        self.taken() || self.refused()
    }

    /// Whether the server took the message itself.
    fn taken(&self) -> bool {
        self.at_data && self.code == 250
    }

    /// Whether the server refused the message itself for good.
    fn refused(&self) -> bool {
        self.at_data && (500..600).contains(&self.code)
    }
}

/// What the tests were sent to and from: results for another listener,
/// recipient or sender are not these tests'.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
struct Aim {
    host: String,
    port: u16,
    recipient: String,
    sender: String,
}

/// The last result of each test, as the status database keeps them.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
struct Tests {
    eicar: Sent,
    gtube: Sent,
    /// The macro test, where the operator switched it on.
    #[serde(default)]
    macros: Option<Sent>,
    /// The harmless message, while a test is refused at its end.
    #[serde(default)]
    control: Option<Sent>,
    /// What they were sent to. An earlier release kept none; its results are
    /// taken as made for the configuration as it is.
    #[serde(default)]
    aim: Option<Aim>,
}

impl Tests {
    /// Each test that was sent, the harmless message not among them.
    fn sent(&self) -> impl Iterator<Item = (Test, &Sent)> {
        [
            (Test::Eicar, Some(&self.eicar)),
            (Test::Gtube, Some(&self.gtube)),
            (Test::Macro, self.macros.as_ref()),
        ]
        .into_iter()
        .filter_map(|(test, sent)| Some((test, sent?)))
    }
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
    /// How long one session may take in all.
    session: Duration,
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
            session: SESSION,
        })
    }

    /// For tests: give each session this long in all.
    #[cfg(test)]
    #[must_use]
    pub fn within(mut self, session: Duration) -> Self {
        self.session = session;
        self
    }

    /// What the event history says became of an accepted message, or why it
    /// could not be read.
    fn filed(context: &Context<'_>, queue: &str) -> Result<Option<&'static str>, String> {
        let text = |error: rusqlite::Error| error.to_string();
        let Some(db) = reading(&context.events_database, Duration::from_secs(2))
            .map_err(|error| error.to_string())?
        else {
            // Nothing is recorded yet, so nothing is filed yet either.
            return Ok(None);
        };
        let mut statement = db
            .prepare("SELECT type FROM events WHERE queue_id=? LIMIT 200")
            .map_err(text)?;
        let kinds: Vec<String> = statement
            .query_map([queue], |row| row.get(0))
            .map_err(text)?
            .filter_map(Result::ok)
            .collect();
        Ok(if kinds.iter().any(|kind| kind == "message-ingest.spam") {
            Some("spam")
        } else if kinds.iter().any(|kind| kind == "message-ingest.ham") {
            Some("ham")
        } else {
            None
        })
    }

    /// The result of one test that was sent at `at`, beside the harmless
    /// message `control`: its state and what to say of it.
    fn judged(
        context: &Context<'_>,
        test: Test,
        sent: &Sent,
        at: i64,
        control: Option<&Sent>,
    ) -> (State, String) {
        if !sent.happened() {
            // Refused before the message, deferred, or no session.
            return (State::Unknown, format!("not tested: {}", sent.reply));
        }
        if test == Test::Control {
            return if sent.taken() {
                (State::Ok, "accepted".to_owned())
            } else {
                (State::Unknown, format!("refused: {}", sent.reply))
            };
        }
        if sent.refused() {
            return match control {
                Some(control) if control.taken() => (State::Ok, format!("refused: {}", sent.reply)),
                Some(control) if control.refused() => (
                    State::Unknown,
                    format!(
                        "not tested: refused like a harmless message: {}",
                        sent.reply
                    ),
                ),
                _ => (
                    State::Unknown,
                    format!(
                        "not tested: refused, and no harmless message got through to compare: {}",
                        sent.reply
                    ),
                ),
            };
        }
        let unfiltered = match test {
            Test::Eicar => Some("accepted: no scanner refused the test file"),
            Test::Macro => Some("accepted: no filter refused the test document"),
            Test::Gtube | Test::Control => None,
        };
        if let Some(said) = unfiltered {
            return (State::Failed, said.to_owned());
        }
        let filed = match sent.queue.as_deref() {
            Some(queue) => Self::filed(context, queue),
            None => Ok(None),
        };
        match filed {
            Err(why) => (
                State::Unknown,
                format!("accepted; the event history could not be read: {why}"),
            ),
            Ok(Some("spam")) => (State::Ok, "accepted and filed as spam".to_owned()),
            Ok(Some(_)) => (
                State::Failed,
                "accepted and delivered as ordinary mail".to_owned(),
            ),
            Ok(None) if context.now.as_second().saturating_sub(at) <= VERDICT_WITHIN => (
                State::Unknown,
                "accepted; the event history does not show yet how it was filed".to_owned(),
            ),
            Ok(None) => (
                State::Unknown,
                "accepted; the event history never showed how it was filed".to_owned(),
            ),
        }
    }
}

impl Provider for MailTest {
    fn name(&self) -> &'static str {
        "mail-test"
    }

    fn ids(&self) -> Vec<String> {
        vec!["mailtest.results".to_owned()]
    }

    fn collect(&self, context: &Context<'_>) -> Collected {
        let kept = cached(
            context,
            MEMORY,
            |at, tests: &Tests| self.wait(at, tests),
            |before| self.tested(context, before),
        );
        let tests = &kept.answer;
        let control = tests.control.as_ref();
        // Each test with when it was sent and what became of it, the harmless
        // message last.
        let results: Vec<(Test, i64, (State, String))> = tests
            .sent()
            .chain(control.map(|sent| (Test::Control, sent)))
            .map(|(test, sent)| {
                let at = sent.at.unwrap_or(kept.at);
                (test, at, Self::judged(context, test, sent, at, control))
            })
            .collect();
        let state = if results
            .iter()
            .any(|(_, _, (state, _))| *state == State::Failed)
        {
            State::Failed
        } else if results
            .iter()
            .any(|(_, _, (state, _))| *state == State::Unknown)
        {
            State::Unknown
        } else {
            State::Ok
        };
        let findings: Vec<String> = results
            .iter()
            .filter(|(_, _, (state, _))| *state != State::Ok)
            // A reply that ends its sentence ends the finding with it.
            .map(|(test, _, (_, said))| {
                let finding = format!("{}: {}.", test.label(), said.trim_end_matches('.'));
                if *test == Test::Control && control.is_some_and(Sent::refused) {
                    format!("{finding} {REFUSES_ALL}")
                } else {
                    finding
                }
            })
            .collect();
        let stated = |at: i64| time::Timestamp::from_second(at).ok().map(time::isoformat);
        let column = |label: &str, format: Format| Column {
            label: label.to_owned(),
            format,
        };
        let observation = Observation::new(Required {
            id: "mailtest.results",
            provider: self.name(),
            title: "Test messages",
            modules: [ModuleId::Antivirus, ModuleId::Spam],
            evidence: Evidence::Probe,
            state,
            checked_at: &context.checked_at(),
            source: &format!("SMTP to {}:{}", self.host, self.port),
        })?
        .with_scope(format!(
            "Garrison handed the test messages to the local SMTP listener without signing in, \
             addressed to {}. A refusal counts only where the server takes a harmless message \
             sent after it. Each test is sent again {} hours after it was sent; one that did not \
             happen or does not count, as one the server deferred, is tried again after an hour.",
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
                .map(|(test, at, (_, said))| {
                    vec![json!(test.label()), json!(stated(*at)), json!(said)]
                })
                .collect(),
        })
        .with_findings(findings);
        // The card is as old as the last session, and stale once the next
        // test is overdue.
        Ok(Report::of(kept.dated(observation)))
    }
}

#[cfg(test)]
mod kept_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod time_tests;
