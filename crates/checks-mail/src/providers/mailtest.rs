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
//! A refusal is a verdict only where it is shown to be for what the message
//! carries: a scanner that fails closed, as clamav-milter with `OnFail
//! Reject` while clamd is down, another milter or a policy of the server
//! refuses every message at its end, and one that fails on part of its
//! scans, or takes turns with a scanner that is down, refuses by turns. So a
//! test the server refused is sent again at once, and where it refused that
//! too, a harmless message of the same build goes after the run's tests,
//! which lands in that mailbox where the server takes it.
//!
//! Where the operator switches it on (`macro_document = true`), a third
//! message carries a document that a virus scanner told to report macros
//! takes for one with macros (`ClamAV` with `AlertOLE2Macros yes`); it must
//! be refused like the test file.

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
use session::{PACE, SESSION};

mod document;
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
                           clamav-milter does with `OnFail Reject` while clamd is down, or a \
                           policy that refuses the tests' sender, which `sender` changes; no \
                           refusal of a test counts.";
/// What a refusal of the harmless document means.
const REFUSES_DOCUMENTS: &str = "The server refuses a harmless document of the same build, so \
                                 the refusal of the test document shows no macro filter.";
/// The states a result can make the card, the worst first.
const WORST_FIRST: [State; 3] = [State::Failed, State::Warning, State::Unknown];

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
    /// Where the server refused the message: the same message sent again at
    /// once. A filter refuses every copy of what it refuses; a server that
    /// refuses by turns takes one of them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    again: Option<Box<Sent>>,
    /// Where it refused both: the harmless message of the same build that
    /// went after the tests of the run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    beside: Option<Box<Sent>>,
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

    /// Whether the server refused the message and the copy sent again.
    fn refused_twice(&self) -> bool {
        self.refused() && self.again.as_deref().is_some_and(Sent::refused)
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
    /// What they were sent to. An earlier release kept none; its results are
    /// taken as made for the configuration as it is.
    #[serde(default)]
    aim: Option<Aim>,
}

impl Tests {
    /// Each test that was sent, the harmless messages not among them.
    fn sent(&self) -> impl Iterator<Item = (Test, &Sent)> {
        [
            (Test::Eicar, Some(&self.eicar)),
            (Test::Gtube, Some(&self.gtube)),
            (Test::Macro, self.macros.as_ref()),
        ]
        .into_iter()
        .filter_map(|(test, sent)| Some((test, sent?)))
    }

    /// Each harmless message once, after the tests it went beside.
    fn harmless(&self) -> Vec<(Test, &Sent)> {
        let mut found: Vec<(Test, &Sent)> = Vec::new();
        for (test, sent) in self.sent() {
            if let Some(beside) = sent.beside.as_deref()
                && !found
                    .iter()
                    .any(|(twin, seen)| *twin == test.twin() && seen.at == beside.at)
            {
                found.push((test.twin(), beside));
            }
        }
        found
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
    /// How long a session waits before it begins.
    pace: Duration,
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
            pace: PACE,
        })
    }

    /// For tests: have each session wait this long before it begins.
    #[cfg(test)]
    #[must_use]
    pub fn paced(mut self, pace: Duration) -> Self {
        self.pace = pace;
        self
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

    /// The result of one test that was sent at `at`: its state and what to
    /// say of it. A server that refuses the harmless message takes no mail,
    /// which an operator is told of; one that refuses the harmless document
    /// shows no macro filter.
    fn judged(context: &Context<'_>, test: Test, sent: &Sent, at: i64) -> (State, String) {
        if !sent.happened() {
            // Refused before the message, deferred, or no session.
            return (State::Unknown, format!("not tested: {}", sent.reply));
        }
        if matches!(test, Test::Control | Test::Document) {
            return match (sent.taken(), test) {
                (true, _) => (State::Ok, "accepted".to_owned()),
                (false, Test::Control) => (State::Warning, format!("refused: {}", sent.reply)),
                (false, _) => (State::Unknown, format!("refused: {}", sent.reply)),
            };
        }
        if sent.refused() {
            Self::refusal(context, test, sent, at)
        } else {
            Self::accepted(context, test, sent, at)
        }
    }

    /// A test the server refused: a verdict only where it refused the copy
    /// sent again at once too, and took the harmless message of the same
    /// build that went after the tests of that run.
    fn refusal(context: &Context<'_>, test: Test, sent: &Sent, at: i64) -> (State, String) {
        let reply = &sent.reply;
        let Some(again) = sent.again.as_deref().filter(|again| !again.cut) else {
            return (
                State::Unknown,
                format!("not tested: refused, and not sent again yet: {reply}"),
            );
        };
        if again.taken() {
            let (state, said) = Self::accepted(context, test, again, again.at.unwrap_or(at));
            return (state, format!("refused, then sent again: {said}"));
        }
        if !again.refused() {
            return (
                State::Unknown,
                format!("not tested: refused, then sent again: {}", again.reply),
            );
        }
        match sent.beside.as_deref() {
            Some(beside) if beside.taken() => (State::Ok, format!("refused: {reply}")),
            Some(beside) if beside.refused() => (
                State::Unknown,
                format!("not tested: refused like a harmless message: {reply}"),
            ),
            _ => (
                State::Unknown,
                format!(
                    "not tested: refused, and no harmless message got through to compare: {reply}"
                ),
            ),
        }
    }

    /// A test the server took: in order only for the spam text filed as
    /// spam.
    fn accepted(context: &Context<'_>, test: Test, sent: &Sent, at: i64) -> (State, String) {
        let unfiltered = match test {
            Test::Eicar => Some("accepted: no scanner refused the test file"),
            Test::Macro => Some("accepted: no filter refused the test document"),
            Test::Gtube | Test::Control | Test::Document => None,
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
        // Each test with when it was sent and what became of it, the harmless
        // messages last.
        let results: Vec<(Test, i64, &Sent, (State, String))> = tests
            .sent()
            .chain(tests.harmless())
            .map(|(test, sent)| {
                let at = sent.at.unwrap_or(kept.at);
                (test, at, sent, Self::judged(context, test, sent, at))
            })
            .collect();
        // The worst result makes the card's state, and its finding comes
        // first: a notification carries the first.
        let rank = |state: &State| WORST_FIRST.iter().position(|worse| worse == state);
        let state = WORST_FIRST
            .into_iter()
            .find(|worst| results.iter().any(|(_, _, _, (state, _))| state == worst))
            .unwrap_or(State::Ok);
        let mut ranked: Vec<(usize, String)> = results
            .iter()
            .filter_map(|(test, _, sent, (state, said))| {
                // A reply that ends its sentence ends the finding with it.
                let finding = format!("{}: {}.", test.label(), said.trim_end_matches('.'));
                let finding = match test {
                    Test::Control if sent.refused() => format!("{finding} {REFUSES_ALL}"),
                    Test::Document if sent.refused() => format!("{finding} {REFUSES_DOCUMENTS}"),
                    _ => finding,
                };
                Some((rank(state)?, finding))
            })
            .collect();
        ranked.sort_by_key(|(rank, _)| *rank);
        let findings: Vec<String> = ranked.into_iter().map(|(_, finding)| finding).collect();
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
             addressed to {}. A refusal counts only where the server refuses the test again at \
             once and takes a harmless message of the same build sent after it. Each test is \
             sent again {} hours after it was sent; one that did not happen or does not count, as \
             one the server deferred, is tried again after an hour.",
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
                .map(|(test, at, _, (_, said))| {
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
mod macro_tests;
#[cfg(test)]
pub(super) mod tests;
#[cfg(test)]
mod time_tests;
#[cfg(test)]
mod ways_tests;
