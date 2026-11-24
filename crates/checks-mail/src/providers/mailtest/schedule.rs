//! When each test is sent: the results kept between runs, and the tests a
//! run sends.

use super::message::Test;
use super::{AGAIN, Aim, MailTest, Sent, Tests};
use crate::context::Context;

/// Why a test was not sent.
const RUN_OVER: &str = "the collection run's time was used up";

impl MailTest {
    /// When a test of results kept at `kept` is sent again: after its hours
    /// if it happened and counts, after an hour if it did not or the server
    /// did not take the harmless message beside it, and in the next run if
    /// the run had no time for it. A refusal kept without its copy and its
    /// harmless message, as an earlier release kept it or a run that had no
    /// time for them, is sent again at once: it is judged only in a round
    /// of its own.
    fn due(&self, kept: i64, sent: &Sent) -> i64 {
        let at = sent.at.unwrap_or(kept);
        let soon = at.saturating_add(AGAIN.min(self.every));
        if sent.cut {
            return at;
        }
        if sent.refused() {
            let again = sent.again.as_deref().filter(|again| !again.cut);
            let beside = sent.beside.as_deref().filter(|beside| !beside.cut);
            match (again, beside) {
                (None, _) => return at,
                (Some(again), None) if again.refused() => return at,
                (Some(again), Some(beside)) if again.refused() && !beside.taken() => return soon,
                (Some(again), _) if !again.happened() => return soon,
                _ => {}
            }
        }
        if sent.happened() {
            at.saturating_add(self.every)
        } else {
            soon
        }
    }

    /// For how long results kept at `kept` are used: until the first test is
    /// due again, and not at all where they are not this configuration's.
    pub(super) fn wait(&self, kept: i64, tests: &Tests) -> i64 {
        if !self.fits(tests) {
            return 0;
        }
        tests
            .sent()
            .map(|(_, sent)| self.due(kept, sent))
            .min()
            .map_or(0, |due| due.saturating_sub(kept))
    }

    /// The tests that are due, sent now; the others stay as they were kept.
    /// A test the server refused is sent again at once, and after the tests
    /// of this run that it refused twice goes one harmless message of their
    /// build, kept with each of them.
    pub(super) fn tested(&self, context: &Context<'_>, before: Option<(i64, Tests)>) -> Tests {
        let now = context.now.as_second();
        let before = before.filter(|(_, tests)| self.fits(tests));
        let result = |test: Test, kept: fn(&Tests) -> Option<&Sent>| {
            let stays = before.as_ref().and_then(|(at, tests)| {
                let sent = kept(tests)?;
                let sent_at = sent.at.unwrap_or(*at);
                (sent_at..self.due(*at, sent)).contains(&now).then(|| Sent {
                    at: Some(sent_at),
                    ..sent.clone()
                })
            });
            stays.unwrap_or_else(|| self.tried(context, test))
        };
        let mut tests = Tests {
            eicar: result(Test::Eicar, |tests| Some(&tests.eicar)),
            gtube: result(Test::Gtube, |tests| Some(&tests.gtube)),
            macros: self
                .macros
                .then(|| result(Test::Macro, |tests| tests.macros.as_ref())),
            aim: Some(self.aim()),
        };
        let of_this_run = |sent: &Sent| sent.at == Some(now) && sent.refused_twice();
        if [&tests.eicar, &tests.gtube].into_iter().any(of_this_run) {
            let beside = Box::new(self.sent_now(context, Test::Control, false));
            for sent in [&mut tests.eicar, &mut tests.gtube] {
                if of_this_run(sent) {
                    sent.beside = Some(beside.clone());
                }
            }
        }
        if let Some(sent) = tests.macros.as_mut()
            && of_this_run(sent)
        {
            sent.beside = Some(Box::new(self.sent_now(context, Test::Document, false)));
        }
        tests
    }

    /// `test`, sent now, and again at once where the server refused it.
    fn tried(&self, context: &Context<'_>, test: Test) -> Sent {
        let mut sent = self.sent_now(context, test, false);
        if sent.refused() {
            sent.again = Some(Box::new(self.sent_now(context, test, true)));
        }
        sent
    }

    /// `test`, or its copy sent again where `again`, sent now; once the run's
    /// time is up, a test that is due waits.
    fn sent_now(&self, context: &Context<'_>, test: Test, again: bool) -> Sent {
        let sent = if context.deadline.expired() {
            Sent {
                reply: format!("not sent: {RUN_OVER}"),
                cut: true,
                ..Sent::default()
            }
        } else {
            self.send(context, test, again)
        };
        Sent {
            at: Some(context.now.as_second()),
            ..sent
        }
    }

    /// What this configuration sends the tests to and from.
    fn aim(&self) -> Aim {
        Aim {
            host: self.host.clone(),
            port: self.port,
            recipient: self.recipient.clone(),
            sender: self.sender.clone(),
        }
    }

    /// Whether results kept are of the tests this configuration asks for:
    /// not where the macro test was switched since, nor where they were sent
    /// to another listener or recipient or from another sender.
    fn fits(&self, tests: &Tests) -> bool {
        tests.macros.is_some() == self.macros
            && tests.aim.as_ref().is_none_or(|aim| *aim == self.aim())
    }
}
