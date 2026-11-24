//! When each test is sent: the results kept between runs, and the tests a
//! run sends.

use super::message::Test;
use super::{AGAIN, Aim, MailTest, Sent, Tests};
use crate::context::Context;

/// Why a test was not sent.
const RUN_OVER: &str = "the collection run's time was used up";

impl MailTest {
    /// When a test of results kept at `kept` is sent again: after its hours
    /// if it happened, sooner if it did not or the server did not take the
    /// harmless message `control` sent after its refusal, and in the next run
    /// if the run had no time for it.
    fn due(&self, kept: i64, sent: &Sent, control: Option<&Sent>) -> i64 {
        let at = sent.at.unwrap_or(kept);
        if sent.cut {
            return at;
        }
        let unjudged =
            sent.refused() && control.is_some_and(|control| !control.cut && !control.taken());
        let wait = if sent.happened() && !unjudged {
            self.every
        } else {
            AGAIN.min(self.every)
        };
        at.saturating_add(wait)
    }

    /// Whether refusals kept have no harmless message beside them, as results
    /// an earlier release kept or a run that had no time for it: the next run
    /// sends it.
    fn owed(tests: &Tests) -> bool {
        tests.sent().any(|(_, sent)| sent.refused())
            && tests.control.as_ref().is_none_or(|control| control.cut)
    }

    /// For how long results kept at `kept` are used: until the first test is
    /// due again, and not at all where they are not this configuration's.
    pub(super) fn wait(&self, kept: i64, tests: &Tests) -> i64 {
        if !self.fits(tests) || Self::owed(tests) {
            return 0;
        }
        tests
            .sent()
            .map(|(_, sent)| self.due(kept, sent, tests.control.as_ref()))
            .min()
            .map_or(0, |due| due.saturating_sub(kept))
    }

    /// The tests that are due, sent now; the others stay as they were kept.
    /// The harmless message goes after a test the server refused in this
    /// run, or where the refusals kept have none beside them; else it stays
    /// as it was kept, while a test is refused.
    pub(super) fn tested(&self, context: &Context<'_>, before: Option<(i64, Tests)>) -> Tests {
        let now = context.now.as_second();
        let before = before.filter(|(_, tests)| self.fits(tests));
        let mut refused_now = false;
        let mut result = |test: Test, kept: fn(&Tests) -> Option<&Sent>| {
            let stays = before.as_ref().and_then(|(at, tests)| {
                let sent = kept(tests)?;
                let sent_at = sent.at.unwrap_or(*at);
                (sent_at..self.due(*at, sent, tests.control.as_ref()))
                    .contains(&now)
                    .then(|| Sent {
                        at: Some(sent_at),
                        ..sent.clone()
                    })
            });
            stays.unwrap_or_else(|| {
                let sent = self.sent_now(context, test);
                refused_now |= sent.refused();
                sent
            })
        };
        let mut tests = Tests {
            eicar: result(Test::Eicar, |tests| Some(&tests.eicar)),
            gtube: result(Test::Gtube, |tests| Some(&tests.gtube)),
            macros: self
                .macros
                .then(|| result(Test::Macro, |tests| tests.macros.as_ref())),
            control: None,
            aim: Some(self.aim()),
        };
        if tests.sent().any(|(_, sent)| sent.refused()) {
            let kept = before
                .and_then(|(_, kept)| kept.control)
                .filter(|control| !refused_now && !control.cut);
            tests.control = Some(kept.unwrap_or_else(|| self.sent_now(context, Test::Control)));
        }
        tests
    }

    /// `test`, sent now; once the run's time is up, a test that is due waits.
    fn sent_now(&self, context: &Context<'_>, test: Test) -> Sent {
        let sent = if context.deadline.expired() {
            Sent {
                reply: format!("not sent: {RUN_OVER}"),
                cut: true,
                ..Sent::default()
            }
        } else {
            self.send(context, test)
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
