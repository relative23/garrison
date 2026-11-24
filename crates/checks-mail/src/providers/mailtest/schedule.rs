//! When each test is sent: the results kept between runs, and the tests a
//! run sends.

use super::message::Test;
use super::{AGAIN, Aim, MailTest, Sent, Tests};
use crate::context::Context;

/// Why a test was not sent.
const RUN_OVER: &str = "the collection run's time was used up";

impl MailTest {
    /// When a test of results kept at `kept` is sent again: after its hours
    /// if it happened, sooner if it did not, and in the next run if the run
    /// had no time for it.
    fn due(&self, kept: i64, sent: &Sent) -> i64 {
        let at = sent.at.unwrap_or(kept);
        if sent.cut {
            return at;
        }
        let wait = if sent.happened() {
            self.every
        } else {
            AGAIN.min(self.every)
        };
        at.saturating_add(wait)
    }

    /// For how long results kept at `kept` are used: until the first test is
    /// due again, and not at all where they are not this configuration's.
    pub(super) fn wait(&self, kept: i64, tests: &Tests) -> i64 {
        if !self.fits(tests) {
            return 0;
        }
        [
            Some(&tests.eicar),
            Some(&tests.gtube),
            tests.macros.as_ref(),
        ]
        .into_iter()
        .flatten()
        .map(|sent| self.due(kept, sent))
        .min()
        .map_or(0, |due| due.saturating_sub(kept))
    }

    /// The tests that are due, sent now; the others stay as they were kept.
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
            stays.unwrap_or_else(|| {
                // Once the run's time is up, a test that is due waits.
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
                    at: Some(now),
                    ..sent
                }
            })
        };
        Tests {
            eicar: result(Test::Eicar, |tests| Some(&tests.eicar)),
            gtube: result(Test::Gtube, |tests| Some(&tests.gtube)),
            macros: self
                .macros
                .then(|| result(Test::Macro, |tests| tests.macros.as_ref())),
            aim: Some(self.aim()),
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
