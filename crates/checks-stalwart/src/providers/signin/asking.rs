//! How the sign-in check asks for the page and the files it loads.

use garrison_core::time::Timestamp;

use crate::context::Deadline;
use crate::fetch::{self, Answer, Roots};

/// How an examination asks for the page and its files: the authorities
/// their server's certificate must come from, until when it asks, and the
/// time it judges that certificate at, a run's, as every check judges what
/// it finds; `None` judges by the clock.
#[derive(Clone, Copy, Debug)]
pub struct Asking<'a> {
    pub roots: &'a Roots,
    pub deadline: Deadline,
    pub at: Option<Timestamp>,
}

impl<'a> Asking<'a> {
    /// Asked by hand, as `garrison doctor` asks: no run's time to keep, and
    /// the certificate judged by the clock.
    #[must_use]
    pub fn by_hand(roots: &'a Roots) -> Self {
        Asking {
            roots,
            deadline: Deadline::NONE,
            at: None,
        }
    }

    pub(super) fn get(self, url: &str) -> Result<Answer, String> {
        match self.at {
            Some(at) => fetch::get_at(url, self.roots, at),
            None => fetch::get(url, self.roots),
        }
    }
}
