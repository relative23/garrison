//! What a reading holds, as the status database keeps it, and what it says
//! of itself: whether its cards can be in order.

use serde::{Deserialize, Serialize};

use super::shown;
use super::verdict::Said;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub(super) struct Asked {
    pub(super) host: String,
    pub(super) address: String,
    /// The address's reverse name, if it has one.
    pub(super) pointer: Option<String>,
    /// Whether that name leads back to the address.
    pub(super) confirmed: bool,
    /// Why the reverse name, or where it leads, could not be read: an
    /// answer the check cannot use counts for this address alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) unread: Option<String>,
    pub(super) lists: Vec<(String, Said)>,
}

/// What the status database keeps of the last reading.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub(super) struct Read {
    pub(super) hosts: Vec<String>,
    pub(super) addresses: Vec<Asked>,
    pub(super) problem: Option<String>,
    /// What to say of Stalwart's domains after the first `max_domains`.
    #[serde(default)]
    pub(super) rest: Option<String>,
    /// Why not every address or list was asked, where that is so.
    #[serde(default)]
    pub(super) cut: Option<String>,
    /// What the reading's own limits left out: mail hosts after the first
    /// [`MOST_HOSTS`](super::MOST_HOSTS), addresses after the first
    /// [`MOST_ADDRESSES`](super::MOST_ADDRESSES).
    #[serde(default)]
    pub(super) left_out: Vec<String>,
    /// Why the zones of Spamhaus' Data Query Service written without their
    /// key were not asked, where the run had no key.
    #[serde(default)]
    pub(super) keyless: Option<String>,
    /// Whether Stalwart's mail hosts were not asked for want of the
    /// collector's key: made again in the first run that has one.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(super) no_native_key: bool,
    /// The mail hosts whose addresses of a kind could not be read, and why:
    /// an answer the check cannot use counts for that host alone.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) hosts_unread: Vec<String>,
    /// Whether a list went unasked about an address because the lists had
    /// had their time: the blocklists card cannot be in order then. The
    /// row's words only say so.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(super) lists_unasked: bool,
    /// What the reading was made with; none where an earlier release kept
    /// it.
    #[serde(default)]
    pub(super) made: Option<Made>,
}

/// What a reading is made with: the resolver it asks and the options that
/// decide what it asks. A reading made with others is made again at once,
/// as is one an earlier release kept, which says nothing of them: a
/// resolver, a list or a mail host the operator changes shows in the next
/// run, not hours later.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub(super) struct Made {
    /// The resolver: the option's, or the first of /etc/resolv.conf.
    pub(super) resolver: Option<String>,
    pub(super) hosts: Vec<String>,
    /// How many of Stalwart's domains name the mail hosts, without `hosts`.
    pub(super) max_domains: Option<usize>,
    /// The lists, named as the cards name them: a zone's key stays out.
    pub(super) lists: Vec<String>,
    pub(super) lists_ipv6: Vec<String>,
}

impl Read {
    /// Whether an address's reverse name could not be read: the reverse
    /// names card cannot be in order then.
    pub(super) fn reverse_unread(&self) -> bool {
        self.addresses.iter().any(|asked| asked.unread.is_some())
    }

    /// Whether a list that was asked gave no verdict about an address: the
    /// blocklists card cannot be in order then, and the next reading may
    /// get one.
    pub(super) fn no_verdict(&self) -> bool {
        self.addresses.iter().any(|asked| {
            asked
                .lists
                .iter()
                .any(|(_, said)| matches!(said, Said::Unanswered(_)))
        })
    }

    /// Whether an address of the mail hosts was neither asked nor counted:
    /// then neither card can be in order.
    pub(super) fn incomplete(&self) -> bool {
        self.cut.is_some() || !self.left_out.is_empty() || !self.hosts_unread.is_empty()
    }

    /// Whether it names a zone with a key, as an earlier release kept it.
    pub(super) fn names_a_key(&self) -> bool {
        self.addresses
            .iter()
            .any(|asked| asked.lists.iter().any(|(zone, _)| shown(zone) != *zone))
    }
}
