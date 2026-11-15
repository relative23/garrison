//! Stalwart's sign-in page as a visitor's browser loads it. Everybody signs in
//! to Garrison there. Two things go wrong behind a proxy while every other
//! check still passes. The issuer's name is often shared: a webmail or another
//! application may answer the same address with a sign-in page of its own, one
//! that loads without a fault. And the page is of use only if the scripts and
//! style sheets it names reach Stalwart as well. So the page behind the public
//! name is held against the page Stalwart serves itself, whatever else is
//! installed beside it, and every file it names is asked for. What the page is
//! expected to look like is `garrison_stalwart::sign_in_page`.
//!
//! `garrison doctor` examines the page when it is called. The check `sign-in`
//! examines it every five minutes, and in every run while it is not in order,
//! so the notifications report a page that stopped working within minutes. A
//! Stalwart release that loads other files than the proxy passes leaves nobody
//! able to sign in, and nothing else says so.

use std::collections::BTreeSet;

use garrison_core::config::Deployment;
use garrison_core::modules::ModuleId;
use garrison_core::observations::{Evidence, Field, Format, Observation, Required, State};
use garrison_core::time::Timestamp;
use garrison_stalwart::sign_in_page::{self, Kind};
use serde::{Deserialize, Serialize};

use crate::context::{Collected, Context, Deadline, Provider, Report};
use crate::fetch::{self, Answer, Roots, origin};
use crate::kept::{Kept, keep, recalled};
use crate::options::{Checked, Options};

/// The most files of one page that are asked for; a page that loads more is
/// in order only as far as they go.
const MOST: usize = 12;
/// A page in order is examined again after five minutes; one that is not, in
/// the next run.
const EVERY: i64 = 300;
/// Where the status database keeps the last page in order.
const KEPT: &str = "signin.page";
/// Why an examination stopped before it had asked everything.
const RUN_OVER: &str = "the collection run's time was used up";

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

    fn get(self, url: &str) -> Result<Answer, String> {
        match self.at {
            Some(at) => fetch::get_at(url, self.roots, at),
            None => fetch::get(url, self.roots),
        }
    }
}

/// What an examination of the page found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Examined {
    /// `Ok`, `Partial` (in order as far as it was asked, where the page loads
    /// more files than are asked for), `Failed` or `Unknown`.
    pub state: State,
    /// What was seen, in one sentence.
    pub what: String,
    /// What to do about a failure.
    pub fix: Option<String>,
    /// How many files of its own host the page loads, once it was read.
    pub files: Option<usize>,
}

impl Examined {
    fn failed(what: String, fix: impl Into<String>) -> Self {
        Examined {
            state: State::Failed,
            what,
            fix: Some(fix.into()),
            files: None,
        }
    }

    fn unknown(what: String) -> Self {
        Examined {
            state: State::Unknown,
            what,
            fix: None,
            files: None,
        }
    }
}

/// Whose page the public name serves, going by Stalwart's own.
#[derive(Debug, PartialEq, Eq)]
enum Whose {
    Stalwart,
    /// It names other files than Stalwart's page does.
    Another,
    /// The pages differ and neither names a file to tell them by.
    Unclear,
}

/// The files a page names, each once, in a fixed order.
fn named(html: &str) -> Vec<String> {
    let mut names: Vec<String> = sign_in_page::files(html)
        .into_iter()
        .map(|(_, name)| name)
        .collect();
    names.sort();
    names.dedup();
    names
}

/// A proxy may change a page on its way (add a tag, compress it again), so a
/// page that differs is still Stalwart's if it loads the same files: their
/// names carry a hash of what Stalwart built.
fn whose(public: &str, own: &str) -> Whose {
    if public == own {
        return Whose::Stalwart;
    }
    match (named(public), named(own)) {
        (public, own) if public.is_empty() && own.is_empty() => Whose::Unclear,
        (public, own) if public == own => Whose::Stalwart,
        _ => Whose::Another,
    }
}

/// `a, b` or, for none, `no files`.
fn listed(names: &[String]) -> String {
    if names.is_empty() {
        "no files".to_owned()
    } else {
        names.join(", ")
    }
}

/// Asks for the first [`MOST`] files of its own host that the page at `page`
/// loads, while the run has time: how many it loads, those that did not come
/// back as what they are, and how many of the first [`MOST`] were not asked
/// for the run's time.
fn files_of(page: &str, html: &str, asking: Asking<'_>) -> (usize, Vec<String>, usize) {
    let mut files: Vec<(Kind, String)> = Vec::new();
    for (kind, reference) in sign_in_page::files(html) {
        if let Some(address) = sign_in_page::address(page, &reference)
            && !files.iter().any(|(_, known)| *known == address)
        {
            files.push((kind, address));
        }
    }
    let count = files.len();
    files.truncate(MOST);
    let host = origin(page);
    let (mut broken, mut unasked) = (Vec::new(), 0);
    for (index, (kind, address)) in files.iter().enumerate() {
        if asking.deadline.expired() {
            unasked = files.len() - index;
            break;
        }
        let path = address.strip_prefix(host).unwrap_or(address);
        match asking.get(address) {
            Ok(file)
                if file.status == 200
                    && sign_in_page::media_fits(
                        *kind,
                        file.header("content-type").unwrap_or(""),
                    ) => {}
            Ok(file) => broken.push(format!(
                "{path} ({}, {})",
                file.status,
                file.header("content-type").unwrap_or("no content type")
            )),
            Err(error) => broken.push(format!("{path} ({error})")),
        }
    }
    (count, broken, unasked)
}

/// The sign-in page at `page`, asked for as Garrison sends its users there,
/// held against the page Stalwart serves at `own`, and every file of its own
/// host that it loads; each asked only while there is time before the
/// deadline of `asking`, and what was not asked is said.
pub fn examine(page: &str, own: &str, query: &str, asking: Asking<'_>) -> Examined {
    if asking.deadline.expired() {
        return Examined::unknown(format!(
            "Stalwart's sign-in page {page} was not asked: {RUN_OVER}"
        ));
    }
    let page_fix = "This address must reach Stalwart; check the proxy rules of the issuer's host.";
    let answer = match asking.get(&format!("{page}?{query}")) {
        Ok(answer) if answer.status == 200 => answer,
        Ok(answer) => {
            return Examined::failed(
                format!("Stalwart's sign-in page {page} answers {}", answer.status),
                page_fix,
            );
        }
        Err(error) => {
            return Examined::failed(format!("Stalwart's sign-in page {page}: {error}"), page_fix);
        }
    };
    if asking.deadline.expired() {
        return Examined::unknown(format!(
            "{page} answered, but Stalwart's own page at {own} and the files it loads were not \
             asked: {RUN_OVER}"
        ));
    }
    let stalwart = asking
        .get(&format!("{own}?{query}"))
        .ok()
        .filter(|stalwart| stalwart.status == 200)
        .map(|stalwart| stalwart.body);
    let compared = stalwart
        .as_deref()
        .map(|stalwart| whose(&answer.body, stalwart));
    if let (Some(Whose::Another), Some(stalwart)) = (&compared, &stalwart) {
        return Examined::failed(
            format!(
                "{page} does not show Stalwart's sign-in page: it loads {}, Stalwart's own \
                 page at {own} loads {}",
                listed(&named(&answer.body)),
                listed(&named(stalwart)),
            ),
            format!(
                "Something else answers this address for the request Garrison sends, such as a \
                 webmail on the same name. Whatever answers for {} must pass {} with a \
                 client_id to Stalwart.",
                origin(page),
                sign_in_page::PATH
            ),
        );
    }
    judged(page, own, &answer.body, compared.as_ref(), asking)
}

/// What the files that the page at `page` loads, and whose page it is, make
/// of a page that answered with `html`.
fn judged(
    page: &str,
    own: &str,
    html: &str,
    compared: Option<&Whose>,
    asking: Asking<'_>,
) -> Examined {
    let (count, broken, unasked) = files_of(page, html, asking);
    let host = origin(page);
    // The files after the first MOST are never asked for, and are named.
    let beyond = count.saturating_sub(MOST);
    let after = match beyond {
        0 => String::new(),
        beyond => format!("; the {beyond} after the first {MOST} were not asked"),
    };
    let left = match unasked {
        0 => after.clone(),
        more => format!("; {more} more were not asked: {RUN_OVER}{after}"),
    };
    if !broken.is_empty() {
        return Examined {
            files: Some(count),
            ..Examined::failed(
                format!(
                    "Stalwart's sign-in page {page} cannot load {}{left}",
                    broken.join(", ")
                ),
                format!(
                    "Whatever answers for {host} must pass these paths to Stalwart as it passes \
                     the page (nginx: a location with proxy_pass). Without them the page does \
                     nothing and nobody can sign in."
                ),
            )
        };
    }
    if unasked > 0 {
        return Examined {
            files: Some(count),
            ..Examined::unknown(format!(
                "Of the {count} files the sign-in page at {page} loads, {unasked} were not \
                 asked: {RUN_OVER}{after}"
            ))
        };
    }
    let loads = match count {
        0 => "needs no files of its own".to_owned(),
        1 => "gets the 1 file it loads".to_owned(),
        count if beyond > 0 => format!(
            "gets the first {MOST} of the {count} files it loads; the {beyond} after them were \
             not asked"
        ),
        count => format!("gets the {count} files it loads"),
    };
    let (state, what) = match compared {
        // In order as far as it was asked, which is not all of it.
        Some(Whose::Stalwart) if beyond > 0 => (
            State::Partial,
            format!("{page} shows Stalwart's sign-in page, which {loads}"),
        ),
        Some(Whose::Stalwart) => (
            State::Ok,
            format!("{page} shows Stalwart's sign-in page, which {loads}"),
        ),
        // Not known to be Stalwart's page is not a page in order.
        Some(_) => (
            State::Unknown,
            format!(
                "{page} differs from the sign-in page Stalwart serves at {own}, and neither \
                 names a file to tell them by"
            ),
        ),
        None => (
            State::Unknown,
            format!(
                "The sign-in page at {page} {loads}, but Stalwart did not answer at {own} to \
                 hold it against"
            ),
        ),
    };
    Examined {
        state,
        what,
        fix: None,
        files: Some(count),
    }
}

/// The page Garrison sends its users to, under the issuer.
pub fn page(deployment: &Deployment) -> String {
    format!("{}{}", deployment.issuer, sign_in_page::PATH)
}

/// The page as Garrison's users get it, held against the one Stalwart serves
/// itself on loopback.
pub fn check(deployment: &Deployment, asking: Asking<'_>) -> Examined {
    examine(
        &page(deployment),
        &format!(
            "{}{}",
            deployment.stalwart_url.trim_end_matches('/'),
            sign_in_page::PATH
        ),
        &sign_in_page::query(&deployment.public_origin),
        asking,
    )
}

/// What the status database keeps of the last examination that found the
/// page in order.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct InOrder {
    page: String,
    files: Option<usize>,
}

#[derive(Debug)]
pub struct SignIn {
    modules: BTreeSet<ModuleId>,
    /// The authorities the page's server is checked against: the system's,
    /// unless a test gives its own.
    roots: Option<Roots>,
}

impl SignIn {
    pub fn new(raw: &toml::Table) -> Checked<Self> {
        let options = Options::new(raw, &["modules"])?;
        Ok(SignIn {
            modules: options.modules(&["services"])?,
            roots: None,
        })
    }

    /// For tests: trust these roots for the page's server.
    #[cfg(test)]
    #[must_use]
    pub fn with_roots(mut self, roots: Roots) -> Self {
        self.roots = Some(roots);
        self
    }

    /// What was found of the page and when: a page in order is examined
    /// again after five minutes, any other in every run. Only a page in
    /// order is kept, so nothing kept can stand for one that is not.
    fn examined(&self, context: &Context<'_>, page: &str) -> Kept<Examined> {
        let now = context.now.as_second();
        let kept = recalled::<InOrder>(context, KEPT).filter(|(at, kept)| {
            kept.page == page && (0..EVERY).contains(&now.saturating_sub(*at))
        });
        if let Some((at, kept)) = kept {
            let answer = Examined {
                state: State::Ok,
                what: String::new(),
                fix: None,
                files: kept.files,
            };
            return Kept {
                at,
                wait: EVERY,
                answer,
            };
        }
        // Within the run's time, with the certificate judged at that time.
        let roots = self.roots.clone().unwrap_or_else(fetch::roots);
        let asking = Asking {
            roots: &roots,
            deadline: context.deadline,
            at: Some(context.now),
        };
        let answer = check(context.deployment, asking);
        let wait = if answer.state == State::Ok {
            let page = page.to_owned();
            let files = answer.files;
            keep(context, KEPT, &InOrder { page, files });
            EVERY
        } else {
            0
        };
        Kept {
            at: now,
            wait,
            answer,
        }
    }
}

impl Provider for SignIn {
    fn name(&self) -> &'static str {
        "sign-in"
    }

    fn ids(&self) -> Vec<String> {
        vec!["signin.page".to_owned()]
    }

    fn collect(&self, context: &Context<'_>) -> Collected {
        let page = page(context.deployment);
        let kept = self.examined(context, &page);
        let examined = kept.answer.clone();
        // A page in order needs no words; what is wrong comes with what to do.
        let findings = if examined.state == State::Ok {
            Vec::new()
        } else {
            std::iter::once(format!("{}.", examined.what))
                .chain(examined.fix)
                .collect()
        };
        let observation = Observation::new(Required {
            id: "signin.page",
            provider: self.name(),
            title: "Sign-in page",
            modules: self.modules.iter().copied(),
            evidence: Evidence::Probe,
            state: examined.state,
            checked_at: &context.checked_at(),
            source: &page,
        })?
        .with_scope(
            "Stalwart's sign-in page under the issuer's name, as a visitor's browser loads it, \
             with the scripts and style sheets it names; asked every five minutes, and in \
             every run while it is not in order.",
        )
        .with_fields(vec![
            Field::text("Page", page),
            Field::new("Files it loads", examined.files, Format::Number),
            Field::new("Asked", kept.asked(), Format::Datetime),
        ])
        .with_findings(findings);
        // The card is as old as the examination it is made from.
        Ok(Report::of(kept.dated(observation)))
    }
}

#[cfg(test)]
mod clock_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod time_tests;
