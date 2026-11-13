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
use garrison_core::observations::{Evidence, Field, Format, Observation, State};
use garrison_core::time;
use garrison_stalwart::sign_in_page::{self, Kind};
use serde::{Deserialize, Serialize};

use crate::context::{Collected, Context, Provider, Report};
use crate::fetch::{self, Roots, get, origin};
use crate::options::{Checked, Options};

/// The most files of one page that are asked for.
const MOST: usize = 12;
/// A page in order is examined again after five minutes; one that is not, in
/// the next run.
const EVERY: i64 = 300;
/// Where the status database keeps the last page in order.
const KEPT: &str = "signin.page";

/// What an examination of the page found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Examined {
    /// `Ok`, `Failed` or `Unknown`.
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

/// Asks for every file of its own host that the page at `page` loads: how
/// many there are, and those that did not come back as what they are.
fn files_of(page: &str, html: &str, roots: &Roots) -> (usize, Vec<String>) {
    let mut files: Vec<(Kind, String)> = Vec::new();
    for (kind, reference) in sign_in_page::files(html) {
        if let Some(address) = sign_in_page::address(page, &reference)
            && !files.iter().any(|(_, known)| *known == address)
        {
            files.push((kind, address));
        }
    }
    files.truncate(MOST);
    let host = origin(page);
    let broken = files
        .iter()
        .filter_map(|(kind, address)| {
            let path = address.strip_prefix(host).unwrap_or(address);
            match get(address, roots) {
                Ok(file)
                    if file.status == 200
                        && sign_in_page::media_fits(
                            *kind,
                            file.header("content-type").unwrap_or(""),
                        ) =>
                {
                    None
                }
                Ok(file) => Some(format!(
                    "{path} ({}, {})",
                    file.status,
                    file.header("content-type").unwrap_or("no content type")
                )),
                Err(error) => Some(format!("{path} ({error})")),
            }
        })
        .collect();
    (files.len(), broken)
}

/// The sign-in page at `page`, asked for as Garrison sends its users there,
/// held against the page Stalwart serves at `own`, and every file of its own
/// host that it loads.
pub fn examine(page: &str, own: &str, query: &str, roots: &Roots) -> Examined {
    let page_fix = "This address must reach Stalwart; check the proxy rules of the issuer's host.";
    let answer = match get(&format!("{page}?{query}"), roots) {
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
    let stalwart = get(&format!("{own}?{query}"), roots)
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
    let (count, broken) = files_of(page, &answer.body, roots);
    let host = origin(page);
    if !broken.is_empty() {
        return Examined {
            files: Some(count),
            ..Examined::failed(
                format!(
                    "Stalwart's sign-in page {page} cannot load {}",
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
    let loads = match count {
        0 => "needs no files of its own".to_owned(),
        1 => "gets the 1 file it loads".to_owned(),
        count => format!("gets the {count} files it loads"),
    };
    let (state, what) = match compared {
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
pub fn check(deployment: &Deployment, roots: &Roots) -> Examined {
    examine(
        &page(deployment),
        &format!(
            "{}{}",
            deployment.stalwart_url.trim_end_matches('/'),
            sign_in_page::PATH
        ),
        &sign_in_page::query(&deployment.public_origin),
        roots,
    )
}

/// What the status database keeps of the last examination that found the
/// page in order.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Kept {
    at: i64,
    page: String,
    files: Option<usize>,
}

#[derive(Debug)]
pub struct SignIn {
    modules: BTreeSet<ModuleId>,
}

impl SignIn {
    pub fn new(raw: &toml::Table) -> Checked<Self> {
        let options = Options::new(raw, &["modules"])?;
        Ok(SignIn {
            modules: options.modules(&["services"])?,
        })
    }

    /// When the page was examined and what was found: a page in order is
    /// examined again after five minutes, any other in every run.
    fn examined(context: &Context<'_>, page: &str) -> (i64, Examined) {
        let now = context.now.as_second();
        let kept = context
            .memory
            .recall(KEPT)
            .and_then(|text| serde_json::from_str::<Kept>(&text).ok())
            .filter(|kept| kept.page == page && (0..EVERY).contains(&(now - kept.at)));
        if let Some(kept) = kept {
            let examined = Examined {
                state: State::Ok,
                what: String::new(),
                fix: None,
                files: kept.files,
            };
            return (kept.at, examined);
        }
        let examined = check(context.deployment, &fetch::roots());
        if examined.state == State::Ok {
            let kept = Kept {
                at: now,
                page: page.to_owned(),
                files: examined.files,
            };
            if let Ok(text) = serde_json::to_string(&kept) {
                context.memory.keep(KEPT, &text);
            }
        }
        (now, examined)
    }
}

impl Provider for SignIn {
    fn name(&self) -> &'static str {
        "sign-in"
    }

    fn collect(&self, context: &Context<'_>) -> Collected {
        let page = page(context.deployment);
        let (at, examined) = Self::examined(context, &page);
        // A page in order needs no words; what is wrong comes with what to do.
        let findings = if examined.state == State::Ok {
            Vec::new()
        } else {
            std::iter::once(format!("{}.", examined.what))
                .chain(examined.fix)
                .collect()
        };
        let asked = time::Timestamp::from_second(at).ok().map(time::isoformat);
        let observation = Observation::new(
            "signin.page",
            self.name(),
            "Sign-in page",
            self.modules.iter().copied(),
            Evidence::Probe,
            examined.state,
            context.checked_at(),
            page.clone(),
        )?
        .with_scope(
            "Stalwart's sign-in page under the issuer's name, as a visitor's browser loads it, \
             with the scripts and style sheets it names; asked every five minutes, and in \
             every run while it is not in order.",
        )
        .with_fields(vec![
            Field::text("Page", page),
            Field::new("Files it loads", examined.files, Format::Number),
            Field::new("Asked", asked, Format::Datetime),
        ])
        .with_findings(findings)
        .with_max_age(180);
        Ok(Report::of(observation))
    }
}

#[cfg(test)]
mod tests;
