//! Stalwart's sign-in page as a visitor's browser loads it. Everybody signs in
//! to Garrison there. Two things go wrong behind a proxy while every other
//! check still passes. The issuer's name is often shared: a webmail or another
//! application may answer the same address with a sign-in page of its own, one
//! that loads without a fault. And the page is of use only if the scripts and
//! style sheets it names reach Stalwart as well. So the page behind the public
//! name is held against the page Stalwart serves itself, whatever else is
//! installed beside it, and every file it names is asked for. What the page is
//! expected to look like is `garrison_stalwart::sign_in_page`.

use std::sync::Arc;

use garrison_core::config::Config;
use garrison_stalwart::sign_in_page::{self, Kind};
use rustls::RootCertStore;

use super::Finding;
use super::public::{origin, sign_in_query};
use garrison_collector::fetch::get;

/// The most files of one page that are asked for.
const MOST: usize = 12;

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
fn files_of(page: &str, html: &str, roots: &Arc<RootCertStore>) -> (usize, Vec<String>) {
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
fn examine(page: &str, own: &str, query: &str, roots: &Arc<RootCertStore>) -> Finding {
    let page_fix = "This address must reach Stalwart; check the proxy rules of the issuer's host.";
    let answer = match get(&format!("{page}?{query}"), roots) {
        Ok(answer) if answer.status == 200 => answer,
        Ok(answer) => {
            return Finding::fail(
                format!("Stalwart's sign-in page {page} answers {}", answer.status),
                page_fix,
            );
        }
        Err(error) => {
            return Finding::fail(format!("Stalwart's sign-in page {page}: {error}"), page_fix);
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
        return Finding::fail(
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
        return Finding::fail(
            format!(
                "Stalwart's sign-in page {page} cannot load {}",
                broken.join(", ")
            ),
            format!(
                "Whatever answers for {host} must pass these paths to Stalwart as it passes the \
                 page (nginx: a location with proxy_pass). Without them the page does nothing \
                 and nobody can sign in."
            ),
        );
    }
    let loads = match count {
        0 => "needs no files of its own".to_owned(),
        1 => "gets the 1 file it loads".to_owned(),
        count => format!("gets the {count} files it loads"),
    };
    match compared {
        Some(Whose::Stalwart) => Finding::ok(format!(
            "{page} shows Stalwart's sign-in page, which {loads}"
        )),
        // Not known to be Stalwart's page is not a page in order.
        Some(_) => Finding::unknown(format!(
            "{page} differs from the sign-in page Stalwart serves at {own}, and neither names \
             a file to tell them by"
        )),
        None => Finding::unknown(format!(
            "the sign-in page at {page} {loads}, but Stalwart did not answer at {own} to hold \
             it against"
        )),
    }
}

pub(super) fn check(config: &Config, roots: &Arc<RootCertStore>) -> Finding {
    let deployment = &config.deployment;
    examine(
        &format!("{}{}", deployment.issuer, sign_in_page::PATH),
        &format!(
            "{}{}",
            deployment.stalwart_url.trim_end_matches('/'),
            sign_in_page::PATH
        ),
        &sign_in_query(&deployment.public_origin),
        roots,
    )
}

#[cfg(test)]
mod tests;
