//! Whether a newer release exists, asked of GitHub once a day.
//!
//! One request for each product goes to the public list of its releases. It
//! carries nothing about this installation; GitHub sees the host's address.
//! The answer is kept in the status database for a day, a failed request for
//! an hour, so a run of the collector every minute asks no more often.
//!
//! Where a release runs, the newest release is the one GitHub calls the
//! latest, which is never a pre-release. Where a pre-release runs, the newest
//! of the last releases counts, pre-releases among them: whoever runs one is
//! told of the next.

use std::sync::LazyLock;

use garrison_core::modules::ModuleId;
use garrison_core::observations::{Evidence, Field, Format, Observation, State};
use garrison_core::{time, version};
use regex_lite::Regex;
use serde::{Deserialize, Serialize};

use super::stalwart::running_version;
use crate::context::{Collected, Context, Provider, Report};
use crate::fetch::{self, Request};
use crate::options::{Checked, Options, fail};

const API: &str = "https://api.github.com";
/// A known answer is asked for again after a day, a failed request after an hour.
const DAY: i64 = 86400;
const RETRY: i64 = 3600;
/// The newest releases that are read where pre-releases count.
const LISTED: usize = 10;

static TAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""tag_name"\s*:\s*"v?([^"\\]{1,60})""#).expect("valid pattern"));

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Product {
    Garrison,
    Stalwart,
}

impl Product {
    const ALL: [Product; 2] = [Product::Garrison, Product::Stalwart];

    fn id(self) -> &'static str {
        match self {
            Product::Garrison => "garrison",
            Product::Stalwart => "stalwart",
        }
    }

    fn title(self) -> &'static str {
        match self {
            Product::Garrison => "Garrison",
            Product::Stalwart => "Stalwart",
        }
    }

    fn repository(self) -> &'static str {
        match self {
            Product::Garrison => "relative23/garrison",
            Product::Stalwart => "stalwartlabs/stalwart",
        }
    }
}

/// What the status database keeps of the last request for one product.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct Asked {
    at: i64,
    /// The newest release GitHub named, when it last named one.
    latest: Option<String>,
    /// Why the last request gave none.
    problem: Option<String>,
    /// Whether pre-releases counted in that request.
    every: bool,
}

#[derive(Debug)]
pub struct Releases {
    api: String,
    products: Vec<Product>,
    /// The version of Garrison that runs here.
    garrison: String,
}

impl Releases {
    pub fn new(raw: &toml::Table) -> Checked<Self> {
        Options::new(raw, &["products", "api"])?;
        let api = match raw.get("api") {
            None => API.to_owned(),
            // A mirror, or a stand-in on this host.
            Some(toml::Value::String(api))
                if api.starts_with("https://") || api.starts_with("http://127.0.0.1") =>
            {
                api.trim_end_matches('/').to_owned()
            }
            Some(_) => return fail("providers[releases].api must be an https URL"),
        };
        let products = match raw.get("products") {
            None => Product::ALL.to_vec(),
            Some(toml::Value::Array(names)) if !names.is_empty() => {
                let mut products = Vec::new();
                for name in names {
                    let product = Product::ALL
                        .into_iter()
                        .find(|product| name.as_str() == Some(product.id()));
                    match product {
                        Some(product) if !products.contains(&product) => products.push(product),
                        _ => {
                            return fail(
                                "providers[releases].products lists garrison, stalwart or both",
                            );
                        }
                    }
                }
                products
            }
            Some(_) => {
                return fail("providers[releases].products lists garrison, stalwart or both");
            }
        };
        Ok(Releases {
            api,
            products,
            garrison: env!("CARGO_PKG_VERSION").to_owned(),
        })
    }

    /// The version that runs here.
    fn installed(&self, product: Product, context: &Context<'_>) -> Option<String> {
        match product {
            Product::Garrison => Some(self.garrison.clone()),
            Product::Stalwart => running_version(context).map(|(version, _)| version),
        }
    }

    fn address(&self, product: Product, every: bool) -> String {
        let releases = format!("{}/repos/{}/releases", self.api, product.repository());
        if every {
            format!("{releases}?per_page={LISTED}")
        } else {
            format!("{releases}/latest")
        }
    }

    /// Where the answer comes from, as a card names it: the whole address is
    /// long enough to fill a phone's screen line by line.
    fn source(&self, product: Product) -> String {
        let host = self
            .api
            .split_once("://")
            .map_or(self.api.as_str(), |(_, rest)| rest);
        format!("{host}: releases of {}", product.repository())
    }

    /// The newest release GitHub lists, or why it named none. With `every`,
    /// pre-releases count as well.
    fn ask(&self, product: Product, every: bool) -> Result<String, String> {
        let address = self.address(product, every);
        let request = Request {
            method: "GET",
            url: &address,
            headers: &[
                ("Accept", "application/vnd.github+json"),
                ("X-GitHub-Api-Version", "2022-11-28"),
            ],
            body: &[],
        };
        let answer = fetch::send(&request, &fetch::roots())?;
        match answer.status {
            200 => {}
            404 => return Err("GitHub lists no release".to_owned()),
            status => return Err(format!("GitHub answered {status}")),
        }
        // A name stands near the top of its release, so it is found even
        // where a long answer was cut off.
        let mut named = TAG
            .captures_iter(&answer.body)
            .map(|found| found[1].to_owned());
        if every {
            newest(named)
        } else {
            let named = named.next().ok_or("GitHub's answer names no release")?;
            version::newer(&named, &named)
                .map(|_| named.clone())
                .ok_or(format!("GitHub names {named}, which is no version"))
        }
    }

    /// What is known of the product's newest release, asking if that is due.
    /// `every` says whether pre-releases count; an answer kept from the other
    /// way of asking is not used.
    fn known(&self, context: &Context<'_>, product: Product, every: bool) -> Asked {
        let key = format!("release.{}", product.id());
        let now = context.now.as_second();
        let kept: Option<Asked> = context
            .memory
            .recall(&key)
            .and_then(|text| serde_json::from_str(&text).ok())
            .filter(|kept: &Asked| kept.every == every);
        if let Some(kept) = &kept {
            let wait = if kept.problem.is_some() { RETRY } else { DAY };
            if (0..wait).contains(&(now - kept.at)) {
                return kept.clone();
            }
        }
        let asked = match self.ask(product, every) {
            Ok(latest) => Asked {
                at: now,
                latest: Some(latest),
                problem: None,
                every,
            },
            // What was known before stays known; the next try comes sooner.
            Err(problem) => Asked {
                at: now,
                latest: kept.and_then(|kept| kept.latest),
                problem: Some(problem),
                every,
            },
        };
        if let Ok(text) = serde_json::to_string(&asked) {
            context.memory.keep(&key, &text);
        }
        asked
    }

    fn observation(
        &self,
        context: &Context<'_>,
        product: Product,
    ) -> Result<Observation, crate::context::ProviderError> {
        let installed = self.installed(product, context);
        // Whoever runs a pre-release is told of the next one too.
        let every = installed.as_deref().and_then(version::prerelease) == Some(true);
        let asked = self.known(context, product, every);
        let title = product.title();
        let (state, finding) = match (&asked.latest, &installed) {
            (Some(latest), Some(installed)) => match version::newer(latest, installed) {
                Some(true) => (
                    State::Warning,
                    Some(format!(
                        "{title} {latest} is available; {installed} runs here."
                    )),
                ),
                Some(false) => (State::Ok, None),
                None => (
                    State::Unknown,
                    Some(format!(
                        "The running version {installed} cannot be compared."
                    )),
                ),
            },
            (Some(_), None) => (
                State::Unknown,
                Some(format!(
                    "The version of {title} that runs here is not known."
                )),
            ),
            (None, _) => (
                State::Unknown,
                Some(format!(
                    "The newest release is not known: {}.",
                    asked.problem.as_deref().unwrap_or("not asked yet")
                )),
            ),
        };
        let at = time::Timestamp::from_second(asked.at)
            .ok()
            .map(time::isoformat);
        Ok(Observation::new(
            format!("release.{}", product.id()),
            self.name(),
            format!("{title} release"),
            [ModuleId::Services],
            Evidence::Probe,
            state,
            context.checked_at(),
            self.source(product),
        )?
        .with_scope("The newest release GitHub lists, asked once a day.")
        .with_fields(vec![
            Field::text("Runs here", installed),
            Field::text("Newest release", asked.latest),
            Field::new("Asked", at, Format::Datetime),
        ])
        .with_findings(finding.into_iter().collect())
        .with_max_age(180))
    }
}

/// The highest version among the releases `named`, or why there is none.
fn newest(named: impl Iterator<Item = String>) -> Result<String, String> {
    let mut highest: Option<String> = None;
    let mut other = None;
    for name in named {
        match &highest {
            _ if version::prerelease(&name).is_none() => other = Some(name),
            Some(known) if version::newer(&name, known) != Some(true) => {}
            _ => highest = Some(name),
        }
    }
    match (highest, other) {
        (Some(highest), _) => Ok(highest),
        (None, Some(other)) => Err(format!("GitHub names {other}, which is no version")),
        (None, None) => Err("GitHub lists no release".to_owned()),
    }
}

impl Provider for Releases {
    fn name(&self) -> &'static str {
        "releases"
    }

    fn collect(&self, context: &Context<'_>) -> Collected {
        let mut report = Report::default();
        for product in &self.products {
            report
                .observations
                .push(self.observation(context, *product)?);
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests;
