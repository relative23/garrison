//! HTTP health probes.

use std::collections::BTreeSet;
use std::time::Duration;

use garrison_core::modules::ModuleId;
use garrison_core::observations::{Evidence, Field, Format, Observation, Required, State};
use garrison_stalwart::http::status_of;

use crate::context::{Collected, Context, Provider, Report};
use crate::options::{Checked, Options, fail};

/// A loopback endpoint answers with an expected status (process evidence).
#[derive(Debug)]
pub struct Http {
    id: String,
    title: String,
    url: String,
    expect: u16,
    modules: BTreeSet<ModuleId>,
}

impl Http {
    pub fn new(raw: &toml::Table) -> Checked<Self> {
        let options = Options::new(raw, &["id", "title", "url", "expect_status", "modules"])?;
        let id = options.text("id", None)?;
        let title = options.text("title", None)?;
        let url = options.text("url", None)?;
        let loopback = url::Url::parse(&url).is_ok_and(|parsed| {
            parsed.scheme() == "http"
                && matches!(parsed.host_str(), Some("127.0.0.1" | "[::1]" | "localhost"))
        });
        if !loopback {
            return fail("providers[http].url must be a loopback http:// URL");
        }
        let expect = options.integer("expect_status", 200, 100, 599)?;
        Ok(Http {
            id,
            title,
            url,
            expect: u16::try_from(expect).unwrap_or(200),
            modules: options.modules(&["services"])?,
        })
    }
}

impl Provider for Http {
    fn name(&self) -> &'static str {
        "http"
    }

    fn ids(&self) -> Vec<String> {
        vec![format!("http.{}", self.id)]
    }

    fn collect(&self, context: &Context<'_>) -> Collected {
        let status = status_of(&self.url, Duration::from_secs(5)).ok();
        let findings = match status {
            None => vec!["The endpoint did not answer.".to_owned()],
            Some(status) if status != self.expect => {
                vec![format!("Answered HTTP {status}, expected {}.", self.expect)]
            }
            Some(_) => Vec::new(),
        };
        let observation = Observation::new(Required {
            id: &format!("http.{}", self.id),
            provider: self.name(),
            title: &self.title,
            modules: self.modules.iter().copied(),
            evidence: Evidence::Process,
            state: if status == Some(self.expect) {
                State::Ok
            } else {
                State::Failed
            },
            checked_at: &context.checked_at(),
            source: &self.url,
        })?
        .with_scope("The endpoint answered; this does not test user functionality.")
        .with_fields(vec![Field::new("HTTP status", status, Format::Number)])
        .with_findings(findings)
        .with_max_age(180);
        Ok(Report::of(observation))
    }
}

#[cfg(test)]
mod tests {
    use garrison_testing::http::{answer, serve};

    use super::*;
    use crate::testing::{Canned, config, context, table};

    fn probe(url: &str, expect: u16) -> Observation {
        let directory = tempfile::tempdir().unwrap();
        let (config, runner) = (config(directory.path()), Canned(String::new()));
        let raw =
            format!("id = \"api\"\ntitle = \"API\"\nurl = \"{url}\"\nexpect_status = {expect}");
        let provider = Http::new(&table(&raw)).unwrap();
        provider
            .collect(&context(&config, &runner))
            .unwrap()
            .observations
            .remove(0)
    }

    #[test]
    fn an_endpoint_is_ok_only_with_the_expected_status() {
        let ok = serve(vec![answer(204, "")]);
        let observation = probe(&ok.url, 204);
        assert_eq!(
            (observation.state, observation.findings.len()),
            (State::Ok, 0)
        );
        let other = serve(vec![answer(503, "")]);
        let observation = probe(&other.url, 204);
        assert_eq!(observation.state, State::Failed);
        assert_eq!(observation.findings, ["Answered HTTP 503, expected 204."]);
    }
}
