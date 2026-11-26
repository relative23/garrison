//! The card of the milter Stalwart asks, from `x:MtaMilter`.

use garrison_core::modules::ModuleId;
use garrison_core::observations::{Evidence, Field, Format, Observation, State};
use serde_json::json;

use super::Stalwart;
use super::answers::Milter;
use crate::context::{Context, ProviderError};
use crate::values::loosely_equal;

impl Stalwart {
    pub(super) fn milter(
        &self,
        context: &Context<'_>,
        rows: Option<&[Milter]>,
    ) -> Result<Observation, ProviderError> {
        let matches: Vec<&Milter> = rows
            .into_iter()
            .flatten()
            .filter(|row| {
                let host = self
                    .milter_host
                    .as_ref()
                    .is_none_or(|host| row.host.0 == Some(json!(host)));
                let wanted = json!(self.milter_port);
                let port = self.milter_port == 0
                    || (row.port.0.as_ref()).is_some_and(|port| loosely_equal(port, &wanted));
                host && port
            })
            .collect();
        // With a host or a port named, the one milter that is meant. Without,
        // every milter Stalwart asks.
        let named = self.milter_host.is_some() || self.milter_port != 0;
        let endpoint = |row: &Milter| format!("{}:{}", row.host.text(), row.port.text());
        let mut findings = Vec::new();
        for row in &matches {
            if row.temp_fail_on_error.0 != Some(false) {
                continue;
            }
            findings.push(if matches.len() == 1 {
                "Milter errors do not cause a temporary rejection; mail may pass unscanned."
                    .to_owned()
            } else {
                format!(
                    "Errors of the milter {} do not cause a temporary rejection; mail may pass \
                     it unscanned.",
                    endpoint(row)
                )
            });
        }
        if rows.is_some() && (matches.is_empty() || (named && matches.len() != 1)) {
            findings.push(format!(
                "Expected one matching milter, found {}.",
                matches.len()
            ));
        }
        // What holds for every one of them; unknown where one does not say.
        let all = |value: fn(&Milter) -> Option<bool>| {
            let mut values = matches.iter().map(|row| value(row)).peekable();
            values.peek()?;
            values.try_fold(true, |all, value| value.map(|value| all && value))
        };
        let endpoints: Vec<String> = matches.iter().map(|row| endpoint(row)).collect();
        let endpoint = (!endpoints.is_empty()).then(|| endpoints.join(", "));
        let state = match (rows.is_some(), findings.is_empty()) {
            (false, _) => State::Unknown,
            (true, false) => State::Warning,
            (true, true) => State::Ok,
        };
        Ok(Self::observation(
            context,
            "stalwart.milter",
            "Stalwart milter connection",
            &[ModuleId::Antivirus],
            Evidence::Configuration,
            state,
            "x:MtaMilter/get",
        )?
        .with_fields(vec![
            Field::new(
                "Matching milters",
                rows.as_ref().map(|_| matches.len()),
                Format::Number,
            ),
            Field::text("Endpoint", endpoint),
            Field::new("Enabled", all(|row| row.enable.0), Format::Boolean),
            Field::new(
                "DATA stage",
                all(|row| row.stages.0.data.0),
                Format::Boolean,
            ),
            Field::new(
                "Temporary failure on error",
                all(|row| row.temp_fail_on_error.0),
                Format::Boolean,
            ),
        ])
        .with_findings(findings))
    }
}
