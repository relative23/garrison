//! The two cards a reading makes: whether an address stands on a blocklist,
//! and whether its reverse name fits.

use garrison_core::observations::{
    Column, Evidence, Field, Format, Observation, Required, State, Table,
};
use serde_json::json;

use super::asker::SLOW;
use super::verdict::Said;
use super::{Read, Reputation, shown};
use crate::context::{Context, Provider};

impl Reputation {
    /// A listing is a failure; a list without a verdict is only a row.
    pub(super) fn blocklists(
        &self,
        context: &Context<'_>,
        read: &Read,
        unknown: Option<&String>,
        fields: Vec<Field>,
    ) -> Result<Observation, crate::context::ProviderError> {
        let mut rows = Vec::new();
        let mut listed = Vec::new();
        let mut verdicts = 0;
        for address in &read.addresses {
            for (list, said) in &address.lists {
                let list = shown(list);
                let result = match said {
                    Said::Listed(code) => {
                        listed.push(format!("{} is listed on {list} ({code}).", address.address));
                        verdicts += 1;
                        format!("listed ({code})")
                    }
                    Said::Clear => {
                        verdicts += 1;
                        "not listed".to_owned()
                    }
                    Said::Unanswered(reason) => format!("no verdict: {reason}"),
                };
                rows.push(vec![json!(address.address), json!(list), json!(result)]);
            }
        }
        // A list left unasked for its time concerns this card alone, as
        // does one of the Data Query Service that this run had no key for.
        let lists_unasked = read.lists_unasked();
        let keyless = read.keyless.as_ref().map(|why| {
            format!(
                "The lists of Spamhaus' Data Query Service written without their key were not \
                 asked: {why}."
            )
        });
        let partial =
            read.cut.is_some() || !read.left_out.is_empty() || lists_unasked || keyless.is_some();
        let state = match (unknown, listed.is_empty(), verdicts) {
            (Some(_), _, _) | (None, true, 0) => State::Unknown,
            (None, false, _) => State::Failed,
            (None, true, _) if partial => State::Partial,
            (None, true, _) => State::Ok,
        };
        let mut findings = match (unknown, verdicts) {
            (Some(unknown), _) => vec![unknown.clone()],
            // What was not asked is said once, beside both cards.
            (None, 0) if read.cut.is_some() || lists_unasked || keyless.is_some() => Vec::new(),
            (None, 0) => vec!["No list gave a verdict.".to_owned()],
            (None, _) => listed,
        };
        if unknown.is_none() && lists_unasked {
            findings.push(format!("Not every list was asked: {SLOW}."));
        }
        if unknown.is_none() {
            findings.extend(keyless);
        }
        Ok(self
            .observation(context, "blocklists", "Blocklists", state)?
            .with_scope(
                "Whether an address this server sends from stands on a blocklist that receiving \
                 servers ask. The lists learn the addresses asked about. Asked every six hours.",
            )
            .with_fields(fields)
            .with_table(Table {
                columns: vec![column("Address"), column("List"), column("Result")],
                rows,
            })
            .with_findings(findings))
    }

    /// Each address needs a reverse name that leads back to it and is a mail
    /// host's own.
    pub(super) fn reverse(
        &self,
        context: &Context<'_>,
        read: &Read,
        unknown: Option<&String>,
        fields: Vec<Field>,
    ) -> Result<Observation, crate::context::ProviderError> {
        let mut rows = Vec::new();
        let mut findings = Vec::new();
        // Addresses whose reverse name could not be read: the card is not in
        // order for them, nor does it say that they are wrong.
        let mut unread = Vec::new();
        for address in &read.addresses {
            let result = match (&address.pointer, &address.unread) {
                (None, Some(why)) => {
                    unread.push(format!(
                        "The reverse name of {} could not be read: {why}.",
                        address.address
                    ));
                    format!("not read: {why}")
                }
                (Some(name), Some(why)) => {
                    unread.push(format!(
                        "{} names {name}; whether that leads back to it could not be read: {why}.",
                        address.address
                    ));
                    format!("not followed back: {why}")
                }
                (None, None) => {
                    findings.push(format!("{} has no reverse name.", address.address));
                    "no reverse name".to_owned()
                }
                (Some(name), None) if !address.confirmed => {
                    findings.push(format!(
                        "{} names {name}, which does not lead back to it.",
                        address.address
                    ));
                    "does not lead back".to_owned()
                }
                (Some(name), None) if !read.hosts.contains(name) => {
                    findings.push(format!(
                        "{} names {name}, which is none of the mail hosts.",
                        address.address
                    ));
                    "not a mail host's name".to_owned()
                }
                (Some(_), None) => "fits".to_owned(),
            };
            rows.push(vec![
                json!(address.address),
                json!(address.host),
                json!(address.pointer),
                json!(result),
            ]);
        }
        let partial = read.cut.is_some() || !read.left_out.is_empty() || !unread.is_empty();
        let none_read = read.addresses.len() == unread.len();
        let state = match (unknown, findings.is_empty(), none_read) {
            (Some(_), _, _) | (None, true, true) => State::Unknown,
            (None, false, _) => State::Warning,
            (None, true, false) if partial => State::Partial,
            (None, true, false) => State::Ok,
        };
        let findings = match (unknown, read.addresses.is_empty()) {
            (Some(unknown), _) => vec![unknown.clone()],
            (None, true) if read.cut.is_some() => Vec::new(),
            (None, true) => vec!["The mail hosts have no address.".to_owned()],
            (None, false) => findings.into_iter().chain(unread).collect(),
        };
        Ok(self
            .observation(context, "reverse", "Reverse names", state)?
            .with_scope(
                "Each address this server sends from should have a reverse name that leads back \
                 to it and is the name the server greets with.",
            )
            .with_fields(fields)
            .with_table(Table {
                columns: vec![
                    column("Address"),
                    column("Mail host"),
                    column("Reverse name"),
                    column("Result"),
                ],
                rows,
            })
            .with_findings(findings))
    }

    fn observation(
        &self,
        context: &Context<'_>,
        id: &str,
        title: &str,
        state: State,
    ) -> Result<Observation, crate::context::ProviderError> {
        Ok(Observation::new(Required {
            id: &format!("reputation.{id}"),
            provider: self.name(),
            title,
            modules: self.modules.iter().copied(),
            evidence: Evidence::Probe,
            state,
            checked_at: &context.checked_at(),
            source: "this host's resolver",
        })?)
    }
}

fn column(label: &str) -> Column {
    Column {
        label: label.to_owned(),
        format: Format::Text,
    }
}
