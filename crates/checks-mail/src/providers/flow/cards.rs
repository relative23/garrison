//! The cards of the mail flow, one function each, from the week that was
//! read: spam and ham, the milter's verdicts, the checks of incoming senders
//! and TLS in transit.

use garrison_core::modules::ModuleId;
use garrison_core::observations::{Column, Field, Format, State, Table};
use garrison_core::time;
use serde_json::{Value, json};

use super::{Flow, Read};
use crate::context::{Context, ProviderError, Report};

/// The events of a milter that Stalwart could not reach.
const NOT_REACHED: [&str; 4] = [
    "milter.action-connection-failure",
    "milter.timeout",
    "milter.io-error",
    "milter.disconnected",
];

fn column(label: &str, format: Format) -> Column {
    Column {
        label: label.to_owned(),
        format,
    }
}

/// `part` of `whole` in per cent; a dash where there is nothing to divide.
fn share(part: u64, whole: u64) -> String {
    (part * 100 + whole / 2)
        .checked_div(whole)
        .map_or_else(|| "–".to_owned(), |per_cent| format!("{per_cent} %"))
}

/// The day a second belongs to, as `2026-11-11`.
fn date(second: i64) -> String {
    time::Timestamp::from_second(second)
        .map(|at| time::isoformat(at).chars().take(10).collect())
        .unwrap_or_default()
}

impl Flow {
    pub(super) fn spam(
        &self,
        context: &Context<'_>,
        read: &Read,
        report: &mut Report,
    ) -> Result<(), ProviderError> {
        let week = &read.week;
        let (ham, spam) = (
            week.of("message-ingest.ham"),
            week.of("message-ingest.spam"),
        );
        let rows = week
            .days
            .iter()
            .enumerate()
            .rev()
            .map(|(day, start)| {
                vec![
                    json!(date(*start)),
                    json!(ham[day]),
                    json!(spam[day]),
                    json!(share(spam[day], ham[day] + spam[day])),
                ]
            })
            .collect();
        let trained = time::Timestamp::from_second(week.last_training.unwrap_or(-1))
            .ok()
            .map(time::isoformat);
        let by_day = self
            .observation(
                context,
                read,
                "spam",
                "Spam and ham",
                ModuleId::Spam,
                State::Ok,
            )?
            .with_scope(
                "How Stalwart's filter filed delivered mail on each of the last seven days (UTC).",
            )
            .with_fields(vec![
                Field::new(
                    "Training runs in these days",
                    week.sum(&["spam.train-completed"]),
                    Format::Number,
                ),
                Field::new(
                    "Last training",
                    trained.filter(|_| week.last_training.is_some()),
                    Format::Datetime,
                ),
            ])
            .with_table(Table {
                columns: vec![
                    column("Day", Format::Text),
                    column("Ham", Format::Number),
                    column("Spam", Format::Number),
                    column("Spam share", Format::Text),
                ],
                rows,
            });
        report.observations.push(by_day);
        if !week.filed.is_empty() {
            let rows = week
                .filed
                .iter()
                .map(|(domain, ham, spam)| {
                    vec![
                        json!(domain),
                        json!(ham),
                        json!(spam),
                        json!(share(*spam, ham + spam)),
                    ]
                })
                .collect();
            let by_domain = self
                .observation(
                    context,
                    read,
                    "spam-domains",
                    "Spam and ham by domain",
                    ModuleId::Spam,
                    State::Ok,
                )?
                .with_scope("The same seven days by the domain of the mailbox the mail went to.")
                .with_table(Table {
                    columns: vec![
                        column("Domain", Format::Text),
                        column("Ham", Format::Number),
                        column("Spam", Format::Number),
                        column("Spam share", Format::Text),
                    ],
                    rows,
                });
            report.observations.push(by_domain);
        }
        Ok(())
    }

    /// The scanner's verdicts by day. A host without a milter has none, and
    /// then no card either.
    pub(super) fn milter(
        &self,
        context: &Context<'_>,
        read: &Read,
        report: &mut Report,
    ) -> Result<(), ProviderError> {
        let week = &read.week;
        let of = |kind: &str| week.of(&format!("milter.action-{kind}"));
        let (accepted, rejected, discarded) = (of("accept"), of("reject"), of("discard"));
        let deferred: Vec<u64> = of("temp-fail")
            .iter()
            .zip(of("reply-code"))
            .map(|(left, right)| left + right)
            .collect();
        let unreached: Vec<u64> = (0..week.days.len())
            .map(|day| NOT_REACHED.iter().map(|kind| week.of(kind)[day]).sum())
            .collect();
        let all = [&accepted, &rejected, &discarded, &deferred, &unreached];
        if read.problem.is_none() && all.iter().all(|days| days.iter().all(|count| *count == 0)) {
            return Ok(());
        }
        // Since yesterday: a scanner that was away for a moment shows for a day.
        let recent: u64 = unreached.iter().rev().take(2).sum();
        let (state, findings) = if recent > 0 {
            (
                State::Warning,
                vec![format!(
                    "The milter could not be reached {recent} times since yesterday. What Stalwart does \
                     with mail then, defer it or let it pass unscanned, is the milter's setting there."
                )],
            )
        } else {
            (State::Ok, Vec::new())
        };
        let rows = week
            .days
            .iter()
            .enumerate()
            .rev()
            .map(|(day, start)| {
                vec![
                    json!(date(*start)),
                    json!(accepted[day]),
                    json!(rejected[day]),
                    json!(discarded[day]),
                    json!(deferred[day]),
                    json!(unreached[day]),
                ]
            })
            .collect();
        let mut observation = self
            .observation(context, read, "milter", "Milter verdicts", ModuleId::Antivirus, state)?
            .with_scope("What the scanner behind the milter said of the mail it was shown on each of the last seven days (UTC).")
            .with_table(Table {
                columns: ["Day", "Accepted", "Rejected", "Discarded", "Deferred", "Not reached"]
                    .iter()
                    .enumerate()
                    .map(|(index, label)| column(label, if index == 0 { Format::Text } else { Format::Number }))
                    .collect(),
                rows,
            });
        if read.problem.is_none() {
            observation = observation.with_findings(findings);
        }
        report.observations.push(observation);
        Ok(())
    }

    pub(super) fn authentication(
        &self,
        context: &Context<'_>,
        read: &Read,
        report: &mut Report,
    ) -> Result<(), ProviderError> {
        let week = &read.week;
        let rows = [
            ("SPF of the greeting (EHLO)", "spf-ehlo"),
            ("SPF of the sender", "spf-from"),
            ("DKIM", "dkim"),
            ("DMARC", "dmarc"),
            ("ARC", "arc"),
            ("Reverse name", "iprev"),
        ]
        .iter()
        .map(|(label, kind)| {
            let passed = week.sum(&[&format!("smtp.{kind}-pass")]);
            let failed = week.sum(&[&format!("smtp.{kind}-fail")]);
            vec![
                json!(label),
                json!(passed),
                json!(failed),
                json!(share(passed, passed + failed)),
            ]
        })
        .collect();
        let checks = self
            .observation(context, read, "authentication", "Checks of incoming senders", ModuleId::Spam, State::Ok)?
            .with_scope(
                "How the mail of the last seven days fared in Stalwart's checks of its sender. Not passed \
                 includes senders that publish no record to check against.",
            )
            .with_table(Table {
                columns: vec![column("Check", Format::Text), column("Passed", Format::Number), column("Not passed", Format::Number), column("Passed share", Format::Text)],
                rows,
            });
        report.observations.push(checks);
        if !week.failing.is_empty() {
            let rows = week
                .failing
                .iter()
                .map(|(domain, spf, dmarc)| vec![json!(domain), json!(spf), json!(dmarc)])
                .collect();
            let senders = self
                .observation(context, read, "failing-senders", "Sender domains that fail the checks", ModuleId::Spam, State::Ok)?
                .with_scope(
                    "Domains whose mail failed SPF or DMARC in the last seven days: forged senders, or a \
                     sender whose own records are wrong. A domain without a record is not listed.",
                )
                .with_table(Table {
                    columns: vec![column("Sender domain", Format::Text), column("SPF failures", Format::Number), column("DMARC failures", Format::Number)],
                    rows,
                });
            report.observations.push(senders);
        }
        Ok(())
    }

    pub(super) fn tls(
        &self,
        context: &Context<'_>,
        read: &Read,
        report: &mut Report,
    ) -> Result<(), ProviderError> {
        let week = &read.week;
        let (secured, plain) = week.inbound;
        let sent = week.sum(&["delivery.start-tls"]);
        let unsecured = week.sum(&["delivery.start-tls-unavailable", "delivery.start-tls-error"]);
        let mut rows: Vec<Vec<Value>> = Vec::new();
        for (domain, count) in &week.plain_in {
            rows.push(vec![json!("incoming"), json!(domain), json!(count)]);
        }
        for (host, count) in &week.plain_out {
            rows.push(vec![json!("outgoing"), json!(host), json!(count)]);
        }
        let observation = self
            .observation(context, read, "tls", "TLS in transit", ModuleId::DnsTls, State::Ok)?
            .with_scope(
                "Mail of the last seven days between this server and others: incoming on port 25 with \
                 and without STARTTLS, and outgoing deliveries to hosts that offered TLS or did not.",
            )
            .with_fields(vec![
                Field::new("Incoming with TLS", secured, Format::Number),
                Field::new("Incoming without TLS", plain, Format::Number),
                Field::text("Incoming share with TLS", share(secured, secured + plain)),
                Field::new("Outgoing with TLS", sent, Format::Number),
                Field::new("Outgoing without TLS", unsecured, Format::Number),
                Field::text("Outgoing share with TLS", share(sent, sent + unsecured)),
            ])
            .with_table(Table {
                columns: vec![column("Direction", Format::Text), column("Sender domain or host", Format::Text), column("Without TLS", Format::Number)],
                rows,
            });
        report.observations.push(observation);
        Ok(())
    }
}
