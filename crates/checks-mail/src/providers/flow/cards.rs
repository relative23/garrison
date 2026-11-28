//! The cards of the mail flow, one function each, from the week that was
//! read: spam and ham, the milter's verdicts, the checks of incoming senders
//! and TLS in transit.

use garrison_core::modules::ModuleId;
use garrison_core::observations::{Column, Field, Format, State, Table};
use garrison_core::time;
use serde_json::{Value, json};

use super::read::Week;
use super::{Flow, Read};
use crate::context::{Context, ProviderError, Report};

/// The events of a milter that Stalwart could not reach.
const NOT_REACHED: [&str; 4] = [
    "milter.action-connection-failure",
    "milter.timeout",
    "milter.io-error",
    "milter.disconnected",
];
/// The events of a milter answer that is no answer of the protocol as
/// Stalwart reads it. They are recorded for their number alone: the
/// receiver keeps nothing of the frame they carry.
const NOT_OF_THE_PROTOCOL: [&str; 2] = ["milter.frame-invalid", "milter.unexpected-response"];

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

/// What the lists of a card left out, as findings, and whether they read
/// only a part of the week: `kinds` are the event types they read, `lists`
/// each list with its name in the reading, the rows it shows and what they
/// are. A list that shows its busiest rows is no part: the rows it shows
/// are whole.
fn left_out(week: &Week, kinds: &[&str], lists: &[(&str, usize, &str)]) -> (bool, Vec<String>) {
    let part = kinds.iter().any(|kind| week.cut.contains(*kind));
    let mut findings = Vec::new();
    if part {
        findings.push(
            "The list counts only the newest events of each kind it reads; more were recorded in \
             these seven days."
                .to_owned(),
        );
    }
    for (list, shown, what) in lists {
        if let Some(all) = week.listed.get(*list) {
            findings.push(format!("The {shown} busiest of {all} {what} are listed."));
        }
    }
    (part, findings)
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
        self.spam_domains(context, read, report)
    }

    /// The same by the domain of the mailbox, where the week had any.
    fn spam_domains(
        &self,
        context: &Context<'_>,
        read: &Read,
        report: &mut Report,
    ) -> Result<(), ProviderError> {
        let week = &read.week;
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
            // Without the domains it is about, the card is not in order, and
            // without some of them it is a part; that mail is counted under
            // "unknown".
            let unread = read.domains_unread.as_ref();
            let accounts_left = read.domains_left.clone();
            let (part, cut) = left_out(
                week,
                &["message-ingest.ham", "message-ingest.spam"],
                &[("filed", week.filed.len(), "domains")],
            );
            let mut by_domain = self
                .observation(
                    context,
                    read,
                    "spam-domains",
                    "Spam and ham by domain",
                    ModuleId::Spam,
                    if unread.is_some() {
                        State::Unknown
                    } else if part || accounts_left.is_some() {
                        State::Partial
                    } else {
                        State::Ok
                    },
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
            by_domain.findings.extend(
                unread.map(|why| format!("The domains of the mailboxes are not known: {why}.")),
            );
            by_domain.findings.extend(accounts_left);
            by_domain.findings.extend(cut);
            report.observations.push(by_domain);
        }
        Ok(())
    }

    /// The scanner's verdicts by day. A host without a milter has none, and
    /// then no card either. A reply of the milter's own may refuse a message
    /// or defer it, and Stalwart's event does not say which (measured with
    /// Stalwart 1.2.0), so it is counted apart, and as an answer.
    pub(super) fn milter(
        &self,
        context: &Context<'_>,
        read: &Read,
        report: &mut Report,
    ) -> Result<(), ProviderError> {
        let week = &read.week;
        let of = |kind: &str| week.of(&format!("milter.action-{kind}"));
        let (accepted, rejected, discarded) = (of("accept"), of("reject"), of("discard"));
        let (deferred, replied) = (of("temp-fail"), of("reply-code"));
        let by_day = |kinds: &[&str]| -> Vec<u64> {
            (0..week.days.len())
                .map(|day| kinds.iter().map(|kind| week.of(kind)[day]).sum())
                .collect()
        };
        let unreached = by_day(&NOT_REACHED);
        // An answer larger than Stalwart reads (its `maxResponseSize`) and
        // one that is no answer of the protocol are no verdict either, and
        // no other event comes with them (measured with Stalwart 1.2.1).
        let oversized = week.of("milter.frame-too-large");
        let garbled = by_day(&NOT_OF_THE_PROTOCOL);
        let unread: Vec<u64> = oversized.iter().zip(&garbled).map(|(a, b)| a + b).collect();
        let all = [
            &accepted, &rejected, &discarded, &deferred, &replied, &unreached, &unread,
        ];
        if read.problem.is_none() && all.iter().all(|days| days.iter().all(|count| *count == 0)) {
            return Ok(());
        }
        // Since yesterday: a scanner that was away for a moment shows for a day.
        let recent = |days: &[u64]| -> u64 { days.iter().rev().take(2).sum() };
        let mut findings = Vec::new();
        let unreached_lately = recent(&unreached);
        if unreached_lately > 0 {
            findings.push(format!(
                "The milter could not be reached {unreached_lately} times since yesterday. What \
                 Stalwart does with mail then, defer it or let it pass unscanned, is the milter's \
                 setting there."
            ));
        }
        for (count, what) in [
            (recent(&oversized), "more than Stalwart reads of an answer"),
            (
                recent(&garbled),
                "what Stalwart could not read as an answer of the milter protocol",
            ),
        ] {
            if count > 0 {
                findings.push(format!(
                    "A milter answered {count} times since yesterday with {what}, so it gave no \
                     verdict for that mail. What Stalwart does with mail then, defer it or let it \
                     pass unscanned, is the milter's setting there."
                ));
            }
        }
        // A deferral is no verdict: where a milter deferred every message,
        // as a scanner does that cannot scan, nothing was judged, whatever
        // another milter answered before it. A deferral ends a message, so
        // their number is that of the messages.
        if week.deferred_all {
            findings.push(format!(
                "Every message shown to the milters since yesterday was deferred ({} in all), so \
                 their senders were asked to try again later. A scanner that cannot scan answers \
                 so, as clamav-milter does while clamd is down.",
                recent(&deferred)
            ));
        }
        let state = if findings.is_empty() {
            State::Ok
        } else {
            State::Warning
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
                    json!(replied[day]),
                    json!(unreached[day]),
                    json!(unread[day]),
                ]
            })
            .collect();
        let mut observation = self
            .observation(context, read, "milter", "Milter verdicts", ModuleId::Antivirus, state)?
            .with_scope(
                "What the scanner behind the milter said of the mail it was shown on each of the last \
                 seven days (UTC). A reply of the milter's own may refuse a message or defer it; \
                 Stalwart's event does not say which.",
            )
            .with_table(Table {
                columns: ["Day", "Accepted", "Rejected", "Discarded", "Deferred", "Own reply", "Not reached", "Answer not read"]
                    .iter()
                    .enumerate()
                    .map(|(index, label)| column(label, if index == 0 { Format::Text } else { Format::Number }))
                    .collect(),
                rows,
            });
        if read.problem.is_none() {
            // Before what the observation says of the history itself.
            observation.findings.splice(0..0, findings);
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
            let (part, cut) = left_out(
                week,
                &["smtp.spf-from-fail", "smtp.dmarc-fail"],
                &[("failing", week.failing.len(), "sender domains")],
            );
            let rows = week
                .failing
                .iter()
                .map(|(domain, spf, dmarc)| vec![json!(domain), json!(spf), json!(dmarc)])
                .collect();
            let state = if part { State::Partial } else { State::Ok };
            let mut senders = self
                .observation(context, read, "failing-senders", "Sender domains that fail the checks", ModuleId::Spam, state)?
                .with_scope(
                    "Domains whose mail failed SPF or DMARC in the last seven days: forged senders, or a \
                     sender whose own records are wrong. A domain without a record is not listed.",
                )
                .with_table(Table {
                    columns: vec![column("Sender domain", Format::Text), column("SPF failures", Format::Number), column("DMARC failures", Format::Number)],
                    rows,
                });
            senders.findings.extend(cut);
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
        let (part, cut) = left_out(
            week,
            &[
                "smtp.mail-from",
                "delivery.start-tls-unavailable",
                "delivery.start-tls-error",
            ],
            &[
                (
                    "plain_in",
                    week.plain_in.len(),
                    "sender domains without TLS",
                ),
                ("plain_out", week.plain_out.len(), "hosts without TLS"),
            ],
        );
        let state = if part { State::Partial } else { State::Ok };
        let mut observation = self
            .observation(context, read, "tls", "TLS in transit", ModuleId::DnsTls, state)?
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
        observation.findings.extend(cut);
        report.observations.push(observation);
        Ok(())
    }
}
