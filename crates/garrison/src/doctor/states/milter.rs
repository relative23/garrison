//! The states of the macro milter's checks (`doctor/milter.rs`).

use std::fmt::Display;

use garrison_stalwart::{Error, SUPPORTED};

use crate::doctor::milter::entries::{self, Entry};
use crate::state::State;
use crate::units;

/// What mends a line setup mends; where Stalwart also asks in vain an
/// entry that is not the filter's (`others`), setup refuses until that is
/// out of Stalwart.
fn setup(others: bool) -> &'static str {
    if others {
        "Run `garrison stalwart setup` once the milters named above are out of Stalwart."
    } else {
        "Run `garrison stalwart setup`."
    }
}

/// What Stalwart does where it asks `entry` and nothing answers.
fn vainly(entry: &Entry) -> String {
    format!(
        ", where nothing answers: Stalwart {}",
        entry.meanwhile("all incoming mail")
    )
}

/// Why Stalwart's milters could not be asked: the collector's key could
/// not be read.
pub(in crate::doctor) fn key_unread(error: impl Display) -> String {
    format!("the collector's API key: {error}")
}

/// Why Stalwart at `url` did not tell its milters.
pub(in crate::doctor) fn unasked(url: &str, error: Error) -> String {
    match error {
        Error::Unavailable(why) => super::no_answer(url, why),
        Error::Limited(why) => {
            format!(
                "Stalwart refused the question for its rate limit ({why}); ask again in a minute"
            )
        }
        // A key it does not know and one without the permission alike:
        // the line on the key says which.
        Error::Denied(_) | Error::InvalidToken(_) | Error::Misconfigured(_) => {
            "Stalwart refused the collector's API key".to_owned()
        }
        Error::Unreadable(why) => format!(
            "Stalwart answered in a form this release of Garrison does not read ({why}); \
             {SUPPORTED}"
        ),
    }
}

pub(in crate::doctor) fn answers(port: u16) -> State {
    let text = format!("the macro milter answers on 127.0.0.1:{port}");
    State::new("doctor-milter-answers", text)
}

pub(in crate::doctor) fn silent(port: u16, error: &str) -> State {
    let text = format!("the macro milter does not answer on 127.0.0.1:{port}: {error}");
    State::new("doctor-milter-silent", text)
        .with_fix(format!("journalctl -u {} -n 50 shows why.", units::MILTER))
}

/// An entry Stalwart asks in vain that is not the filter's: setup leaves
/// it, and refuses to run while it is there.
fn stray(entry: &Entry) -> String {
    format!(
        "Stalwart asks a milter at {} (entry {}), where nothing answers: Stalwart {}",
        entry.address(),
        entry.id,
        entry.meanwhile("all incoming mail")
    )
}

/// Such an entry, where Stalwart defers mail meanwhile or decides by
/// conditions of its own.
pub(in crate::doctor) fn stranded(entry: &Entry) -> State {
    State::new("doctor-milter-stranded", stray(entry)).with_fix(entries::REMOVE)
}

/// Such an entry, where Stalwart takes mail unscanned meanwhile.
pub(in crate::doctor) fn stranded_unscanned(entry: &Entry) -> State {
    State::new("doctor-milter-stranded-unscanned", stray(entry)).with_fix(entries::REMOVE)
}

/// One of the filter's entries asks it at another port than the
/// configuration's, `port`, where it answers.
pub(in crate::doctor) fn moved(entry: &Entry, port: u16, others: bool) -> State {
    let text = format!(
        "Stalwart asks the macro milter at {}, but the configuration has it on \
         127.0.0.1:{port}",
        entry.address()
    );
    State::new("doctor-milter-entry-moved", text).with_fix(setup(others))
}

/// One of the filter's entries asks it where nothing answers, at the
/// configuration's port or, `elsewhere`, at another.
pub(in crate::doctor) fn unanswered(entry: &Entry, elsewhere: Option<u16>, others: bool) -> State {
    let elsewhere = elsewhere
        .map(|port| format!(", but the configuration has it on 127.0.0.1:{port}"))
        .unwrap_or_default();
    let text = format!(
        "Stalwart asks the macro milter at {}{elsewhere}{}",
        entry.address(),
        vainly(entry)
    );
    State::new("doctor-milter-entry-unanswered", text).with_fix(setup(others))
}

pub(in crate::doctor) fn no_entry(port: u16, others: bool) -> State {
    let text = format!(
        "Stalwart has no entry for the macro milter on 127.0.0.1:{port} and asks it nothing"
    );
    State::new("doctor-milter-entry-missing", text).with_fix(setup(others))
}

pub(in crate::doctor) fn several(count: usize, port: u16, others: bool) -> State {
    let text = format!("Stalwart has {count} entries for the macro milter on 127.0.0.1:{port}");
    State::new("doctor-milter-entries-several", text).with_fix(setup(others))
}

pub(in crate::doctor) fn off(port: u16, others: bool) -> State {
    let text = format!("Stalwart's entry for the macro milter on 127.0.0.1:{port} is switched off");
    State::new("doctor-milter-entry-off", text).with_fix(setup(others))
}

pub(in crate::doctor) fn conditional(port: u16, others: bool) -> State {
    let text = format!(
        "Stalwart's entry for the macro milter on 127.0.0.1:{port} is switched on only under \
         conditions of its own"
    );
    State::new("doctor-milter-entry-conditional", text).with_fix(setup(others))
}

pub(in crate::doctor) fn before_data(port: u16, others: bool) -> State {
    let text = format!(
        "Stalwart does not ask the macro milter on 127.0.0.1:{port} once a message's data \
         has arrived, so it sees no attachment"
    );
    State::new("doctor-milter-entry-before-data", text).with_fix(setup(others))
}

/// Stalwart does with mail what `entry` says while the filter does not
/// answer, though `when_unreachable` says to `defer` it or not.
pub(in crate::doctor) fn when_unreachable(entry: &Entry, defer: bool, others: bool) -> State {
    let wanted = if defer { "defer" } else { "accept" };
    let text = format!(
        "Stalwart {} while the macro milter does not answer, though when_unreachable is \
         \"{wanted}\"",
        entry.meanwhile("mail")
    );
    State::new("doctor-milter-when-unreachable", text).with_fix(setup(others))
}

pub(in crate::doctor) fn asked(entry: &Entry, port: u16) -> State {
    let text = format!(
        "Stalwart asks the macro milter on 127.0.0.1:{port} about every message and {} \
         while it does not answer",
        entry.meanwhile("mail")
    );
    State::new("doctor-milter-entry-asked", text)
}

/// One of the filter's entries, where the configuration no longer has the
/// filter; `vain` where nothing answers it.
pub(in crate::doctor) fn dropped(entry: &Entry, vain: bool, others: bool) -> State {
    let unanswered = if vain { vainly(entry) } else { String::new() };
    let text = format!(
        "Stalwart still asks the macro milter at {}, which the configuration no longer \
         has{unanswered}",
        entry.address()
    );
    State::new("doctor-milter-entry-dropped", text).with_fix(format!(
        "{} It takes the filter out of Stalwart; until then mail may be deferred.",
        setup(others)
    ))
}

pub(in crate::doctor) fn entry_unknown(port: u16, why: &str) -> State {
    let text = format!("whether Stalwart asks the macro milter on 127.0.0.1:{port}: {why}");
    State::new("doctor-milter-entry-unknown", text)
}

pub(in crate::doctor) fn stranded_unknown(why: &str) -> State {
    let text = format!("whether Stalwart asks a milter where nothing answers: {why}");
    State::new("doctor-milter-stranded-unknown", text)
}

/// An entry as setup writes it, at `port`, with `defer` as its
/// `tempFailOnError`.
#[cfg(test)]
fn entry(id: &str, port: u16, defer: Option<bool>) -> Entry {
    serde_json::from_value(
        serde_json::json!({"id": id, "host": "127.0.0.1", "port": port,
        "enable": {"match": {}, "else": "true"}, "stages": {"data": true},
        "tempFailOnError": defer}),
    )
    .unwrap()
}

#[cfg(test)]
pub(super) fn rows() -> Vec<(State, &'static str)> {
    [answering(), asking()].concat()
}

/// Whether the filter answers, the entries Stalwart asks in vain, and
/// what differs in the filter's entry.
#[cfg(test)]
fn answering() -> Vec<(State, &'static str)> {
    let (filter, unscanned, other) = (
        entry("m", 8096, Some(true)),
        entry("x", 9000, Some(false)),
        entry("o", 11332, None),
    );
    vec![
        (
            answers(8096),
            "the macro milter answers on 127.0.0.1:8096 [doctor-milter-answers]",
        ),
        (
            silent(8096, "Connection refused (os error 111)"),
            "the macro milter does not answer on 127.0.0.1:8096: Connection refused (os error \
             111) [doctor-milter-silent]\n      journalctl -u garrison-milter.service -n 50 \
             shows why.",
        ),
        (
            stranded(&other),
            "Stalwart asks a milter at 127.0.0.1:11332 (entry o), where nothing answers: \
             Stalwart decides by conditions of its own what to do with all incoming mail \
             [doctor-milter-stranded]\n      If nothing is to answer there, remove that entry in \
             the Stalwart WebUI (Settings ▸ MTA ▸ Milters) and reload its settings.",
        ),
        (
            stranded_unscanned(&unscanned),
            "Stalwart asks a milter at 127.0.0.1:9000 (entry x), where nothing answers: Stalwart \
             takes all incoming mail unscanned [doctor-milter-stranded-unscanned]\n      If \
             nothing is to answer there, remove that entry in the Stalwart WebUI (Settings ▸ MTA \
             ▸ Milters) and reload its settings.",
        ),
        (
            moved(&filter, 8097, false),
            "Stalwart asks the macro milter at 127.0.0.1:8096, but the configuration has it on \
             127.0.0.1:8097 [doctor-milter-entry-moved]\n      Run `garrison stalwart setup`.",
        ),
        (
            unanswered(&filter, Some(8097), true),
            "Stalwart asks the macro milter at 127.0.0.1:8096, but the configuration has it on \
             127.0.0.1:8097, where nothing answers: Stalwart defers all incoming mail \
             [doctor-milter-entry-unanswered]\n      Run `garrison stalwart setup` once the \
             milters named above are out of Stalwart.",
        ),
        (
            no_entry(8096, false),
            "Stalwart has no entry for the macro milter on 127.0.0.1:8096 and asks it nothing \
             [doctor-milter-entry-missing]\n      Run `garrison stalwart setup`.",
        ),
        (
            several(2, 8096, false),
            "Stalwart has 2 entries for the macro milter on 127.0.0.1:8096 \
             [doctor-milter-entries-several]\n      Run `garrison stalwart setup`.",
        ),
        (
            off(8096, false),
            "Stalwart's entry for the macro milter on 127.0.0.1:8096 is switched off \
             [doctor-milter-entry-off]\n      Run `garrison stalwart setup`.",
        ),
        (
            conditional(8096, false),
            "Stalwart's entry for the macro milter on 127.0.0.1:8096 is switched on only under \
             conditions of its own [doctor-milter-entry-conditional]\n      Run `garrison \
             stalwart setup`.",
        ),
        (
            before_data(8096, false),
            "Stalwart does not ask the macro milter on 127.0.0.1:8096 once a message's data has \
             arrived, so it sees no attachment [doctor-milter-entry-before-data]\n      Run \
             `garrison stalwart setup`.",
        ),
    ]
}

/// How the filter's entry asks it, and what could not be asked.
#[cfg(test)]
fn asking() -> Vec<(State, &'static str)> {
    let filter = entry("m", 8096, Some(true));
    let unavailable = Error::Unavailable("connection refused".into());
    let denied = Error::Denied("forbidden".into());
    vec![
        (
            when_unreachable(&filter, false, false),
            "Stalwart defers mail while the macro milter does not answer, though \
             when_unreachable is \"accept\" [doctor-milter-when-unreachable]\n      Run \
             `garrison stalwart setup`.",
        ),
        (
            asked(&filter, 8096),
            "Stalwart asks the macro milter on 127.0.0.1:8096 about every message and defers mail \
             while it does not answer [doctor-milter-entry-asked]",
        ),
        (
            dropped(&filter, false, false),
            "Stalwart still asks the macro milter at 127.0.0.1:8096, which the configuration no \
             longer has [doctor-milter-entry-dropped]\n      Run `garrison stalwart setup`. It \
             takes the filter out of Stalwart; until then mail may be deferred.",
        ),
        (
            entry_unknown(8096, &unasked("http://127.0.0.1:8080", unavailable)),
            "whether Stalwart asks the macro milter on 127.0.0.1:8096: Stalwart did not answer at \
             http://127.0.0.1:8080 (connection refused) [doctor-milter-entry-unknown]",
        ),
        (
            stranded_unknown(&unasked("http://127.0.0.1:8080", denied)),
            "whether Stalwart asks a milter where nothing answers: Stalwart refused the \
             collector's API key [doctor-milter-stranded-unknown]",
        ),
    ]
}
