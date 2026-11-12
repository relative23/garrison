//! `garrison modules`: choose the modules this installation offers.
//!
//! Each module is listed with what `detect` found for it. The choice becomes
//! the top-level `modules = [...]` of the configuration: the edited file must
//! load and offer exactly that choice, the old one stays next to it as
//! `<file>.previous`, and the file is replaced atomically. The broker and the
//! web service read the list when they start, so as root they are restarted.

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use garrison_core::config::{self, Config};
use garrison_core::modules::ModuleId;
use garrison_core::systemd::SYSTEMCTL;

use crate::{complain, detect, say, units};

/// Every installation has these.
const ALWAYS: [ModuleId; 2] = [ModuleId::Dashboard, ModuleId::Services];
const RESTART: [&str; 2] = [units::BROKER, units::WEB];

/// A module, what was found for it, and whether that suggests switching it on.
#[derive(Debug)]
struct Row {
    id: ModuleId,
    hint: String,
    suggested: bool,
}

pub(crate) fn run(path: &Path, config: &Config, set: Option<&str>, yes: bool, adopt: bool) -> u8 {
    let chosen = if let Some(list) = set {
        match parse_list(list) {
            Ok(chosen) => chosen,
            Err(message) => {
                complain(&message);
                return 2;
            }
        }
    } else {
        let rows = rows(
            &detect::found(),
            config.broker.actions.len(),
            config.notifications.any(),
        );
        let mut chosen = config.modules.clone();
        if !crate::at_terminal() {
            say(table(&rows, &chosen).trim_end());
            say("Change it with: garrison modules --set antivirus,backups,...");
            return 0;
        }
        match choose(
            &mut io::stdin().lock(),
            &mut io::stdout(),
            &rows,
            &mut chosen,
        ) {
            Ok(true) => chosen,
            Ok(false) => {
                say("Nothing was changed.");
                return 0;
            }
            Err(error) => {
                complain(&error.to_string());
                return 1;
            }
        }
    };
    let entries = additions(
        set.is_some(),
        adopt,
        || detect::entries(&chosen, &config.collector.providers),
        offer,
    );
    if chosen == config.modules && entries.is_empty() {
        say("The configuration offers these modules already; nothing was changed.");
        return 0;
    }
    say(&format!("{}\ngoes into {}.", line(&chosen), path.display()));
    let question = "Write it? [y/N]";
    if !yes && !ask(question, false, &mut io::stdin().lock(), &mut io::stdout()) {
        say("Nothing was changed.");
        return 0;
    }
    match write(path, &chosen, &entries) {
        Ok(previous) => say(&format!(
            "Written; the previous file is {}.",
            previous.display()
        )),
        Err(message) => {
            complain(&message);
            return 1;
        }
    }
    restart();
    0
}

/// The choice at the first installation, with what `detect` found switched on.
pub(crate) fn first(path: &Path) {
    let config = match config::load(path) {
        Ok(config) => config,
        Err(error) => {
            complain(&format!("Cannot load {}: {error}", path.display()));
            return;
        }
    };
    let rows = rows(
        &detect::found(),
        config.broker.actions.len(),
        config.notifications.any(),
    );
    let mut chosen: BTreeSet<ModuleId> = rows
        .iter()
        .filter(|row| row.suggested)
        .map(|row| row.id)
        .collect();
    say("\nChoose the modules of this installation; what detect found is switched on.\n");
    // The terminal's lock must end with this statement: `offer` reads from it
    // again, and a second lock on the same thread would wait forever.
    let answer = choose(
        &mut io::stdin().lock(),
        &mut io::stdout(),
        &rows,
        &mut chosen,
    );
    match answer {
        Ok(true) => match write(
            path,
            &chosen,
            &additions(
                false,
                true,
                || detect::entries(&chosen, &config.collector.providers),
                offer,
            ),
        ) {
            Ok(_) => say(&format!("{} is in {}.", line(&chosen), path.display())),
            Err(message) => complain(&message),
        },
        _ => say("Every module stays on; change it later with garrison modules."),
    }
}

/// `antivirus,backups`: the modules besides the dashboard and services.
fn parse_list(list: &str) -> Result<BTreeSet<ModuleId>, String> {
    let mut chosen = BTreeSet::from(ALWAYS);
    let words = list
        .split(|character: char| character == ',' || character.is_whitespace())
        .filter(|word| !word.is_empty());
    for word in words {
        let id = word.parse().map_err(|_| {
            let known: Vec<&str> = ModuleId::all().map(ModuleId::as_str).collect();
            format!("{word} is not a module ID; known: {}", known.join(", "))
        })?;
        chosen.insert(id);
    }
    Ok(chosen)
}

/// Every module with a hint from `found` (component IDs of `detect` and what
/// each runs), from the number of configured actions and from whether a
/// notification topic is configured (`notifying`).
fn rows(found: &BTreeMap<&str, Vec<String>>, actions: usize, notifying: bool) -> Vec<Row> {
    let units = |ids: &[&str]| -> Option<String> {
        let all: Vec<String> = ids
            .iter()
            .filter_map(|id| found.get(*id))
            .flatten()
            .cloned()
            .collect();
        (!all.is_empty()).then(|| all.join(", "))
    };
    let stalwart = |hint: &str| {
        if found.contains_key("stalwart") {
            (hint.to_owned(), true)
        } else {
            ("Stalwart not found".to_owned(), false)
        }
    };
    ModuleId::all()
        .map(|id| {
            let (hint, suggested) = match id {
                ModuleId::Dashboard | ModuleId::Services => ("always on".to_owned(), true),
                ModuleId::Antivirus => units(&["clamav-scanner", "clamav-milter"])
                    .map_or(("no ClamAV found".to_owned(), false), |units| {
                        (format!("ClamAV found: {units}"), true)
                    }),
                ModuleId::Spam => stalwart("Stalwart's own spam filter"),
                ModuleId::Attacks | ModuleId::Deliveries | ModuleId::Sessions | ModuleId::Logs => {
                    stalwart("events from Stalwart's webhook")
                }
                ModuleId::Backups => units(&["backups"])
                    .map_or(("no backup tool found".to_owned(), false), |found| {
                        (format!("found: {found}"), true)
                    }),
                ModuleId::Alerts if notifying => ("notifications are configured".to_owned(), true),
                ModuleId::Alerts => units(&["notifications"]).map_or(
                    (
                        "an ntfy topic, a webhook or a mailbox, or receipts of an outside monitor"
                            .to_owned(),
                        false,
                    ),
                    |units| (format!("ntfy found: {units}"), true),
                ),
                ModuleId::DnsTls => ("certificate checks need nothing else".to_owned(), true),
                ModuleId::Actions => {
                    let noun = if actions == 1 { "action" } else { "actions" };
                    (format!("{actions} {noun} configured"), actions > 0)
                }
            };
            Row {
                id,
                hint,
                suggested,
            }
        })
        .collect()
}

fn table(rows: &[Row], chosen: &BTreeSet<ModuleId>) -> String {
    let mut text = String::new();
    for (number, row) in rows.iter().enumerate() {
        let mark = if chosen.contains(&row.id) { 'x' } else { ' ' };
        let label = row.id.module().label;
        let _ = writeln!(text, "{:>3} [{mark}] {label:<15} {}", number + 1, row.hint);
    }
    text
}

/// Switch modules by number until Enter saves (`true`) or `q` leaves (`false`).
fn choose(
    input: &mut impl BufRead,
    output: &mut impl Write,
    rows: &[Row],
    chosen: &mut BTreeSet<ModuleId>,
) -> io::Result<bool> {
    loop {
        write!(output, "\n{}", table(rows, chosen))?;
        write!(
            output,
            "Numbers to switch on or off, Enter to save, q to leave without changes: "
        )?;
        output.flush()?;
        let mut answer = String::new();
        if input.read_line(&mut answer)? == 0 {
            return Ok(false);
        }
        match answer.trim() {
            "" => return Ok(true),
            "q" => return Ok(false),
            words => {
                for word in
                    words.split(|character: char| character == ',' || character.is_whitespace())
                {
                    let row = word
                        .parse::<usize>()
                        .ok()
                        .and_then(|number| number.checked_sub(1))
                        .and_then(|index| rows.get(index));
                    match row {
                        Some(row) if ALWAYS.contains(&row.id) => {
                            writeln!(output, "{} is always on.", row.id.module().label)?;
                        }
                        Some(row) => {
                            if !chosen.remove(&row.id) {
                                chosen.insert(row.id);
                            }
                        }
                        None if word.is_empty() => {}
                        None => writeln!(output, "{word} is not a number from the list.")?,
                    }
                }
            }
        }
    }
}

/// The provider entries that `detect` found for the chosen modules and the
/// configuration lacks: with `--set` (`listed`) only on `--adopt`, in the
/// terminal if the operator accepts them.
fn additions(
    listed: bool,
    adopt: bool,
    found: impl FnOnce() -> String,
    accept: impl FnOnce(&str) -> bool,
) -> String {
    if listed && !adopt {
        return String::new();
    }
    let found = found();
    if listed || found.is_empty() || accept(&found) {
        found
    } else {
        String::new()
    }
}

/// Shows provider entries; adding them is the default.
fn offer(found: &str) -> bool {
    say(&format!("\n{}", found.trim_end()));
    let question = "Add these entries for what detect found? [Y/n]";
    ask(question, true, &mut io::stdin().lock(), &mut io::stdout())
}

/// A yes or no; Enter, or an answer that is neither, takes the default.
fn ask(question: &str, default: bool, input: &mut impl BufRead, output: &mut impl Write) -> bool {
    let _ = write!(output, "{question} ");
    let _ = output.flush();
    let mut answer = String::new();
    if input.read_line(&mut answer).is_err() {
        return false;
    }
    match answer.trim() {
        "y" | "Y" | "yes" => true,
        "n" | "N" | "no" => false,
        _ => default,
    }
}

/// The configuration line; the dashboard and services go without saying.
fn line(chosen: &BTreeSet<ModuleId>) -> String {
    let ids: Vec<String> = chosen
        .iter()
        .filter(|id| !ALWAYS.contains(id))
        .map(|id| format!("\"{}\"", id.as_str()))
        .collect();
    format!("modules = [{}]", ids.join(", "))
}

/// `text` with its top-level `modules` set to `chosen`. A key that is there,
/// also one over several lines, is replaced; otherwise the line goes last among
/// the top-level lines. Comments and sections stay as they are.
fn with_modules(text: &str, chosen: &BTreeSet<ModuleId>) -> String {
    let lines: Vec<&str> = text.lines().collect();
    // Top-level keys come before the first section header.
    let top = lines
        .iter()
        .position(|line| line.trim_start().starts_with('['))
        .unwrap_or(lines.len());
    let (start, end) = if let Some(start) = (0..top).find(|index| is_modules(lines[*index])) {
        let end = (start..top)
            .find(|index| lines[*index].contains(']'))
            .map_or(start + 1, |index| index + 1);
        (start, end)
    } else {
        // After the last non-empty top-level line.
        let at = (0..top)
            .rev()
            .find(|index| !lines[*index].trim().is_empty())
            .map_or(0, |index| index + 1);
        (at, at)
    };
    let mut result: Vec<String> = lines[..start]
        .iter()
        .map(|line| (*line).to_owned())
        .collect();
    result.push(line(chosen));
    result.extend(lines[end..].iter().map(|line| (*line).to_owned()));
    result.join("\n") + "\n"
}

fn is_modules(line: &str) -> bool {
    line.trim_start()
        .strip_prefix("modules")
        .is_some_and(|rest| rest.trim_start().starts_with('='))
}

/// Writes `chosen`, and provider `entries` at the end, into the file at `path`
/// and keeps the old file next to it.
fn write(path: &Path, chosen: &BTreeSet<ModuleId>, entries: &str) -> Result<PathBuf, String> {
    let failed = |error: &dyn std::fmt::Display| format!("{}: {error}", path.display());
    let text = fs::read_to_string(path).map_err(|error| failed(&error))?;
    let mut updated = with_modules(&text, chosen);
    if !entries.is_empty() {
        updated.push('\n');
        updated.push_str(entries);
    }
    // Only a file that loads, offers exactly this choice and has providers the
    // collector accepts replaces the old one.
    let loaded = config::from_text(&updated).map_err(|error| failed(&error))?;
    if loaded.modules != *chosen {
        return Err(failed(&"the edited file does not offer the chosen modules"));
    }
    garrison_collector::build(&loaded.collector.providers).map_err(|error| failed(&error))?;
    crate::config_file::replace(path, &text, &updated)
}

/// The broker and the web service read the modules when they start.
fn restart() {
    let apply = format!("Restart {} to apply it.", RESTART.join(" and "));
    if !rustix::process::geteuid().is_root() {
        say(&apply);
        return;
    }
    let mut arguments = vec![SYSTEMCTL, "try-restart"];
    arguments.extend(RESTART);
    match garrison_core::command::run(&arguments, Duration::from_secs(60)) {
        Ok(output) if output.code == Some(0) => {
            say("The broker and the web service were restarted where they ran.");
        }
        _ => complain(&apply),
    }
}
