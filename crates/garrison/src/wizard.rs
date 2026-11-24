//! `garrison setup`: the guided first configuration, at a terminal. It asks
//! for the addresses and writes them into the configuration, lets the
//! operator choose the modules, connects Stalwart, grants access, starts
//! Garrison and prints the nginx server block. Every step can run again, so
//! after a failure `garrison setup` continues from what is already done.

use std::io::{self, BufRead, Write};
use std::path::Path;

use garrison_core::config::{self, Config};

use crate::{access, complain, nginx, placeholder, say, selection, setup};

/// The `[deployment]` keys the questions fill, in the order they are asked.
const ADDRESSES: [&str; 4] = ["public_origin", "issuer", "stalwart_url", "admin_url"];

fn step(number: u8, title: &str) {
    say(&format!("\n==> Step {number} of 5: {title}"));
}

/// One answer; Enter takes `default`. The end of input ends the setup.
fn ask(question: &str, default: Option<&str>) -> Result<String, String> {
    loop {
        let mut terminal = io::stdout().lock();
        let _ = match default {
            Some(default) => write!(terminal, "{question} [{default}]: "),
            None => write!(terminal, "{question}: "),
        };
        let _ = terminal.flush();
        drop(terminal);
        let mut answer = String::new();
        if io::stdin()
            .lock()
            .read_line(&mut answer)
            .map_err(|error| error.to_string())?
            == 0
        {
            return Err("The setup was ended; run `garrison setup` again to continue.".into());
        }
        let answer = answer.trim().trim_end_matches('/');
        match (answer.is_empty(), default) {
            (false, _)
                if answer.contains(['"', '\\']) || answer.chars().any(char::is_whitespace) =>
            {
                say("An address has no quotes, backslashes or spaces.");
            }
            (false, _) => return Ok(answer.to_owned()),
            (true, Some(default)) => return Ok(default.to_owned()),
            (true, None) => say("This one has no default."),
        }
    }
}

/// Whether `line` opens the table `name`: `[name]`, also with spaces inside
/// the brackets, the name quoted or a comment after it.
fn opens(line: &str, name: &str) -> bool {
    line.split('#')
        .next()
        .unwrap_or_default()
        .trim()
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .filter(|inner| !inner.starts_with('['))
        .is_some_and(|inner| inner.trim().trim_matches(['"', '\'']) == name)
}

/// `text` with `key = "value"` in the `[deployment]` section: the key's line
/// is replaced, or added at the end of the section; comments stay.
fn with_deployment(text: &str, key: &str, value: &str) -> String {
    let wanted = format!("{key} = \"{value}\"");
    let mut lines: Vec<String> = Vec::new();
    let (mut inside, mut done) = (false, false);
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            if inside && !done {
                // Before the blank lines that end the section.
                let at = lines
                    .iter()
                    .rposition(|line| !line.trim().is_empty())
                    .map_or(0, |index| index + 1);
                lines.insert(at, wanted.clone());
                done = true;
            }
            inside = opens(trimmed, "deployment");
        } else if inside
            && !done
            && trimmed
                .split_once('=')
                .is_some_and(|(name, _)| name.trim().trim_matches(['"', '\'']) == key)
        {
            lines.push(wanted.clone());
            done = true;
            continue;
        }
        lines.push(line.to_owned());
    }
    if inside && !done {
        lines.push(wanted);
    }
    lines.join("\n") + "\n"
}

/// What writing the addresses into a configuration comes to.
#[derive(Debug, PartialEq, Eq)]
enum Written {
    /// The file holds them already.
    Already,
    /// The file with them in place.
    Changed(String),
    /// With them the file does not load: why.
    Invalid(String),
    /// The `[deployment]` table is written so that no line of it could be
    /// replaced, as with dotted keys.
    Unwritable,
}

/// The configuration `text` with `answers` for [`ADDRESSES`], judged by what
/// its `[deployment]` table holds then, not by whether the text changed.
fn written(text: &str, answers: &[String]) -> Written {
    let mut updated = text.to_owned();
    for (key, value) in ADDRESSES.iter().zip(answers) {
        updated = with_deployment(&updated, key, value);
    }
    let table = updated.parse::<toml::Table>().ok();
    let deployment = table
        .as_ref()
        .and_then(|table| table.get("deployment")?.as_table());
    let held = deployment.is_some_and(|deployment| {
        ADDRESSES.iter().zip(answers).all(|(key, value)| {
            deployment.get(*key).and_then(toml::Value::as_str) == Some(value.as_str())
        })
    });
    if !held {
        return Written::Unwritable;
    }
    match config::from_text(&updated) {
        Err(error) => Written::Invalid(error.to_string()),
        Ok(_) if updated == text => Written::Already,
        Ok(_) => Written::Changed(updated),
    }
}

/// Whether `text` chooses the modules, with the top-level `modules` that
/// `garrison modules` writes; a provider's `modules` chooses none.
fn chosen(text: &str) -> bool {
    text.parse::<toml::Table>()
        .is_ok_and(|table| table.contains_key("modules"))
}

/// The current value of a `[deployment]` key, unless it is still a placeholder.
fn current(config: &Config, key: &str) -> Option<String> {
    let value = match key {
        "public_origin" => &config.deployment.public_origin,
        "issuer" => &config.deployment.issuer,
        "stalwart_url" => &config.deployment.stalwart_url,
        _ => &config.deployment.admin_url,
    };
    (!placeholder(value)).then(|| value.trim_end_matches('/').to_owned())
}

fn addresses(path: &Path) -> Result<(), String> {
    step(1, "Addresses");
    let failed = |error: &dyn std::fmt::Display| format!("{}: {error}", path.display());
    loop {
        let text = std::fs::read_to_string(path).map_err(|error| failed(&error))?;
        let config = config::from_text(&text).map_err(|error| failed(&error))?;
        let own = ask(
            "Garrison's own address, a host name of its own (https://garrison.example.org)",
            current(&config, "public_origin").as_deref(),
        )?;
        let issuer = ask(
            "Stalwart's public address, its OAuth issuer (https://mail.example.org)",
            current(&config, "issuer").as_deref(),
        )?;
        let local = ask(
            "Stalwart's HTTP listener on this host",
            current(&config, "stalwart_url").as_deref(),
        )?;
        let webui = ask(
            "The Stalwart WebUI",
            Some(
                current(&config, "admin_url")
                    .unwrap_or_else(|| format!("{issuer}/admin"))
                    .as_str(),
            ),
        )?;
        let answers = [own, issuer, local, format!("{webui}/")];
        match written(&text, &answers) {
            Written::Already => {
                say("The configuration already has these addresses.");
                return Ok(());
            }
            Written::Changed(updated) => {
                let previous = crate::config_file::replace(path, &text, &updated)?;
                say(&format!(
                    "Written; the previous file is {}.",
                    previous.display()
                ));
                return Ok(());
            }
            Written::Invalid(error) => say(&format!("{error}\nLet's try again.")),
            Written::Unwritable => {
                let [own, issuer, local, webui] = &answers;
                return Err(format!(
                    "The addresses cannot be written into {}: its deployment table is not one \
                     [deployment] section with a line for each, as dotted keys write it. Write \
                     public_origin = \"{own}\", issuer = \"{issuer}\", stalwart_url = \"{local}\" \
                     and admin_url = \"{webui}\" under [deployment] there, then run `garrison \
                     setup` again.",
                    path.display()
                ));
            }
        }
    }
}

fn load(path: &Path) -> Result<Config, String> {
    config::load(path).map_err(|error| format!("Cannot load {}: {error}", path.display()))
}

fn finish(code: u8, what: &str) -> Result<(), String> {
    if code == 0 {
        Ok(())
    } else {
        Err(format!(
            "{what} did not succeed; fix the cause above and run `garrison setup` again."
        ))
    }
}

fn guided(path: &Path) -> Result<(), String> {
    say("This sets Garrison up in five steps. Each step can be repeated.");
    addresses(path)?;
    step(2, "Modules");
    let config = load(path)?;
    let text = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
    if chosen(&text) {
        say("The modules are chosen already; `garrison modules` changes them.");
    } else {
        finish(
            selection::run(path, &config, None, false, false),
            "Choosing the modules",
        )?;
    }
    step(3, "Connect Stalwart");
    let config = load(path)?;
    let command = setup::Command::Setup {
        admin_credential: None,
        skip_metrics: false,
        webhook_url: None,
        allow_network: Vec::new(),
        rotate: false,
    };
    finish(setup::run(&config, &command), "Connecting Stalwart")?;
    step(4, "Access");
    if config.broker.policy.exists() {
        say("The access policy exists; `garrison access` changes it.");
    } else {
        finish(
            access::run(&config, &access::Command::Init { force: false }),
            "Creating the access policy",
        )?;
    }
    step(5, "Start");
    crate::install::start_installed().map_err(|error| {
        format!("Starting Garrison failed: {error}; run `garrison setup` again.")
    })?;
    say("\nLast, publish Garrison through nginx:\n");
    nginx::run(&load(path)?, false);
    say("\nThen check everything with: garrison doctor");
    Ok(())
}

pub(crate) fn run(path: &Path) -> u8 {
    if !rustix::process::geteuid().is_root() {
        complain("Run as root.");
        return 2;
    }
    if !crate::at_terminal() {
        complain(
            "garrison setup asks questions at a terminal; without one, follow \
             \"Unattended installation\" in docs/operator/installation.md.",
        );
        return 2;
    }
    if !Path::new("/opt/garrison/current").exists() {
        complain("Install the release first: ./bin/garrison install in the unpacked archive.");
        return 2;
    }
    match guided(path) {
        Ok(()) => 0,
        Err(message) => {
            complain(&message);
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: &str = "schema = 1\n\n[deployment]\n# Garrison's own host name.\n\
                        public_origin = \"https://garrison.example.org\"\nissuer = \"https://mail.example.org\"\n\n\
                        [web]\nport = 8091\n";

    #[test]
    fn a_key_is_replaced_in_its_section_and_comments_stay() {
        let text = with_deployment(TEXT, "public_origin", "https://garrison.mail.internal");
        assert!(text.contains(
            "# Garrison's own host name.\npublic_origin = \"https://garrison.mail.internal\"\n"
        ));
        assert!(text.contains("[web]\nport = 8091\n"));
        assert!(!text.contains("garrison.example.org"));
    }

    #[test]
    fn random_files_keep_every_other_line() {
        let mut noise = garrison_testing::noise::Noise::new(41);
        let lines = [
            "[deployment]",
            "[web]",
            "issuer = \"https://a.example.net\"",
            "# comment",
            "",
            "port = 8091",
            "[[providers]]",
        ];
        for _ in 0..5_000 {
            let mut text = String::new();
            for _ in 0..noise.below(12) {
                text.push_str(lines[noise.below(lines.len())]);
                text.push('\n');
            }
            let edited = with_deployment(&text, "issuer", "https://b.example.net");
            let removed = text
                .lines()
                .filter(|line| !edited.lines().any(|kept| kept == *line))
                .count();
            assert!(
                removed <= text.matches("issuer =").count(),
                "{text:?} -> {edited:?}"
            );
        }
    }

    /// The example configuration with its `[deployment]` table written in
    /// another form TOML allows.
    fn example_as(form: &str) -> String {
        let example = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deploy/config/garrison.example.toml"
        ))
        .unwrap();
        let header = "[deployment]\n";
        let (start, end) = (
            example.find(header).unwrap(),
            example.find("[web]\n").unwrap(),
        );
        let table = &example[start + header.len()..end];
        let rewritten = |line: &dyn Fn(&str) -> String| -> String {
            table.lines().map(|text| line(text) + "\n").collect()
        };
        let keyed = |text: &str| !text.starts_with('#') && text.contains(" = ");
        let (header, table) = match form {
            "a comment after the header" => ("[deployment] # addresses\n", table.to_owned()),
            "spaces inside the brackets" => ("[ deployment ]\n", table.to_owned()),
            "quoted keys" => (
                header,
                rewritten(&|text| match text.split_once(" = ") {
                    Some((key, value)) if keyed(text) => format!("\"{key}\" = {value}"),
                    _ => text.to_owned(),
                }),
            ),
            "dotted keys" => (
                "",
                rewritten(&|text| {
                    if keyed(text) {
                        format!("deployment.{text}")
                    } else {
                        text.to_owned()
                    }
                }),
            ),
            _ => (header, table.to_owned()),
        };
        format!("{}{header}{table}{}", &example[..start], &example[end..])
    }

    /// Step 1 writes the addresses wherever the table's lines can be
    /// replaced, says the file holds them only where it does, and refuses
    /// where they cannot be written there, as with dotted keys.
    #[test]
    fn the_addresses_are_written_where_the_table_takes_them_or_refused() {
        let answers = [
            "https://garrison.mail.internal",
            "https://mail.mail.internal",
            "http://127.0.0.1:8080",
            "https://mail.mail.internal/admin/",
        ]
        .map(str::to_owned);
        let forms = [
            "plain",
            "a comment after the header",
            "spaces inside the brackets",
            "quoted keys",
        ];
        for form in forms {
            let text = example_as(form);
            assert!(config::from_text(&text).is_ok(), "{form}");
            let Written::Changed(updated) = written(&text, &answers) else {
                panic!("{form}: {:?}", written(&text, &answers));
            };
            let deployment = config::from_text(&updated).unwrap().deployment;
            let loaded = [
                deployment.public_origin,
                deployment.issuer,
                deployment.stalwart_url,
                deployment.admin_url,
            ];
            assert_eq!(loaded, answers, "{form}");
            assert_eq!(written(&updated, &answers), Written::Already, "{form}");
        }
        let dotted = example_as("dotted keys");
        assert!(config::from_text(&dotted).is_ok());
        assert_eq!(written(&dotted, &answers), Written::Unwritable);
        // Answers the configuration refuses are asked again.
        let shared = [&answers[1], &answers[1], &answers[2], &answers[3]].map(String::clone);
        assert!(matches!(
            written(&example_as("plain"), &shared),
            Written::Invalid(_)
        ));
    }

    /// The modules are chosen where the file has the top-level `modules` of
    /// `garrison modules`, also over several lines, and not by a provider's.
    #[test]
    fn the_modules_are_chosen_by_a_top_level_key_alone() {
        let example = example_as("plain");
        assert!(!chosen(&example));
        assert!(chosen(&format!("modules = [\"backups\"]\n{example}")));
        assert!(chosen(&format!(
            "modules = [\n    \"backups\",\n]\n{example}"
        )));
        let provider = "\n[[providers]]\ntype = \"receipt\"\nid = \"nightly\"\ntitle = \"Nightly\"\n\
                        path = \"/var/lib/garrison/receipts/nightly.json\"\nmodules = [\"services\"]\n";
        assert!(config::from_text(&(example.clone() + provider)).is_ok());
        assert!(!chosen(&(example + provider)));
    }

    #[test]
    fn a_missing_key_is_added_at_the_end_of_its_section() {
        let text = with_deployment(TEXT, "admin_url", "https://stalwart.example.net/admin/");
        assert!(text.contains(
            "issuer = \"https://mail.example.org\"\nadmin_url = \"https://stalwart.example.net/admin/\"\n\n[web]"
        ));
        let last = with_deployment(
            "[deployment]\nissuer = \"https://a.example.net\"\n",
            "public_origin",
            "https://b.example.net",
        );
        assert!(last.ends_with("public_origin = \"https://b.example.net\"\n"));
    }
}
