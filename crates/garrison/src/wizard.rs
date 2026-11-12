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
            inside = trimmed == "[deployment]";
        } else if inside
            && !done
            && trimmed
                .split_once('=')
                .is_some_and(|(name, _)| name.trim() == key)
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
        let mut updated = text.clone();
        for (key, value) in ADDRESSES.iter().zip(&answers) {
            updated = with_deployment(&updated, key, value);
        }
        match config::from_text(&updated) {
            Ok(_) if updated == text => {
                say("The configuration already has these addresses.");
                return Ok(());
            }
            Ok(_) => {
                let previous = crate::config_file::replace(path, &text, &updated)?;
                say(&format!(
                    "Written; the previous file is {}.",
                    previous.display()
                ));
                return Ok(());
            }
            Err(error) => say(&format!("{error}\nLet's try again.")),
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
    if text
        .lines()
        .any(|line| line.trim_start().starts_with("modules"))
    {
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
    nginx::run(&load(path)?);
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
