//! `garrison <command>`: the entry point for services and operators.
//!
//! Service commands (started by systemd): web, ingest, collect, broker.
//! Operator commands: install, detect, check-config, modules, access,
//! stalwart, polkit-rule, stalwart-switch, backup, self-check. Every command
//! but `install` and `detect` reads the configuration first.

mod access;
mod backup_check;
mod config_file;
mod detect;
mod doctor;
mod install;
mod nginx;
mod ops;
mod selection;
mod setup;
mod units;
mod upgrade;
mod watch;
mod wizard;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use garrison_authz::Authority;
use garrison_core::config::{self, Config};
use garrison_core::credentials::Credentials;
use garrison_core::logging;

#[derive(Debug, Parser)]
#[command(
    name = "garrison",
    version,
    about = "Garrison services and operator commands.",
    arg_required_else_help = true
)]
struct Arguments {
    /// The configuration file.
    #[arg(long, global = true, default_value = config::DEFAULT_PATH)]
    config: PathBuf,
    /// Also log debug messages, including those of libraries.
    #[arg(long, global = true)]
    verbose: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Install or upgrade from this extracted release, or roll back (root).
    Install {
        /// Switch back to the previous release.
        #[arg(long)]
        rollback: bool,
        /// With --rollback: also restore the state copied before the upgrade.
        #[arg(long, requires = "rollback")]
        restore_state: bool,
    },
    /// Take Garrison off this host; data and configuration stay (root).
    Uninstall {
        /// Also remove configuration, credentials, data, the installer's backups and the users.
        #[arg(long)]
        purge: bool,
        /// Only list what would be removed.
        #[arg(long)]
        dry_run: bool,
    },
    /// Set Garrison up step by step at a terminal: addresses, modules, Stalwart, access, start (root).
    Setup,
    /// Install a newer release once its signature checks out (root).
    Upgrade {
        /// The release archive, `garrison-<version>-<arch>.tar.gz`.
        archive: PathBuf,
        /// The minisign signature; by default the archive's name plus `.minisig`.
        #[arg(long)]
        signature: Option<PathBuf>,
    },
    /// One look at whether the collector still runs (systemd timer).
    Watch,
    /// Ask restic or borg about its repository and write a report for the collector (root).
    BackupCheck {
        /// The backup tool: restic or borg.
        tool: String,
        /// The repository; without it the tool reads its own environment.
        #[arg(long)]
        repo: Option<String>,
        /// Also run the tool's integrity check.
        #[arg(long)]
        verify: bool,
        /// Also restore this path from the newest snapshot, count it and remove it again.
        #[arg(long, value_name = "PATH")]
        restore: Option<String>,
        /// Where the report goes; by default restic.json or borg.json in
        /// /var/lib/garrison/backup-check.
        #[arg(long, value_name = "FILE")]
        report: Option<PathBuf>,
    },
    /// Show what this host already runs, without changing anything.
    Detect {
        /// A report (text), the inventory (json) or provider entries (toml).
        #[arg(long, value_enum, default_value = "text")]
        format: detect::Format,
    },
    #[command(flatten)]
    Configured(Task),
}

/// The commands that work with the configuration file.
#[derive(Debug, Subcommand)]
enum Task {
    /// The web service (systemd).
    Web,
    /// The webhook receiver (systemd).
    Ingest,
    /// One collection run (systemd timer).
    Collect,
    /// The maintenance broker (systemd).
    Broker,
    /// The macro milter, where the configuration switches it on (systemd).
    Milter,
    /// Validate the configuration, the providers and the access policy.
    CheckConfig,
    /// Choose the modules this installation offers (root).
    Modules {
        /// The modules besides dashboard and services, e.g. `antivirus,backups`;
        /// without it, choose them in the terminal.
        #[arg(long)]
        set: Option<String>,
        /// Write without asking first.
        #[arg(long)]
        yes: bool,
        /// With --set: also add provider entries for what `detect` finds for
        /// these modules and the configuration lacks.
        #[arg(long, requires = "set")]
        adopt: bool,
    },
    /// Print the polkit rule for the configured actions.
    PolkitRule,
    /// Print the nginx include for the Stalwart WebUI.
    StalwartSwitch,
    /// Print the nginx server block for Garrison's host name, for the nginx installed here.
    Nginx,
    /// Manage Garrison access policy (root).
    Access {
        #[command(subcommand)]
        command: access::Command,
    },
    /// Configure Stalwart for Garrison.
    Stalwart {
        #[command(subcommand)]
        command: setup::Command,
    },
    /// Write consistent copies of Garrison state.
    Backup {
        /// The directory to write; it is created with mode 0700.
        #[arg(long)]
        to: PathBuf,
    },
    /// Check the whole installation and say what to do about each problem (root).
    Doctor,
    /// Send a test message on every configured notification channel (root).
    NotifyTest,
    /// Verify Garrison databases.
    SelfCheck {
        /// A directory written by `backup`.
        #[arg(long)]
        state: Option<PathBuf>,
        /// Also write the result as a receipt file.
        #[arg(long)]
        receipt: Option<PathBuf>,
    },
}

/// Lines for operators on standard output; a closed pipe ends the command.
pub(crate) fn say(text: &str) {
    let _ = writeln!(std::io::stdout().lock(), "{text}");
}

pub(crate) fn complain(text: &str) {
    let _ = writeln!(std::io::stderr().lock(), "{text}");
}

/// The built interface ships next to the binary: `<release>/bin/garrison`
/// and `<release>/static/`.
fn static_directory() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|binary| Some(binary.parent()?.parent()?.join("static")))
        .unwrap_or_else(|| PathBuf::from("static"))
}

/// Under systemd, `$CREDENTIALS_DIRECTORY` holds the loaded credentials.
/// Operator commands run outside systemd and read the same files from their
/// configured source.
fn credentials(config: &Config) -> Credentials {
    Credentials::from_environment(&config.credentials_directory)
}

/// Whether someone can answer a question here: standard input and standard
/// output are both a terminal. Ansible, for one, gives a command a terminal as
/// input but reads its output from a pipe, where no question would be seen,
/// and a command whose output goes to a file asks nobody either.
pub(crate) fn at_terminal() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// Whether an origin names a host reserved for documentation or tests
/// (RFC 2606, RFC 6761), as the example configuration does.
pub(crate) fn placeholder(origin: &str) -> bool {
    let host = origin
        .split_once("://")
        .map_or(origin, |(_, rest)| rest)
        .split(['/', ':'])
        .next()
        .unwrap_or_default()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let under = |name: &str| host == name || host.ends_with(&format!(".{name}"));
    [
        "example.com",
        "example.net",
        "example.org",
        "example",
        "test",
        "invalid",
    ]
    .into_iter()
    .any(under)
}

/// One message on every configured channel, so that an operator sees them
/// work before a check depends on them.
fn notify_test(config: &Config) -> u8 {
    use garrison_collector::notify::{Channels, Secrets, test};
    let secrets = Secrets::read(&credentials(config), &config.notifications);
    let channels = Channels::of(config, secrets);
    if channels.is_empty() {
        complain(
            "No channel is configured: set ntfy_url, webhook_url or the mail settings under \
             [notifications] in garrison.toml.",
        );
        return 2;
    }
    let mut failed = false;
    for (channel, outcome) in test(&channels, garrison_core::time::now()) {
        match outcome {
            Ok(()) => say(&format!("{channel}: the test message is out.")),
            Err(error) => {
                failed = true;
                complain(&format!(
                    "{channel}: the test message did not go out: {error}. Check its address and \
                     its secret in /etc/garrison/credentials."
                ));
            }
        }
    }
    u8::from(failed)
}

fn check_config(config: &Config) -> u8 {
    if let Err(error) = garrison_collector::build(&config.collector.providers) {
        complain(&format!("Configuration not usable: {error}"));
        return 2;
    }
    say(&format!(
        "Configuration valid: {} providers, {} actions.",
        config.collector.providers.len(),
        config.broker.actions.len()
    ));
    let deployment = &config.deployment;
    for (setting, origin) in [
        ("public_origin", &deployment.public_origin),
        ("issuer", &deployment.issuer),
    ] {
        if placeholder(origin) {
            complain(&format!(
                "Warning: deployment.{setting} {origin} is a placeholder; set the real name."
            ));
        }
    }
    match Authority::new(config, credentials(config)).policy() {
        Ok(_) => {
            say(&format!(
                "Access policy valid: {}",
                config.broker.policy.display()
            ));
            0
        }
        Err(error) => {
            say(&format!("Access policy not usable: {error}"));
            1
        }
    }
}

fn stalwart_switch(config: &Config) -> u8 {
    let script = static_directory().join(garrison_web::switch::SCRIPT);
    let Ok(data) = std::fs::read(&script) else {
        complain(&format!(
            "{} is missing; build the interface first.",
            script.display()
        ));
        return 1;
    };
    let text = garrison_web::switch::snippet(&config.deployment.public_origin, &data);
    let _ = std::io::stdout().lock().write_all(text.as_bytes());
    0
}

/// A service that ends with an error exits with status 1, so systemd restarts it.
fn service<E: std::fmt::Display>(name: &str, result: Result<(), E>) -> u8 {
    match result {
        Ok(()) => 0,
        Err(error) => {
            log::error!("The {name} service stopped: {error}");
            1
        }
    }
}

fn dispatch(task: Task, config: &Config, path: &Path) -> u8 {
    match task {
        Task::Web => service("web", garrison_web::run(config.clone(), static_directory())),
        Task::Ingest => service("ingest", garrison_ingest::run(config, &credentials(config))),
        Task::Collect => {
            let runner = garrison_collector::SystemRunner;
            service(
                "collector",
                garrison_collector::collect(config, &credentials(config), &runner).map(drop),
            )
        }
        Task::Broker => service("broker", garrison_broker::run(config, credentials(config))),
        Task::Milter => service("milter", garrison_milter::run(config)),
        Task::CheckConfig => check_config(config),
        Task::Modules { set, yes, adopt } => {
            selection::run(path, config, set.as_deref(), yes, adopt)
        }
        Task::PolkitRule => {
            let rule = garrison_broker::polkit::rule(&config.broker.actions, "garrison-broker");
            let _ = std::io::stdout().lock().write_all(rule.as_bytes());
            0
        }
        Task::StalwartSwitch => stalwart_switch(config),
        Task::Nginx => nginx::run(config),
        Task::Access { command } => access::run(config, &command),
        Task::Stalwart { command } => setup::run(config, &command),
        Task::Backup { to } => ops::backup(config, &to),
        Task::Doctor => doctor::run(config),
        Task::NotifyTest => notify_test(config),
        Task::SelfCheck { state, receipt } => {
            ops::self_check(config, state.as_deref(), receipt.as_deref())
        }
    }
}

fn load(path: &Path) -> Result<Config, String> {
    config::load(path).map_err(|error| format!("Cannot load {}: {error}", path.display()))
}

fn main() -> ExitCode {
    let arguments = Arguments::parse();
    logging::init(arguments.verbose);
    let code = match arguments.command {
        // The installer runs before a configuration exists.
        Command::Install {
            rollback,
            restore_state,
        } => install::run_installer(rollback, restore_state),
        Command::Upgrade { archive, signature } => upgrade::run(&archive, signature.as_deref()),
        Command::Setup => wizard::run(&arguments.config),
        Command::Uninstall { purge, dry_run } => install::run_uninstall(purge, dry_run),
        // The watch also looks where the configuration no longer loads.
        Command::Watch => watch::run(&arguments.config),
        Command::BackupCheck {
            tool,
            repo,
            verify,
            restore,
            report,
        } => backup_check::run_check(&backup_check::Asked {
            tool,
            repo,
            verify,
            restore,
            report,
        }),
        // Detection also runs before a configuration exists.
        Command::Detect { format } => detect::run(format),
        Command::Configured(task) => match load(&arguments.config) {
            Ok(config) => dispatch(task, &config, &arguments.config),
            Err(message) => {
                complain(&message);
                2
            }
        },
    };
    ExitCode::from(code)
}

#[cfg(test)]
mod tests {
    use super::placeholder;

    #[test]
    fn documentation_names_are_placeholders() {
        for origin in [
            "https://garrison.example.org",
            "https://example.com",
            "https://mail.example.net:8443/",
            "https://admin.example.test",
            "https://host.example",
            "https://EXAMPLE.ORG.",
        ] {
            assert!(placeholder(origin), "{origin}");
        }
        for origin in [
            "https://garrison.mail.internal",
            "https://notexample.org",
            "https://example.org.example.com.evil",
            "https://[::1]:8443",
        ] {
            assert!(!placeholder(origin), "{origin}");
        }
    }
}
