//! Stalwart, `ClamAV` and the services around them.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::Path;

use garrison_collector::providers::directives::directives;

use super::Component;
use super::host::{Host, Socket, Unit};
use super::system::{Family, System};

const STALWART: [&str; 2] = ["stalwart.service", "stalwart-mail.service"];
const SCANNER: [&str; 3] = [
    "clamd@scan.service",
    "clamav-daemon.service",
    "clamd.service",
];
const MILTER: &str = "clamav-milter.service";
const FRESHCLAM: &str = "clamav-freshclam.service";
const PROXIES: [&str; 4] = [
    "nginx.service",
    "caddy.service",
    "httpd.service",
    "apache2.service",
];
const RENEWAL: [&str; 3] = [
    "certbot-renew.timer",
    "certbot.timer",
    "snap.certbot.renew.timer",
];
const RESOLVERS: [&str; 2] = ["unbound.service", "systemd-resolved.service"];
const NTFY: &str = "ntfy.service";
const NTFY_CONFIG: &str = "/etc/ntfy/server.yml";
const GARRISON: [&str; 5] = crate::units::RUNNING;

/// A role and its package in the Red Hat and in the Debian family.
const PACKAGES: [(&str, &str, &str); 8] = [
    ("stalwart", "stalwart", "stalwart"),
    ("scanner", "clamd", "clamav-daemon"),
    ("milter", "clamav-milter", "clamav-milter"),
    ("freshclam", "clamav-update", "clamav-freshclam"),
    ("certbot", "certbot", "certbot"),
    ("unbound", "unbound", "unbound"),
    ("restic", "restic", "restic"),
    ("borg", "borgbackup", "borgbackup"),
];

/// Where a distribution puts the file when the unit names none.
const SCANNER_CONFIG: [(Family, &str); 4] = [
    (Family::Rhel, "/etc/clamd.d/scan.conf"),
    (Family::Debian, "/etc/clamav/clamd.conf"),
    (Family::Other, "/etc/clamav/clamd.conf"),
    (Family::Other, "/etc/clamd.d/scan.conf"),
];
const MILTER_CONFIG: [(Family, &str); 4] = [
    (Family::Rhel, "/etc/mail/clamav-milter.conf"),
    (Family::Debian, "/etc/clamav/clamav-milter.conf"),
    (Family::Other, "/etc/clamav/clamav-milter.conf"),
    (Family::Other, "/etc/mail/clamav-milter.conf"),
];
const SIGNATURE_FILES: [&str; 3] = ["cvd", "cld", "cud"];
const FANGFRISCH: [&str; 2] = ["/etc/fangfrisch.conf", "/etc/fangfrisch/fangfrisch.conf"];
/// Distribution timers that back up something other than mail.
const SYSTEM_TIMERS: [&str; 1] = ["dpkg-db-backup.timer"];
const BACKUP_PROGRAMS: [&str; 4] = [
    "/usr/bin/restic",
    "/usr/local/bin/restic",
    "/usr/bin/borg",
    "/usr/local/bin/borg",
];

pub(super) fn inspect(host: &Host<'_>, system: &System) -> Vec<Component> {
    let names: Vec<&str> = STALWART
        .iter()
        .chain(&SCANNER)
        .chain(&[MILTER, FRESHCLAM])
        .chain(&PROXIES)
        .chain(&RENEWAL)
        .chain(&RESOLVERS)
        .chain(&[NTFY])
        .chain(&GARRISON)
        .copied()
        .collect();
    let units = host.units(&names);
    let asked: Vec<&str> = PACKAGES
        .iter()
        .filter_map(|(_, rhel, debian)| match system.family {
            Family::Rhel => Some(*rhel),
            Family::Debian => Some(*debian),
            Family::Other => None,
        })
        .collect();
    let installed = system
        .packages
        .map(|tool| host.packages(tool, &asked))
        .unwrap_or_default();
    let seen = Seen {
        host,
        family: system.family,
        units: &units,
        installed: &installed,
    };
    let scanner = seen.scanner();
    let signatures = seen.signatures(scanner.settings.get("clamd_config").map(String::as_str));
    vec![
        seen.stalwart(&host.listening(), &host.containers()),
        scanner,
        seen.milter(),
        signatures,
        seen.proxy(),
        seen.certificates(),
        seen.resolver(),
        seen.backups(&host.timers()),
        seen.notifications(),
        seen.garrison(),
    ]
}

/// What one inspection saw, shared by the checks below.
struct Seen<'a, 'h> {
    host: &'a Host<'h>,
    family: Family,
    units: &'a BTreeMap<String, Unit>,
    installed: &'a BTreeMap<String, String>,
}

impl Seen<'_, '_> {
    /// The installed package that has `role` in this family.
    fn package(&self, role: &str) -> Option<String> {
        let (_, rhel, debian) = PACKAGES.iter().find(|(name, _, _)| *name == role)?;
        let name = match self.family {
            Family::Rhel => *rhel,
            Family::Debian => *debian,
            Family::Other => return None,
        };
        let version = self.installed.get(name)?;
        Some(format!("package {name} {version}"))
    }

    /// Notes the units among `names` and the package that has `role`.
    fn present(&self, component: &mut Component, names: &[&str], role: Option<&str>) {
        for name in names {
            if let Some(unit) = self.units.get(*name) {
                component.unit(name, unit);
            }
        }
        if let Some(package) = role.and_then(|role| self.package(role)) {
            component.found = true;
            component.note(package);
        }
    }

    /// The configuration file a unit's command names, or else the first
    /// distribution default that exists.
    fn configuration(
        &self,
        names: &[&str],
        defaults: &[(Family, &str)],
    ) -> Option<(String, &'static str)> {
        let from_unit = names
            .iter()
            .filter_map(|name| self.units.get(*name))
            .find_map(|unit| option(&unit.command, &["-c", "--config-file"]));
        if let Some(path) = from_unit {
            return Some((path, "from the unit"));
        }
        defaults
            .iter()
            .filter(|(family, _)| *family == self.family)
            .map(|(_, path)| *path)
            .find(|path| self.host.exists(path))
            .map(|path| (path.to_owned(), "distribution default"))
    }

    fn stalwart(&self, sockets: &[Socket], containers: &[(String, String)]) -> Component {
        let mut component = Component::new("stalwart", "Stalwart");
        self.present(&mut component, &STALWART, Some("stalwart"));
        for unit in STALWART.iter().filter_map(|name| self.units.get(*name)) {
            if let Some(program) = unit.command.first() {
                component.note(format!("program {program} (from the unit)"));
            }
            if let Some(config) = option(&unit.command, &["--config"]) {
                component.note(format!("configuration {config} (from the unit)"));
            }
        }
        for (name, image) in containers
            .iter()
            .filter(|(_, image)| image.contains("stalwart"))
        {
            component.found = true;
            component.note(format!("container {name} ({image})"));
        }
        let ports: BTreeSet<u16> = sockets
            .iter()
            .filter(|socket| socket.process.as_deref() == Some("stalwart"))
            .map(|socket| socket.port)
            .collect();
        if !ports.is_empty() {
            let ports: Vec<String> = ports.iter().map(u16::to_string).collect();
            component.note(format!("listening on {}", ports.join(", ")));
        }
        // Another mail server, or the proxy of a container, on the SMTP port.
        let owner = sockets
            .iter()
            .find(|socket| socket.port == 25)
            .and_then(|socket| socket.process.as_deref());
        if let Some(owner) = owner.filter(|owner| *owner != "stalwart") {
            component.note(format!("port 25 belongs to {owner}"));
        }
        component
    }

    fn scanner(&self) -> Component {
        let mut component = Component::new("clamav-scanner", "ClamAV scanner");
        self.present(&mut component, &SCANNER, Some("scanner"));
        if let Some((path, source)) = self.configuration(&SCANNER, &SCANNER_CONFIG) {
            component.note(format!("configuration {path} ({source})"));
            component.settings.insert("clamd_config", path);
        }
        component
    }

    fn milter(&self) -> Component {
        let mut component = Component::new("clamav-milter", "ClamAV milter");
        self.present(&mut component, &[MILTER], Some("milter"));
        if let Some((path, source)) = self.configuration(&[MILTER], &MILTER_CONFIG) {
            component.note(format!("configuration {path} ({source})"));
            let values = directives(&self.host.path(&path)).unwrap_or_default();
            for (key, label) in [
                ("MilterSocket", "milter socket"),
                ("OnInfected", "infected mail"),
            ] {
                if let Some(Some(value)) = values.get(key) {
                    component.note(format!("{label}: {value}"));
                }
            }
            component.settings.insert("milter_config", path);
        }
        component
    }

    fn signatures(&self, clamd_config: Option<&str>) -> Component {
        let mut component = Component::new("signatures", "Virus signatures");
        self.present(&mut component, &[FRESHCLAM], Some("freshclam"));
        let configured = clamd_config
            .and_then(|path| directives(&self.host.path(path)))
            .and_then(|values| values.get("DatabaseDirectory").cloned().flatten());
        let (directory, source) = configured.map_or_else(
            || ("/var/lib/clamav".to_owned(), "default"),
            |directory| (directory, "from clamd.conf"),
        );
        if self.host.exists(&directory) {
            let files = self
                .host
                .names(&directory)
                .iter()
                .filter(|name| {
                    Path::new(name).extension().is_some_and(|extension| {
                        SIGNATURE_FILES.iter().any(|known| extension == *known)
                    })
                })
                .count();
            component.found |= files > 0;
            component.note(format!("{files} signature files in {directory} ({source})"));
            component.settings.insert("database_directory", directory);
        }
        let fangfrisch = FANGFRISCH
            .into_iter()
            .find_map(|path| self.host.read(path).map(|text| (path, text)));
        if let Some((path, text)) = fangfrisch {
            component.found = true;
            component.note(format!("Fangfrisch configuration {path}"));
            if let Some(database) = fangfrisch_database(&text) {
                component.note(format!("Fangfrisch database {database}"));
                component.settings.insert("fangfrisch_database", database);
            }
        }
        component
    }

    fn proxy(&self) -> Component {
        let mut component = Component::new("proxy", "Reverse proxy");
        self.present(&mut component, &PROXIES, None);
        if self.units.contains_key("nginx.service") && !self.host.exists("/etc/nginx/snippets") {
            component.note("no /etc/nginx/snippets yet; the installer creates it".to_owned());
        }
        component
    }

    fn certificates(&self) -> Component {
        let mut component = Component::new("certificates", "Certificate renewal");
        self.present(&mut component, &RENEWAL, Some("certbot"));
        let live: Vec<String> = self
            .host
            .names("/etc/letsencrypt/live")
            .into_iter()
            .filter(|name| name != "README")
            .collect();
        if !live.is_empty() {
            component.note(format!("certificates for {}", live.join(", ")));
        }
        component
    }

    fn resolver(&self) -> Component {
        let mut component = Component::new("resolver", "DNS resolver");
        // A loaded but stopped resolver answers nothing.
        for name in RESOLVERS {
            if let Some(unit) = self.units.get(name).filter(|unit| unit.active == "active") {
                component.unit(name, unit);
            }
        }
        if let Some(package) = self.package("unbound") {
            component.note(package);
        }
        let servers = self
            .host
            .read("/etc/resolv.conf")
            .map(|text| nameservers(&text))
            .unwrap_or_default();
        if let Some(first) = servers.first() {
            component.note(resolving(first));
        }
        component
    }

    fn backups(&self, timers: &[(String, String)]) -> Component {
        let mut component = Component::new("backups", "Backups");
        for role in ["restic", "borg"] {
            if let Some(package) = self.package(role) {
                component.found = true;
                component.note(package);
            }
        }
        if !component.found {
            for program in BACKUP_PROGRAMS
                .iter()
                .filter(|program| self.host.exists(program))
            {
                component.found = true;
                component.note(format!("program {program}"));
            }
        }
        let scheduled = timers.iter().filter(|(name, _)| {
            ["backup", "restic", "borg"]
                .iter()
                .any(|word| name.contains(word))
                && !SYSTEM_TIMERS.contains(&name.as_str())
        });
        for (timer, job) in scheduled {
            component.found = true;
            component.units.push(timer.clone());
            component.note(format!("timer {timer}"));
            // The job itself says when it last ran and how it ended.
            if job
                .rsplit_once('.')
                .is_some_and(|(_, kind)| kind == "service")
            {
                component.jobs.push(job.clone());
            }
        }
        component
    }

    /// An ntfy server on this host. Garrison tells a topic only where an
    /// operator names one: which topic, and with which token, is theirs to say.
    fn notifications(&self) -> Component {
        let mut component = Component::new("notifications", "Notifications (ntfy)");
        self.present(&mut component, &[NTFY], None);
        if component.found {
            let base = self.host.read(NTFY_CONFIG).and_then(|text| base_url(&text));
            if let Some(base) = &base {
                component.note(format!("base URL {base} (from {NTFY_CONFIG})"));
            }
            component.note(format!(
                "to be told through it: ntfy_url = \"{}/<topic>\" under [notifications] in \
                 garrison.toml",
                base.as_deref().unwrap_or("https://<its name>")
            ));
        }
        component
    }

    fn garrison(&self) -> Component {
        let mut component = Component::new("garrison", "Garrison");
        if let Some(target) = self.host.link("/opt/garrison/current") {
            component.found = true;
            let release = target.rsplit('/').next().unwrap_or(&target);
            component.note(format!("release {release}"));
        }
        if self.host.exists("/etc/garrison/garrison.toml") {
            component.note("configuration /etc/garrison/garrison.toml".to_owned());
        }
        self.present(&mut component, &GARRISON, None);
        component
    }
}

/// The value of `name value` or `name=value` in a command line.
fn option(command: &[String], names: &[&str]) -> Option<String> {
    let mut words = command.iter();
    while let Some(word) = words.next() {
        if names.contains(&word.as_str()) {
            return words.next().cloned();
        }
        let joined = names.iter().find_map(|name| {
            word.strip_prefix(name)
                .and_then(|rest| rest.strip_prefix('='))
        });
        if let Some(value) = joined {
            return Some(value.to_owned());
        }
    }
    None
}

/// What the first resolver means for DNS blocklists, which refuse queries that
/// come through public resolvers.
fn resolving(first: &str) -> String {
    // The stub of systemd-resolved forwards to the network's resolvers.
    if first == "127.0.0.53" {
        return format!(
            "/etc/resolv.conf asks the systemd-resolved stub {first}, which forwards \
             to other resolvers; blocklists such as Spamhaus refuse public ones"
        );
    }
    if first
        .parse::<IpAddr>()
        .is_ok_and(|address| address.is_loopback())
    {
        return format!("/etc/resolv.conf asks {first} on this host");
    }
    format!(
        "/etc/resolv.conf asks {first}; blocklists such as Spamhaus refuse queries \
         that come through public resolvers"
    )
}

/// The `nameserver` lines of resolv.conf, in order.
fn nameservers(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| line.trim().strip_prefix("nameserver"))
        .map(|rest| rest.trim().to_owned())
        .filter(|server| !server.is_empty())
        .collect()
}

/// `base-url: "https://ntfy.example.org"` of ntfy's server.yml. Only an https
/// address serves: Garrison sends to no other.
fn base_url(text: &str) -> Option<String> {
    text.lines()
        .filter_map(|line| line.strip_prefix("base-url:"))
        .map(|value| value.trim().trim_matches(['"', '\'']).trim_end_matches('/'))
        .find(|value| value.starts_with("https://") && !value.contains(char::is_whitespace))
        .map(str::to_owned)
}

/// The SQLite file of `db_url = sqlite:////var/lib/fangfrisch/db.sqlite`.
fn fangfrisch_database(text: &str) -> Option<String> {
    text.lines()
        .filter_map(|line| line.split_once('='))
        .find(|(key, _)| key.trim() == "db_url")
        .and_then(|(_, value)| value.trim().strip_prefix("sqlite:///"))
        .filter(|path| path.starts_with('/'))
        .map(str::to_owned)
}
