//! Hosts for the tests: files below a temporary root and recorded output.

use std::fs;
use std::io;
use std::path::Path;

use garrison_collector::Runner;
use garrison_core::command::Output;

use super::host::Host;
use super::{Component, Inventory, inspect};

/// Recorded output, found by how the command line starts. Any other command
/// is missing from the host.
pub(super) struct Recorded(Vec<(&'static str, String)>);

impl Runner for Recorded {
    fn run(&self, arguments: &[&str]) -> io::Result<Output> {
        let line = arguments.join(" ");
        self.0
            .iter()
            .find(|(start, _)| line.starts_with(start))
            .map(|(_, stdout)| Output {
                code: Some(0),
                stdout: stdout.clone(),
            })
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, line))
    }
}

pub(super) fn write(root: &Path, path: &str, text: &str) {
    let path = root.join(path.trim_start_matches('/'));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

/// One unit as `systemctl show` prints it.
pub(super) fn unit(id: &str, active: &str, command: &str) -> String {
    let exec = command
        .split(' ')
        .next()
        .filter(|_| !command.is_empty())
        .map_or(String::new(), |program| {
            format!(
                "ExecStart={{ path={program} ; argv[]={command} ; ignore_errors=no ; \
                 start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}\n"
            )
        });
    format!("Id={id}\nLoadState=loaded\nActiveState={active}\nUnitFileState=enabled\n{exec}")
}

/// `AlmaLinux` with Stalwart, `ClamAV` and the usual services, all named by their units.
pub(super) fn almalinux(root: &Path) -> Recorded {
    write(
        root,
        "/etc/os-release",
        "NAME=\"AlmaLinux\"\nID=\"almalinux\"\nID_LIKE=\"rhel centos fedora\"\n\
         PRETTY_NAME=\"AlmaLinux 10.0 (Purple Lion)\"\n",
    );
    write(root, "/sys/fs/selinux/enforce", "1\n");
    write(
        root,
        "/etc/ntfy/server.yml",
        "# ntfy server\nbase-url: \"https://notify.example.org/\"\nlisten-http: \"127.0.0.1:2586\"\n",
    );
    write(
        root,
        "/etc/clamd.d/scan.conf",
        "# Local\nDatabaseDirectory /var/lib/clamav\nLocalSocket /run/clamd.scan/clamd.sock\n",
    );
    write(
        root,
        "/etc/mail/clamav-milter.conf",
        "MilterSocket inet:7357@127.0.0.1\nOnInfected Reject\n",
    );
    for file in ["main.cvd", "daily.cld", "bytecode.cvd", "freshclam.dat"] {
        write(root, &format!("/var/lib/clamav/{file}"), "");
    }
    write(
        root,
        "/etc/fangfrisch.conf",
        "[DEFAULT]\ndb_url = sqlite:////var/lib/fangfrisch/db.sqlite\n",
    );
    write(
        root,
        "/etc/resolv.conf",
        "# Generated\nnameserver 127.0.0.1\n",
    );
    write(root, "/etc/letsencrypt/live/README", "");
    write(root, "/etc/letsencrypt/live/mail.example.org/cert.pem", "");
    let units = [
        unit(
            "stalwart.service",
            "active",
            "/opt/stalwart/bin/stalwart --config=/opt/stalwart/etc/config.toml",
        ),
        unit(
            "clamd@scan.service",
            "active",
            "/usr/sbin/clamd -c /etc/clamd.d/scan.conf",
        ),
        unit(
            "clamav-milter.service",
            "active",
            "/usr/sbin/clamav-milter --config-file=/etc/mail/clamav-milter.conf",
        ),
        unit(
            "clamav-freshclam.service",
            "active",
            "/usr/bin/freshclam -d --foreground=true",
        ),
        unit("nginx.service", "active", "/usr/sbin/nginx"),
        unit("certbot-renew.timer", "active", ""),
        unit("unbound.service", "active", "/usr/sbin/unbound -d"),
        unit(
            "systemd-resolved.service",
            "inactive",
            "/usr/lib/systemd/systemd-resolved",
        ),
        unit(
            "firewalld.service",
            "active",
            "/usr/sbin/firewalld --nofork --nopid",
        ),
        unit("chronyd.service", "active", "/usr/sbin/chronyd -n"),
        unit("ntfy.service", "active", "/usr/bin/ntfy serve"),
        "Id=caddy.service\nLoadState=not-found\nActiveState=inactive\n".to_owned(),
    ]
    .join("\n");
    Recorded(vec![
        ("systemctl show", units),
        (
            "systemctl list-timers",
            "Thu 2026-10-30 03:00:00 UTC 22h Wed 2026-10-29 03:00:00 UTC 1h ago \
             restic-backup.timer restic-backup.service\n\
             n/a n/a n/a n/a unbound-anchor.timer unbound-anchor.service\n"
                .to_owned(),
        ),
        (
            "rpm -q",
            "clamd 1.4.3-1.el10\nclamav-milter 1.4.3-1.el10\nclamav-update 1.4.3-1.el10\n\
             package borgbackup is not installed\nrestic 0.18.1-1.el10\nunbound 1.23.1-1.el10\n"
                .to_owned(),
        ),
        (
            "ss -Hltnp",
            "LISTEN 0 4096 0.0.0.0:25 0.0.0.0:* users:((\"stalwart\",pid=812,fd=9))\n\
             LISTEN 0 4096 [::]:25 [::]:* users:((\"stalwart\",pid=812,fd=10))\n\
             LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:* users:((\"stalwart\",pid=812,fd=12))\n\
             LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:((\"nginx\",pid=700,fd=6))\n"
                .to_owned(),
        ),
    ])
}

/// Debian, whose `ClamAV` units name no file, with Stalwart in a container.
pub(super) fn debian(root: &Path) -> Recorded {
    write(
        root,
        "/etc/os-release",
        "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nVERSION_ID=\"13\"\nID=debian\n",
    );
    write(root, "/sys/module/apparmor/parameters/enabled", "Y\n");
    write(
        root,
        "/etc/clamav/clamd.conf",
        "DatabaseDirectory /var/lib/clamav\n",
    );
    write(
        root,
        "/etc/clamav/clamav-milter.conf",
        "MilterSocket /var/run/clamav/clamav-milter.ctl\nOnInfected Quarantine\n",
    );
    fs::create_dir_all(root.join("var/lib/clamav")).unwrap();
    write(
        root,
        "/etc/resolv.conf",
        "nameserver 9.9.9.9\nnameserver 149.112.112.112\n",
    );
    let units = [
        unit(
            "clamav-daemon.service",
            "active",
            "/usr/sbin/clamd --foreground=true",
        ),
        unit(
            "clamav-milter.service",
            "failed",
            "/usr/sbin/clamav-milter --foreground=true",
        ),
        unit(
            "clamav-freshclam.service",
            "active",
            "/usr/bin/freshclam -d --foreground=true",
        ),
        unit(
            "nftables.service",
            "active",
            "/usr/sbin/nft -f /etc/nftables.conf",
        ),
        unit(
            "systemd-timesyncd.service",
            "active",
            "/usr/lib/systemd/systemd-timesyncd",
        ),
    ]
    .join("\n");
    Recorded(vec![
        ("systemctl show", units),
        (
            "dpkg-query -W",
            "clamav-daemon 1.4.3+dfsg-1 ii \nclamav-milter 1.4.3+dfsg-1 ii \n\
             clamav-freshclam 1.4.3+dfsg-1 ii \nrestic 0.18.0-1 rc \n"
                .to_owned(),
        ),
        (
            "ss -Hltnp",
            "LISTEN 0 4096 0.0.0.0:25 0.0.0.0:* users:((\"docker-proxy\",pid=1200,fd=4))\n"
                .to_owned(),
        ),
        (
            "docker ps",
            "stalwart stalwartlabs/stalwart:v1.1.0\nwebmail roundcube/roundcubemail:1.6\n"
                .to_owned(),
        ),
        (
            "systemctl list-timers",
            "Fri 2026-10-31 00:00:00 UTC 19h n/a n/a dpkg-db-backup.timer dpkg-db-backup.service\n\
             Fri 2026-10-31 02:00:00 UTC 21h n/a n/a borgmatic.timer borgmatic.service\n"
                .to_owned(),
        ),
    ])
}

pub(super) fn bare(_: &Path) -> Recorded {
    Recorded(Vec::new())
}

/// Signature files from an old installation, but no scanner.
pub(super) fn leftovers(root: &Path) -> Recorded {
    write(root, "/var/lib/clamav/main.cvd", "");
    Recorded(Vec::new())
}

/// A host that resolves through the stub of systemd-resolved.
pub(super) fn stub(root: &Path) -> Recorded {
    write(
        root,
        "/etc/resolv.conf",
        "nameserver 127.0.0.53\noptions edns0\n",
    );
    Recorded(Vec::new())
}

pub(super) fn detected(prepare: fn(&Path) -> Recorded) -> (tempfile::TempDir, Inventory) {
    let root = tempfile::tempdir().unwrap();
    let runner = prepare(root.path());
    let inventory = inspect(&Host::new(root.path().to_owned(), &runner));
    (root, inventory)
}

pub(super) fn component<'a>(inventory: &'a Inventory, id: &str) -> &'a Component {
    inventory
        .components
        .iter()
        .find(|component| component.id == id)
        .unwrap()
}

pub(super) fn mentions(component: &Component, text: &str) -> bool {
    component.details.iter().any(|detail| detail.contains(text))
}
