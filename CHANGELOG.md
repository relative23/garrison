# Changelog

Notable changes for operators and users. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Firewall units of the host's own.** `firewall_units` in the `host-care`
  provider names the units that filter the host, such as one that loads its
  own nftables rules. The firewall check then asks whether one of them runs,
  instead of warning that firewalld, nftables and ufw are not active.

### Changed

- **The update check names an unreadable dnf cache.** Where only root may
  read a folder in `/var/cache/dnf`, as a dnf run under umask 077 leaves it,
  the check is still Unknown, but now says which repositories and that
  `chmod 755` on their folders lets it read them.
- **The update check follows the host.** It asks the package manager again
  within five minutes after packages are installed or removed, new metadata
  is fetched or the cache folders it could not read are opened, and
  otherwise every six hours as before. A warning for an update that is
  installed now goes away within minutes.

## [0.1.0] - 2026-11-12

The first release.

### Added

- **The interface.** A console beside the Stalwart WebUI for what Stalwart
  itself does not show: Dashboard, Services, Antivirus, Spam filter, Attacks
  & bans, Backups, DNS & TLS, Alerts and Maintenance, and under Mail flow the
  Deliveries, Sessions and Event history. It follows the Stalwart WebUI's layout with
  colours of its own, in a light and a dark theme, and is checked against
  WCAG 2.2 AA. A row in the menu switches to the Stalwart WebUI in the same
  tab, and an optional nginx include adds the matching row there.
- **Evidence for every value.** Each value says how it was obtained
  (configuration, process, probe, receipt, inventory or metric) and when.
  Missing, stale and unverified data is shown as Unknown, never as zero or as
  a success.
- **Status collection.** A timer runs the configured providers for the host's
  services and schedules, the antivirus scanner, the spam filter, backup and
  monitor receipts, DNS and TLS certificates, and Stalwart's own inventory
  and metrics. A one-shot job such as a backup shows when it last ran, how it
  ended and how long it took, as systemd reports it, and warns when the last
  run is too old. The dashboard keeps a metric history of 90 days.
- **DNS records.** For each mail domain, the records Stalwart names for it
  are held against what the host's resolver answers: a missing MX, SPF, DKIM
  or DMARC record, or a DKIM key other than Stalwart's, is a warning.
- **Reputation.** Whether an address the server sends from stands on a
  blocklist, IPv4 and IPv6 alike, and whether its reverse name leads back to
  it and is a mail host's own; off in the example configuration, since it
  asks public lists. A published TLSA record that is not the one of
  Stalwart's certificate, and an MTA-STS policy that cannot be read or
  leaves a mail host out, are warnings of the DNS check.
- **Mail tests.** Where an operator names a test mailbox, the antivirus test
  file (EICAR) and the spam test text (GTUBE) go through the mail server
  itself once a day; the result says whether each was refused or filed as
  spam.
- **Newer releases.** Garrison asks GitHub's public release list once a day
  whether a newer release of Garrison or Stalwart exists, and says so on the
  Services page; where a pre-release runs, newer pre-releases count too. The
  request carries nothing about the installation and can be switched off.
- **Notifications.** To an [ntfy](https://ntfy.sh) topic, to a webhook as
  JSON, by mail, or to several of them: Garrison sends a message when one of
  its checks fails or warns in two runs in a row, when it is in order again,
  and when a newer release exists. Mail is submitted signed in over TLS, as a
  mail program does it. A watch beside the collector reports when the
  collector itself stops, also where the configuration no longer loads.
  `garrison notify-test` sends a test message on every channel, and
  `garrison detect` names an ntfy server on the host.
- **Event history.** Stalwart's signed webhook events are recorded behind a
  privacy filter: raw protocol input and output, message bodies, request URLs
  and credentials are never stored. Queue lifecycles and SMTP sessions are
  put together from the events, with SPF, DKIM, DMARC and rejections. Events
  are kept for 30 days within an event limit and a storage budget, and the
  interface says from when on events are kept and where recording had a gap.
- **Host care.** Pending security updates, a restart that is due, a clock
  that is not synchronised, a disk that would be full within two weeks and a
  host without a firewall service, each read from what the host itself knows.
- **Delivery problems.** The Deliveries page also sums outgoing mail of the
  last day, week or 30 days by the domain it went to and by the cause of its
  delays and bounces, and lists the messages that still wait, oldest first.
- **Attacks & bans.** From the same events: failed sign-ins, the bans
  Stalwart imposed and TLS handshake errors of the last day, week or 30 days,
  by address, by network (which shows attempts spread over many addresses)
  and by the account that was tried. A name that is no account is never
  stored.
- **Mail flow in numbers.** A week of the recorded events: spam and ham by
  day and by domain with the classifier's training runs, the milter's
  verdicts by day, how many senders pass SPF, DKIM, DMARC and ARC and which
  domains fail, and how much mail travels with and without TLS in each
  direction.
- **Certificates of all listeners.** Without a list of its own the TLS check
  asks Stalwart which listeners speak TLS and probes each under every mail
  host's name.
- **Backup repositories.** `garrison backup-check restic` or `borg`, called
  by the backup job as root, reports the newest snapshot, the stored size
  and, when asked, an integrity check and a test restore; the Backups page
  shows them and warns when one is overdue. The backup's password never
  reaches Garrison's services.
- **Macro filter.** Optional and off by default: a milter that Stalwart
  shows each incoming message, and that has mail with Office documents
  carrying macros refused or marked with a header. It is the one part of
  Garrison that acts on mail. `garrison stalwart setup` enters it in Stalwart
  only while it answers and takes it out before it stops; the daily mail
  test can send a harmless test document through it.
- **Sending accounts.** What each signed-in account sent in the last day
  against its own average of the two weeks before: many times its usual
  volume, a burst within one hour or a large share of bounces is a warning
  that names the account, as a taken-over account would cause it.
- **Maintenance actions.** Start or restart of the systemd units an operator
  configures, each with a confirmation the user types, a cooldown and an
  audit. A broker behind a Unix socket runs them through a generated polkit
  rule that allows exactly those units. The configuration reference shows
  the distribution's update job as such an action.
- **Sign-in and access.** Users sign in with their Stalwart account (OpenID
  Connect, Authorization Code with PKCE). A root-managed access policy binds
  Stalwart roles or accounts to profiles of modules and actions
  (`garrison access`); the user's current Stalwart permissions are checked
  again on every request.
- **Four services, no root process.** One static binary runs as the web
  service, the webhook receiver, the collector and the broker (and as the
  macro filter where that is switched on), each under a system user of its
  own in a sandboxed systemd unit. The web service never
  holds an administrative credential.
- **Installation.** The installer links the `garrison` command into the
  search path. `garrison setup` leads through an installation at a
  terminal; `garrison detect` shows what a host already runs and
  `garrison modules` chooses what an installation offers.
  `garrison stalwart setup` registers the webhook, the read-only API keys and
  the sign-in client in Stalwart. Every step also runs unattended, and an
  Ansible role comes with each release. Tested on Debian, Ubuntu, AlmaLinux,
  Rocky Linux, CentOS Stream, Fedora, openSUSE Leap and Amazon Linux.
- **Operations.** `garrison doctor` checks an installation from its services
  to what visitors see from outside, including that the issuer's name shows
  Stalwart's own sign-in page with the files it loads, and says for every
  problem what to do. `garrison backup` and `garrison self-check` write and
  verify consistent copies of the state. `garrison upgrade` installs a newer
  release once its minisign signature checks out; `garrison install
  --rollback` returns to the previous release, with the state from before the
  upgrade if asked. `garrison uninstall` takes Garrison off a host and leaves
  its data.
- **Stalwart 1.1.0.** Everything Garrison assumes about Stalwart is held to
  contract tests against the real server.
- **Releases.** Reproducible static archives for x86_64 and aarch64, each
  with the third-party notices and a CycloneDX SBOM.

[Unreleased]: https://github.com/relative23/garrison/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/relative23/garrison/releases/tag/v0.1.0
