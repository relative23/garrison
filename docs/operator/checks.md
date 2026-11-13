# Checks

What Garrison shows on its pages comes from checks. The configuration calls
them providers: each `[[providers]]` entry in `/etc/garrison/garrison.toml`
is one check, and `type` names it. The collector runs them every minute. A
source that is missing or unreadable shows as Unknown; it never stops the
other checks.

`garrison detect --format toml` prints entries for what the host runs, with
the paths it found (for ClamAV, from the units or the distribution's
defaults). The rest of the file is in the
[configuration reference](configuration.md), and the id of every
observation the checks report is in [observation ids](observations.md).

| `type` | Options | Shows |
|---|---|---|
| `host` | `disk_path`, `modules` | Memory, load, disk, uptime |
| `host-care` | `checks` (default: all of `updates`, `restart`, `clock`, `disk`, `firewall`), `disk_path`, `firewall_units`, `modules` | What the host needs from its operator; see below |
| `systemd` | `units = [{unit, label, modules, expect = "active" \| "idle", max_age_hours}]` | Unit states; timers show their schedule and next run. For one-shot jobs see below |
| `tls` | `endpoints = [{host, port, address = "127.0.0.1", starttls = false}]` (default: Stalwart's own listeners), `modules` | Certificate validity per endpoint; see below |
| `mail-flow` | `checks` (default: all of `spam`, `milter`, `authentication`, `tls`) | A week of the recorded events in numbers; see below |
| `stalwart` | `milter_host`, `milter_port`, `max_accounts` | Spam settings, classifier, milter, queue, mailbox storage, running version |
| `prometheus` | `path` | Native counters and gauges for the dashboard |
| `dns` | `resolver` (default: the first of `/etc/resolv.conf`), `max_domains` (20) | For each domain, the DNS records Stalwart names against what the resolver answers; see below |
| `clamav` | `milter_config`, `clamd_config`, `database_directory`, `signatures`, `fangfrisch_database`, `expect_on_infected`, `expect_on_fail` | Scanner policy and signature files |
| `backup-check` | `tool` (`restic` or `borg`), `max_age_hours` (30), `verify_days` (0: not expected), `restore_days` (0), `path`, `modules` | What the backup tool reported of its repository; see below |
| `bulwark` | `admin_directory`, `plugins` | Webmail plugin versions and bundle integrity |
| `http` | `id`, `title`, `url` (loopback), `expect_status`, `modules` | Whether an endpoint answers |
| `version-command` | `component`, `command`, `pattern`, `modules` | Installed version from a command; it runs in the collector's sandbox, so a program that compiles code at run time (a JIT) fails there |
| `reputation` | `hosts` (default: the mail hosts Stalwart names), `lists`, `lists_ipv6`, `resolver`, `modules` | Blocklists and reverse names of the addresses this server sends from; see below |
| `senders` | `min_recipients` (50), `factor` (5), `burst` (100), `bounces` (10), `modules` | The accounts that send unusually much; see below |
| `releases` | `products` (`garrison`, `stalwart`; default both) | Whether a newer release exists; see below |
| `mail-test` | `recipient`, `sender` (default: none, as a bounce is sent), `host` (`127.0.0.1`), `port` (25), `every_hours` (24), `macro_document` (false) | Test messages through the mail server itself; see below |
| `receipt` | `id`, `title`, `path`, `modules`, `date`, `max_age_hours`, `fields`, `ok_when`, `rows`, `columns`, `row_date`, `ok_rows`, `scope` | Results that other jobs write as JSON |

## `host-care`

Five checks of the host itself. Each reads what the host already knows and
changes nothing; one that cannot be made is Unknown.

- `updates`: the updates the package manager would install, security updates
  apart, which are a warning. It reads the metadata the host has fetched, so
  it is as fresh as the host's own update job keeps it. It asks again within
  five minutes once packages are installed or removed or new metadata is
  fetched, and otherwise every six hours. It reads `apt` (Debian, Ubuntu) and
  `dnf` 4 (the RHEL family, Amazon Linux); elsewhere it is Unknown. The
  collector's user reads dnf's cache in `/var/cache/dnf`: where only root may
  read a cache folder, as a dnf run under umask 077 leaves it, the finding
  names the repository.
- `restart`: the marker Debian and Ubuntu write when installed updates need a
  restart, and on every distribution an installed kernel newer than the one
  that runs.
- `clock`: whether the system clock follows a time server, as `timedatectl`
  says.
- `disk`: the free space of `disk_path` (default `/`), read hourly and carried
  forward in a straight line. A disk that would be full within 14 days is a
  warning. The forecast needs a day of readings first.
- `firewall`: whether one of the services firewalld, nftables and ufw is
  active; none is a warning. Where a unit of the host's own loads the rules,
  for example one that runs `nft -f`, name it:
  `firewall_units = ["host-firewall.service"]`. The check then asks for
  those units instead. The rules themselves are not read.

## `senders`

An account whose password was guessed or stolen shows in what it sends. From
the event history, read every ten minutes, the check takes what each
signed-in account handed in during the last 24 hours and holds it against
that account's own average of the 14 days before. A warning names the account
and the figures when

- it sent to at least `min_recipients` recipients and to at least `factor`
  times its usual number (once the history holds three days to compare with),
- it sent to `burst` recipients or more within one hour, or
- `bounces` or more of its recipients bounced, and they are a fifth of all.

The table lists the 20 accounts that need a look first, with messages,
recipients, their usual number a day, the busiest hour, bounces and the
addresses the mail was handed in from. Garrison blocks nothing: an account is
disabled, and its password changed, in the Stalwart WebUI. The check shows on
the Attacks & bans page, and a warning goes out on the notification channels
like any other.

## `tls`

Each endpoint is asked on this host with the host name as a browser or a mail
server would send it. The certificate must be trusted by the system's
authorities and valid for that name; one that expires within 14 days is a
warning. Without `endpoints` the check asks Stalwart what to probe: every
listener that speaks TLS (25 with STARTTLS, 465, 993, 443 and whatever else
is set up), once under the name of each mail host of Stalwart's domains. A
listener added later is then checked without a change here, and a
certificate that does not cover a mail host's name shows as untrusted, which
is what a sender that honours MTA-STS would find. Listeners that begin in
plain text and are not SMTP (IMAP on 143, POP3 on 110, ManageSieve) are left
out; they present the certificate of the ports that are asked. The protocol
shown is the one the handshake agreed on; versions older than TLS 1.2 cannot
be asked for.

## `mail-flow`

Summaries of the last seven days (UTC) of the event history, read every ten
minutes. They count; none of them is a verdict, except where it says so.

- `spam`: ham and spam by day, with the training runs of the classifier, on
  the Spam filter page; and the same by the domain of the mailbox the mail
  went to.
- `milter`: what Stalwart's milters said of the mail they were shown (a
  virus scanner's, Garrison's own macro filter), by day, on the Antivirus
  page. A milter that could not be reached since yesterday is a warning. A
  host without a milter has no such card.
- `authentication`: how many senders passed SPF, DKIM, DMARC, ARC and the
  check of the reverse name, on the Spam filter page; and the sender domains
  whose mail failed SPF or DMARC, which are forged senders or senders whose
  own records are wrong. A domain that publishes no record is counted as not
  passed, but is not listed as failing.
- `tls`: how much mail came in on port 25 with and without STARTTLS and how
  many deliveries went out to hosts that offered TLS, on the DNS & TLS page,
  with the sender domains and hosts without TLS.

## `backup-check`

The newest snapshot, the stored size, the last integrity check and the last
test restore of a restic or borg repository. The backup's password opens
every message on the server, so the collector never gets it. Root asks the
tool and writes down what it answers:

```sh
garrison backup-check restic                       # list the snapshots, read the size
garrison backup-check restic --verify              # also run `restic check`
garrison backup-check restic --restore /var/vmail  # also restore that path and remove it again
```

The command adds no secret of its own: it runs with the environment your
backup job already has (`RESTIC_REPOSITORY`, `RESTIC_PASSWORD_FILE`,
`BORG_REPO`, `BORG_PASSPHRASE` and the like), or takes the repository with
`--repo`. It writes `/var/lib/garrison/backup-check/<tool>.json`, which the
provider reads. Call it from the backup job's own unit, and less often with
the two longer runs:

```ini
# In the backup job's unit: report after every backup.
ExecStartPost=/usr/bin/garrison backup-check restic

# /etc/systemd/system/backup-verify.service, started weekly by a timer:
[Service]
Type=oneshot
EnvironmentFile=/etc/restic/environment
ExecStart=/usr/bin/garrison backup-check restic --verify --restore /var/vmail/example.org
```

The provider warns when the newest snapshot, or the report itself, is older
than `max_age_hours`, and where `verify_days` or `restore_days` is set, when
the last check or restore is older than that. A check or restore that failed,
and a repository the tool could not open, is Failed. A test restore proves
that the newest snapshot can be read with the password and holds the path;
it restores into a directory of its own under `/var/tmp`, counts the files
and removes them, and does not compare them with the originals. The exit
code of the command is 1 when something it ran failed, so the unit shows it
too.

## `systemd`: one-shot jobs

Use `expect = "idle"` for a job that runs and ends, such as a backup. The
entry then shows when the job last ran, how it ended and how long it took, as
systemd reports it. With `max_age_hours` it warns when the last run is older.

## `dns`

Stalwart names the records each of its domains needs (its zone file). The
check asks the resolver for them and compares:

- A record that mail depends on (MX, SPF, DKIM, DMARC) and that is missing is
  a warning. So is a DKIM key or a mail host other than Stalwart's.
- An SPF or DMARC policy of your own is shown as differing, without a warning.
- SRV, TLSA and similar records are optional and only shown. A TLSA record
  that is published but is not the one of Stalwart's certificate is a
  warning: senders that check DANE refuse a server whose record is wrong,
  which happens when a certificate is renewed and the record is not.
- Where the record for an MTA-STS policy is published, the policy itself is
  read from `https://mta-sts.<domain>/.well-known/mta-sts.txt`, once an hour.
  A policy that cannot be read, or that does not name one of the domain's
  mail hosts, is a warning: senders that honour it stop delivering.

The answers are those of this resolver at this moment; another resolver may
still hold older ones.

## `reputation`

A receiving server looks the sender's address up in blocklists and asks for
its reverse name. The check asks the same questions, every six hours, for
every address of the mail hosts: `hosts`, or without it the hosts Stalwart
names in the MX records of its domains.

- **Blocklists.** A listing is Failed and names the address and the list.
  IPv4 addresses are asked of `lists` (default `zen.spamhaus.org`,
  `bl.spamcop.net`, `psbl.surriel.com`, `bl.mailspike.net`), IPv6 addresses
  of `lists_ipv6` (default `zen.spamhaus.org`): a listing of the IPv6 address
  is the one that is overlooked. A list that gives no verdict is shown as
  such and is no listing. Spamhaus gives none to public resolvers, such as
  those of a hosting provider; a resolver of your own on the host gets one.
- **Reverse names.** Each address should have a reverse name that leads back
  to it and is one of the mail hosts, the name the server greets with. One
  that is missing, leads elsewhere or is the hosting provider's default is a
  warning.

The lists learn the addresses they are asked about, through this host's
resolver. Each list has terms of use of its own; remove from `lists` what you
may not ask. That is why the example configuration carries this check
switched off: it asks nobody until you add it.

## `releases`

Once a day the collector asks GitHub's public release list whether a newer
release exists; after a failed request it asks again an hour later. The
request carries nothing about the installation. The example configuration has
this entry; without it nothing is asked.

Where a release runs, the newest release is the one GitHub marks as latest,
which is never a pre-release. Where a pre-release runs, such as `0.2.0-rc.1`,
the newest of the last ten releases counts, pre-releases among them.

## `mail-test`

The collector hands two messages to the local SMTP listener without signing
in: the antivirus test file (EICAR), which a scanner must refuse, and the spam
test text (GTUBE), which must be refused or filed as spam. The event history
shows how an accepted one was filed. The check runs only where you name a
`recipient`. Make a mailbox of its own for it: a test that goes wrong leaves a
harmless message there.

With `macro_document = true` a third message carries a document that a macro
filter takes for one with macros (it holds none, only the name a macro
project has inside a document). It must be refused. Switch this on together
with [`[milter]`](configuration.md#milter) and `on_macro = "reject"`; a filter that only
marks takes the document, and the check then reports that nothing refused it.

## `receipt`

An example:

```toml
[[providers]]
type = "receipt"
id = "backup-local"
title = "Local full backup"
path = "/var/lib/backup/last-run.json"
modules = ["backups", "dashboard"]
max_age_hours = 30                                  # older: Warning
fields = [{ key = "pauseSeconds", label = "Mail service pause", format = "duration" }]
ok_when = { key = "result", equals = ["passed"] }   # otherwise: Failed
```

A receipt counts only if nobody else can have written it: it must belong to
root (or to the collector's own user) and must not be writable by others, nor
by its group unless that group is root. Otherwise the observation is Unknown.
Let the job write it as root with mode `0644`.

Keys can be nested: `key = ["components", "stalwartlabs/stalwart", "installed"]`.
Formats: `text`, `number`, `bytes`, `datetime`, `duration` (seconds), `boolean`, `url`.
