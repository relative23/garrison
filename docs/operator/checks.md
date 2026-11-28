# Checks

What Garrison shows on its pages comes from checks. The configuration calls
them providers: each `[[providers]]` entry in `/etc/garrison/garrison.toml`
is one check, and `type` names it. The collector runs them every minute. A
source that is missing or unreadable shows as Unknown; it never stops the
other checks. A file system that does not answer, as a hard NFS mount whose
server is gone, costs `host`, `host-care`, `receipt`, `backup-check`,
`bulwark` and `version-command` eight seconds each and `clamav` eight for
each of its two cards, and their cards say so; a command that cannot be
started or ended in its eight seconds, as one whose interpreter lies on such
a file system, is left behind in the same time. The checks
that read Stalwart's domains, listeners or
accounts with the collector's API key (`dns`, `tls`, `reputation`,
`mail-flow`) say why where they could not: Stalwart could not be reached or
failed on its side, which the card names, such as "Stalwart answered HTTP
503", or refused the key for its rate limit (HTTP 429), both of which pass by
themselves, did not give the key what the check reads, which
`garrison stalwart setup` mends, or answered in a form this release does
not read, as a Stalwart release Garrison does not support yet may: the
card names the answer, and the README the supported releases. The
`stalwart` and `prometheus` checks say the same of their own requests.
Where the collector has no such key, its credential file missing, empty
or holding no key, these checks and the `stalwart` check ask Stalwart
nothing, and each of their cards that needs the key says so in the same
words: the collector has no API key for Stalwart, and `garrison stalwart
setup` makes one, also where the file is there.

Every card says when its source was asked ("Checked ..."). Most checks ask in
every run, and a card is marked stale once its answer is older than the card
allows: three minutes for the cards of `host`, `host-care`, `systemd`, `http`,
`dns` and `prometheus`, the queue and the notification channels; fifteen for
the TLS certificates, the ClamAV signatures, a `receipt`, a backup check, the
webmail plugins and the mailbox storage; an hour for a version; five minutes
for the others. Some ask less often, because the answer costs time or the
source should not be asked every minute: the pending updates, the blocklists
and reverse names, the release lists, the sign-in page, the test messages and
the counts from the event history. Their cards carry the time of the answer
they are made from, however often the collector has run since, and are marked
stale once a new answer is three minutes overdue.

`garrison detect --format toml` prints entries for what the host runs, with
the paths it found (for ClamAV, from the units or the distribution's
defaults). The rest of the file is in the
[configuration reference](configuration.md), and the id of every
observation the checks report is in [observation ids](observations.md).

| `type` | Options | Shows |
|---|---|---|
| `host` | `disk_path` (`/`), `proc` (`/proc`, for tests), `modules` | Memory, load, disk, uptime |
| `host-care` | `checks` (default: all of `updates`, `restart`, `clock`, `disk`, `firewall`), `disk_path` (with `disk`), `firewall_units`, `root` (`/`, for tests), `modules` | What the host needs from its operator; see below |
| `systemd` | `units = [{unit, label, modules, expect = "active" \| "idle", max_age_hours}]` (`max_age_hours` 1 to 8760, with `expect = "idle"`) | Unit states; an alias, such as `sshd.service`, shows the state of the unit it names and names that unit ("Alias of"). Timers show their schedule and next run. For one-shot jobs see below |
| `tls` | `endpoints = [{host, port, address = "127.0.0.1", starttls = false}]` (default: Stalwart's own listeners), `max_domains` (20, at most 100), `modules` | Certificate validity per endpoint; see below |
| `mail-flow` | `checks` (default: all of `spam`, `milter`, `authentication`, `tls`) | A week of the recorded events in numbers; see below |
| `stalwart` | `milter_host`, `milter_port` (0: none; one milter to look at alone, by host and port), `max_accounts` (1000, at most 20 000: how many of Stalwart's accounts the mailbox storage reads, the oldest first) | Spam settings, classifier, milter, queue, mailbox storage, running version |
| `prometheus` | `path` (`/metrics/prometheus`: where Stalwart's exporter answers) | Native counters and gauges for the dashboard |
| `dns` | `resolver` (default: the first of `/etc/resolv.conf`), `max_domains` (20, at most 100) | For each domain, the DNS records Stalwart names against what the resolver answers; see below |
| `clamav` | `milter_config`, `clamd_config`, `database_directory`, `signatures`, `fangfrisch_database`, `expect_on_infected`, `expect_on_fail` | Scanner policy and signature files; a daily database (`daily.cld`, `daily.cvd`) that was not updated for 48 hours is a warning where ClamAV has published a newer one or that cannot be asked, and so is one dated more than five minutes ahead of the host's clock, whose age is not known; where both are there the newer one counts, also for the dashboard's signature age |
| `backup-check` | `tool` (`restic` or `borg`), `max_age_hours` (30, 1 to 8784), `verify_days` (0: not expected; at most 366), `restore_days` (0; at most 366), `path`, `modules` | What the backup tool reported of its repository; see below |
| `bulwark` | `admin_directory`, `plugins` | Webmail plugin versions and bundle integrity: a bundle (`plugins/<id>.js`) that does not match the SHA-256 in `plugins/registry.json` is a failure. A plugin whose bundle cannot be checked, as one the registry does not list or lists twice, gives no hash for, or whose bundle is missing, a link, unreadable or larger than 2 MiB, is named with why; the card is then Partial, or Unknown where no bundle could be checked, as without `plugins`, which name the plugins to check, or where `admin_directory` holds no `plugins/registry.json`, and the card then names that option |
| `http` | `id`, `title`, `url` (loopback), `expect_status`, `modules` | Whether an endpoint answers |
| `version-command` | `component`, `command`, `pattern` (its first group, `( )`, is the version), `modules` | Installed version from a command; it runs in the collector's sandbox, so a program that compiles code at run time (a JIT) fails there. Only its standard output is read, so a version written to standard error, as `nginx -v` writes it, is not found; a card without a version says why |
| `reputation` | `hosts` (default: the mail hosts Stalwart names), `max_domains` (20, at most 100), `lists`, `lists_ipv6`, `resolver`, `modules` | Blocklists and reverse names of the addresses this server sends from; see below |
| `senders` | `min_recipients` (50), `factor` (5), `burst` (100), `bounces` (10), each 1 to 1 000 000, `modules` | The sender addresses that send unusually much; see below |
| `releases` | `products` (`garrison`, `stalwart`; default both), `api` (`https://api.github.com`; an `https://` address of a mirror that answers as it does) | Whether a newer release exists; see below |
| `sign-in` | `modules` | Whether Stalwart's sign-in page loads under the issuer's name, with its scripts and style sheets; see below |
| `mail-test` | `recipient`, `sender` (default: none, as a bounce is sent), `host` (`127.0.0.1`), `port` (25), `every_hours` (24, 1 to 168), `macro_document` (false) | Test messages through the mail server itself; see below |
| `receipt` | `id`, `title`, `path`, `modules`, `date`, `max_age_hours` (0: no limit; at most 9600), `fields`, `ok_when`, `rows`, `columns`, `row_date`, `ok_rows`, `scope` | Results that other jobs write as JSON |

## `host-care`

Five checks of the host itself. Each reads what the host already knows and
changes nothing; one that cannot be made is Unknown.

- `updates`: the updates a full upgrade would install, security updates
  apart, which are a warning. On Debian and Ubuntu that is what `apt-get
  dist-upgrade` installs: an update that needs a package not installed yet,
  as each kernel update with a new ABI does, counts too, where plain `apt-get
  upgrade` keeps it back. An update counts as a security update by the
  archive it comes from. It reads the metadata the host has fetched, so it is
  as fresh as the host's own update job keeps it; where apt has fetched no
  package lists at all (`/var/lib/apt/lists`), as a container image leaves
  it, the card is Unknown and says so. Where the package manager has not
  fetched its metadata, nor tried to, for a week, as where that job stopped,
  or a list of apt's has expired (its `Valid-Until`), the card warns: updates
  published since are not counted. It asks again within
  five minutes once packages are installed or removed or new metadata is
  fetched, and otherwise every six hours. It reads `apt` (Debian, Ubuntu) and
  `dnf` 4 (the RHEL family, Amazon Linux); elsewhere it is Unknown. The
  collector's user reads dnf's cache in `/var/cache/dnf`: where only root may
  read a cache folder, as a dnf run under umask 077 leaves it, the finding
  names the repository and says to make the cache again under umask 022,
  since such a run leaves the files in it closed too.
- `restart`: whether installed updates need a restart of the host. On every
  distribution a kernel installed in `/lib/modules` that is newer than the
  one that runs, and of its flavor, is a warning. The flavor is the
  release's name from its first hyphen before a letter on, such as `-amd64`,
  `-cloud-amd64` or `-generic`, or else from its last plus on, such as
  `+debug`: another flavor installed beside the running kernel, such as a
  debug or cloud kernel, is no update of it and is not compared, while
  Debian's backports kernel has the flavor of the stock kernel it updates.
  The check also reads `/run/reboot-required`,
  the marker that packages of Debian and Ubuntu write where their update
  needs a restart, as Debian's dbus does, so that such an update shows too.
  The RHEL family, Fedora, Amazon Linux and openSUSE do not write it: there
  a new kernel is what shows. In a container, which runs its host's kernel,
  no kernel is installed and only the marker counts. Where the installed
  kernels cannot be read, as under a drop-in that sets
  `ProtectKernelModules=true` for the collector, the card is Unknown and
  says why.
- `clock`: whether the system clock follows a time server, as `timedatectl`
  says.
- `disk`: the free space of `disk_path` (default `/`), read hourly and carried
  forward in a straight line. A disk that would be full within 14 days is a
  warning. The forecast needs a day of readings first, and again after
  `disk_path` changes.
- `firewall`: whether one of the services firewalld, nftables and ufw is
  active; none is a warning, and a systemctl that gives no state for each,
  as while it cannot reach systemd, is Unknown. Where a unit of the host's own loads the rules,
  for example one that runs `nft -f`, name it:
  `firewall_units = ["host-firewall.service"]`. The check then asks for
  those units instead; `garrison detect` names the ones it finds. The rules
  themselves are not read.

## `senders`

An account whose password was guessed or stolen shows in what it sends. From
the event history, read every ten minutes, the check takes what signed-in
accounts handed in during the last 24 hours under each sender address and
holds it against that address's own average of the 14 days before. The card
is called Sending addresses, and a warning names the address and the figures
when

- it sent to at least `min_recipients` recipients and to at least `factor`
  times its usual number (once the history holds three days to compare with),
- it sent to `burst` recipients or more within one hour, or
- `bounces` or more of its recipients bounced, and they are a fifth of all.

The check counts by address, not by account: Stalwart's event for a message
that a signed-in account hands in names the message's sender address and
not the account. An account that sends under several of its addresses shows
once for each, and each has its own usual number. A mailbox with many
aliases can so stay below a threshold that it would pass as one account;
lower `factor` or `burst` where that matters. The limits apply at once: a
change of them judges the next run's card, also over the reading of up to
ten minutes before.

The table lists the 20 addresses that need a look first, with messages,
recipients, their usual number a day, the busiest hour, bounces and the IP
addresses the mail was handed in from. Garrison blocks nothing: an account is
disabled, and its password changed, in the Stalwart WebUI. The check shows on
the Attacks & bans page, and a warning goes out on the notification channels
like any other. Its observation keeps the id `senders.accounts`.

A quiet day counts only over a history that holds the day. While the event
receiver has not reported for five minutes or runs without storing what
Stalwart sends, or where it lost events within the last 24 hours, the check
is Unknown and says since when; a warning it
did see stays a warning. Where events were lost in the 14 days before, no
usual number is named until that window has passed, since an average over
days that are missing would make an ordinary day look like an outlier.

The check reads the newest 200 000 submissions of the 15 days, and as many
bounces. Where there are more, the usual number is that of the whole days
before the last one that were read, none is named where fewer than three
were, and the card says so; where the last day itself was not read whole,
or bounces were left, its figures are a part, and the card is Partial where
it would be OK. An event whose time or fields are not what the event
receiver writes, as in a history damaged or edited by hand, is left out:
the card says how many were, and is Partial where it would be OK.

## `tls`

Each endpoint is asked on this host with the host name as a browser or a mail
server would send it. The certificate must be trusted by the system's
authorities and valid for that name; one that expires within 14 days is a
warning. Without `endpoints` the check asks Stalwart what to probe: every
listener that speaks TLS (25 with STARTTLS, 465, 993, 443 and whatever else
is set up), on the address it is bound to, or on 127.0.0.1 where it listens
on every address, once under the name of each mail host of Stalwart's
domains, of the `max_domains` oldest of them; the card says when Stalwart has
more. A port bound to more than one single address is probed on each, and
its rows say on which, as `mail.example.com:465 on 192.0.2.10`; so do
`endpoints` that name one host and port at two addresses. It
probes 24 such endpoints at the most; where there are more, the card says how
many and is Partial where it would be OK. A listener added later is then
checked without a change here, and a certificate that does not cover a mail
host's name shows as "certificate not valid for this name", which is what a
sender that honours MTA-STS would find. A certificate that has expired, or is
not from an authority this host trusts, is named so. Listeners that begin in
plain text and are not SMTP (IMAP on 143, POP3 on 110, ManageSieve) are left
out; they present the certificate of the ports that are asked. The protocol
shown is the one the handshake agreed on; versions older than TLS 1.2 cannot
be asked for.

## `mail-flow`

Summaries of the last seven days (UTC) of the event history, read every ten
minutes. They count; none of them is a verdict, except where it says so.

- `spam`: ham and spam by day, with the training runs of the classifier, on
  the Spam filter page; and the same by the domain of the mailbox the mail
  went to, which Stalwart's 20 000 oldest accounts name, read while the run
  has time: mail to an account after those is counted under "unknown", and
  the card says how many there are and is Partial. Where Stalwart did not
  give them to the collector's key, or the collector has no key for
  Stalwart, that mail is counted under "unknown", and the card by domain is
  Unknown and says why; the first run with a key reads them at once, and
  while Stalwart does not give them, each run asks it again, so that the
  card follows its next answer, as once setup gave the key its rights. The
  other cards need no account, and a Stalwart that is slow to answer costs
  them nothing: it is asked before the history is read.
- `milter`: what Stalwart's milters said of the mail they were shown (a
  virus scanner's, for one), by day, on the Antivirus
  page. A milter that could not be reached since yesterday is a warning,
  and so is a deferral of every message the milters were shown since
  yesterday, as a scanner gives that cannot scan, also where another milter
  passed them first. The history names no milter, so a message is told by
  its session: a session in which a milter deferred anything counts as
  deferred. A reply in the milter's own words, with which a milter may
  refuse or defer a message, is counted apart: Stalwart's event does
  not say whether it refused or deferred, so a milter that defers with one
  is not warned of. An answer larger than Stalwart reads is no verdict
  either, is counted apart ("Answer too large") and is a warning: Stalwart
  then defers the mail or lets it pass unscanned, as the milter's entry
  says. A host without a milter has no such card.
- `authentication`: how many senders passed SPF, DKIM, DMARC, ARC and the
  check of the reverse name, on the Spam filter page; and the sender domains
  whose mail failed SPF or DMARC, which are forged senders or senders whose
  own records are wrong. A domain that publishes no record is counted as not
  passed, but is not listed as failing.
- `tls`: how much mail came in on port 25 with and without STARTTLS and how
  many deliveries went out to hosts that offered TLS, on the DNS & TLS page,
  with the sender domains and hosts without TLS.

The lists by domain, of spam and ham, of the failing senders and of mail
without TLS, are made from the newest 50 000 events of each kind in the
seven days, and show the 20 busiest rows. A card whose list read only the
newest events says so and is Partial where it would be OK; one that shows
the 20 busiest of more says how many there are. The counts by day and the
numbers of mail with and without TLS count every event of the week. An event
whose time or fields are not what the event receiver writes, as in a history
damaged or edited by hand, is left out: every card says how many were, and
is Partial where it would be OK. A reading has two seconds: a week too large
to count in them, some millions of events, leaves every card Unknown with
"interrupted".

A summary is in order only over a history that holds the week. While the
event receiver has not reported for five minutes or runs without storing
what Stalwart sends, or where it lost events within these seven days (it was
away, or refused batches, for longer than Stalwart keeps events for it),
every summary that would be in order is Unknown and names the reason; the numbers that were read stay in view, and a warning stays a
warning. A history that only begins inside the week, on a new installation
or after a size limit removed older events, is counted from where it begins.

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
provider reads; `--report FILE` writes another file, for a provider whose
`path` names it. The report names where the repository is, without what signs
in to it but a login: a folder on this host as the folder its name leads to,
whatever slashes, dots, links, `local:` or `file://` are on the way; borg's
repository elsewhere as borg writes it, `user@host:repo` and
`ssh://user@host/./repo` alike; restic's elsewhere as given, without the
slashes at its end (one that restic reads from the file
`RESTIC_REPOSITORY_FILE` by what that file holds; an empty
`RESTIC_REPOSITORY` or `BORG_REPO` names none, as the tools take it). It
also holds the repository's own ID, which restic gives with `restic cat
config` and borg with its listing. A run keeps the last check and restore of
the report before it only where that report is of the same tool, the same
place and the same ID: another repository at its place, as another disk
mounted there, starts without them, and so do a copy of it at another place,
a report without an ID and a run for which the tool gives no ID, as where it
cannot open the repository; the command says so. A copy made byte for byte,
as by rsync, keeps the repository's ID, so one at the same place counts as
the same repository. Other names of one restic repository elsewhere, such as
sftp's two forms, count as two places: name it alike in every run, as one
`EnvironmentFile` for both units does. The card shows no check or restore of
a report an earlier release wrote, which holds no ID: where `verify_days` is
set, it warns until the next run with `--verify`, and where `restore_days`
is set, until the next run with `--restore`. A report that is a link or no
plain file, is larger than 256 KiB, is not one JSON object as the command
writes it, or can be changed by a user other than root makes the check
Unknown. The command reads the report it wrote last the same way, to keep
its last check and restore: from anything else it keeps neither, says so and
writes its report in that place. Call the command from the backup job's own
unit, and less often with the two longer runs:

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
and removes them, and does not compare them with the originals. A copy that
an interrupted run left there, as after a reboot or a stopped unit, is
removed by the next test restore once it has not changed for an hour and no
run holds it; the command says so, and names a copy it could not remove.
The exit code of the command is 1 when something it ran failed, so the unit
shows it too. Two runs that write one report take turns: the second waits
for the first and says so, and keeps what the first wrote.

## `systemd`: one-shot jobs

Use `expect = "idle"` for a job that runs and ends, such as a backup. The
entry then shows when the job last ran, how it ended and how long it took, as
systemd reports it. With `max_age_hours` it warns when the last run is older.
While a run is under way, systemd has forgotten when the one before ended:
the card says since when the run is under way, and `max_age_hours` holds that
start to the limit. systemd also forgets a job's last run when the host
starts, and as soon as the run has ended where no timer or other unit refers
to the job, as for one started by hand or from cron; with `max_age_hours` the
card is Unknown then and says so. Start such a job from a timer, or let it
write a receipt.

A job is a service. `garrison check-config` refuses `expect = "idle"` and
`max_age_hours` on a timer, a socket or a path unit, which is active while it
waits and inactive once it is stopped: put them on the service the timer
starts, such as `backup.service` for `backup.timer`, and leave the timer at
the default, `expect = "active"`, under which a stopped timer is Failed.

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
  read from `https://mta-sts.<domain>/.well-known/mta-sts.txt`, once an hour,
  and at once where the record changed, as senders take a record with
  another id for a new policy.
  A policy that cannot be read, or that does not name one of the domain's
  mail hosts, is a warning, also beside records that could not be read or
  were not asked: senders that honour it stop delivering. A policy file
  longer than 256 KiB, or one that unpacks to more than 4 MiB, is not read,
  as what comes before the cut is no policy to judge by.
- A record whose name is longer than DNS takes, 253 octets as written, as a
  long domain's DKIM or TLSA record may be, says "no DNS name" and is not
  asked: no server can publish it, so a needed one is a warning.

The answers are those of this resolver at this moment; another resolver may
still hold older ones. A record that the resolver answers with an error, such
as SERVFAIL for a zone whose DNSSEC signatures expired, or with an answer
that is malformed or cut off, says "not read" and why; so does one whose
answer is too long for UDP where the resolver then takes no question over
TCP, which it must on port 53. A record that could
not be read keeps the domain from being in order, optional as it may be: a
needed one leaves it Unknown, an optional one, such as a TLSA record, Partial
where it would be OK, and the card names the records and why; where the
record for an MTA-STS policy could not be read, the policy is not checked,
and the card says so. A resolver that does not answer once is not asked again
in that run, and the records left say "no answer"; once the run's time for its
checks is up, the records left say "not asked", and the domain is Partial, or
Unknown where nothing was asked; an MTA-STS policy that is due is then fetched
in the next run. Of each domain it asks the first 60 records Stalwart names;
where Stalwart names more, the card says how many and is Partial where it
would be OK. The check takes the `max_domains` oldest of Stalwart's
domains (Stalwart 1.2.0 numbers them in the order it makes them), 100 at
the most: each run asks every record of each of them
again, and each is a card of its own. Where Stalwart has more, the card "DNS
records" is Unknown and says how many it has; it sends no notification. With
more than 100 domains it stays Unknown, since Garrison does not check the
records of the domains after the oldest 100.

## `reputation`

A receiving server looks the sender's address up in blocklists and asks for
its reverse name. These blocklists are public lists in DNS that other mail
servers ask about this server's own addresses, not Stalwart's Blocked
senders and Safe senders, which decide for one account whether a sender's
mail goes to its Junk folder. The check asks the same questions, every six
hours, for
every address of the mail hosts: `hosts`, or without it the hosts Stalwart
names in the MX records of its domains, of the `max_domains` oldest of them;
the cards say when Stalwart has more. A reading made with another resolver
than the run's, the one `resolver` names or else the first of
`/etc/resolv.conf`, or with other `hosts`, `max_domains`, `lists` or
`lists_ipv6`, is made again in the next run, as is one an earlier release
kept. It asks about eight mail hosts and
twelve addresses at the most, and asks the lists for 30 seconds in all.
Where there are more, or a list was left unasked, the cards say so, and are
Partial where they would be OK. So they are for a mail host Stalwart names
that is longer than DNS takes, 253 octets: it has no address to ask about.
So they are, too, where the resolver's answer for a mail host's IPv4 or
IPv6 addresses cannot be used, as a malformed answer or an error of the
resolver (SERVFAIL, REFUSED): both cards name the host and why, and are
Unknown where no address could be read; the other hosts, and that host's
other addresses, are asked as before, and the reading is asked again after
an hour. A resolver that does not answer for a mail host's addresses is
asked nothing more: what it answered before counts, both cards say that
not every address was asked and why, or are Unknown where nothing could
be, and the reading is asked again after an hour. Without `hosts` the
check needs the collector's API key for Stalwart to read the mail hosts;
where it has none, both cards say so, and the first run with a key asks at
once. Where Stalwart does not give them, as where it refused the key, did
not answer or names no mail host, both cards say why, and the next run asks
Stalwart again, one request a minute while that lasts, so that the cards
follow once it gives them, as after `garrison stalwart setup`.

- **Blocklists.** A listing is Failed and names the address, the list and
  each code the list gave, as Spamhaus gives one for each of its lists.
  IPv4 addresses are asked of `lists` (default `zen.spamhaus.org`,
  `bl.spamcop.net`, `psbl.surriel.com`, `bl.mailspike.net`), IPv6 addresses
  of `lists_ipv6` (default `zen.spamhaus.org`): a listing of the IPv6 address
  is the one that is overlooked. A listing is an answer within
  127.0.0.0/8, where lists give theirs. A list that gives no verdict is no
  listing, and no clean result either: the card names the list, the
  addresses and why, names an address that no list judged, and is Partial
  where it would be OK, or Unknown where no list gave a verdict at all; such
  a reading is asked again after an hour. A list whose question got no
  usable answer, as an error of the resolver or none at all, is not asked
  about the addresses after it in that reading, and their rows say so.
  Spamhaus gives none to public resolvers, such as
  those of a hosting provider, nor after too many questions; a resolver of
  your own on the host gets one. An answer outside 127.0.0.0/8 comes from a
  resolver that answers names that do not exist with an address of its own:
  no list can be read through it, and the card stays Unknown until the
  check asks another: name one with `resolver`, which the next run asks. A
  zone of Spamhaus' Data Query Service
  is read by Spamhaus' own codes too: a key that is disabled or used
  against its terms gives no verdict, never a listing. Its name holds the
  subscriber's key, `KEY.zen.dq.spamhaus.net`, and `garrison.toml` is read
  by every user of the host, so write the zone without it,
  `zen.dq.spamhaus.net`, keep the key in
  `/etc/garrison/credentials/spamhaus-dqs-key` and set
  `collector.dqs_key = "credential:spamhaus-dqs-key"`
  ([configuration](configuration.md)): the collector reads the key for each
  run and asks the zone with it, and the key goes into the question and
  nowhere else. Without a key in that file the zone is not asked, gives no
  verdict and the card says why; the first run with one asks at once.
  `garrison check-config` refuses such a zone while `collector.dqs_key` is
  not set. A zone written with its key still works, named without it,
  `….zen.dq.spamhaus.net`, on the card, in its findings and in what the
  status database keeps, and check-config and `garrison doctor` warn of it.
  Earlier releases kept the key in the status database; the first
  collection run after an upgrade from one removes every copy of it there:
  once its snapshot is stored, it rebuilds the file beside it and puts the
  copy in its place, which the collector's journal says, while the web
  service reads on. On a slow disk with a long history that may take
  minutes, for which that one run asks systemd for more time, eight minutes
  at the most; the cards may show as out of date meanwhile.
  `garrison check-config` refuses a name DNS can never ask, and says which:
  one with a label of more than 63 octets, or one longer than 253 octets as
  it is asked, which is with the reversed address before a list's zone, so
  237 octets at the most in `lists` and 189 in `lists_ipv6`.
- **Reverse names.** Each address should have a reverse name that leads back
  to it and is one of the mail hosts, the name the server greets with. One
  that is missing, is the root (`.`), leads elsewhere or is the hosting
  provider's default is a warning. Where the resolver's answer for an address's reverse name, or for
  where that name leads, cannot be used, as a malformed answer or an error
  of the resolver, the card names the address and why, and is Partial where
  it would be OK, or Unknown where no address could be read; the other
  addresses and every list are asked as before, and the reading is asked
  again after an hour. Where the resolver does not answer such a question
  at all, it is asked no more questions of that kind in the reading, since
  each would wait out its three seconds: the addresses after it say so,
  and the lists are asked as before.

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

## `sign-in`

Everybody signs in to Garrison on Stalwart's sign-in page under the issuer's
name. The check loads that page from this host the way a browser does, with
the request Garrison sends, and asks for every script and style sheet it
names, twelve at the most: a page that names more is Partial and says how
many. It holds the page against the one Stalwart serves itself on loopback,
so a webmail that answers the same name with a sign-in page of its own is
found as well. A page that does not answer, that is not Stalwart's or whose
files do not come back is a failure, and the notifications report it after
two runs. This is what happens after a Stalwart release that loads files the
proxy does not pass: the page shows, and nobody can sign in.

A page in order is asked for again after five minutes, one that is not in
every run. `garrison doctor` makes the same check when it is called.

## `mail-test`

The collector hands two messages to the local SMTP listener without signing
in: the antivirus test file (EICAR), which a scanner must refuse, and the spam
test text (GTUBE), which must be refused or filed as spam. The event history
shows how an accepted one was filed. The check runs only where you name a
`recipient`. Make a mailbox of its own for it: it receives a harmless message,
with `macro_document` a harmless document too, in each round in which the
server refuses a test, one round a day by default and two where a test was
tried again an hour later, and one from a test that goes wrong.

A run opens up to eight sessions, each test with its copy and the harmless
messages after them, a quarter of a second apart: Stalwart takes five
connections a second from one address as it comes and turns the sixth away.

Each test is sent again `every_hours` after it was sent. One that did not
happen, because no session came about, the server turned it away before
the message or it deferred the message with a temporary reply (4xx), is
"not tested": it alone is tried again after an hour, and the table says when
each test was sent. A refused test is sent again at once, and its refusal
counts only where the server refuses that copy too and takes the harmless
message of the same build that the collector sends after the run's tests
("Garrison mail test: Harmless message (control)", beside the test document
a harmless document): a server that refuses by turns takes one of the
copies, which counts as taken, and a policy on attachments refuses the
harmless document. Where the server refuses the harmless message, as
clamav-milter does with `OnFail Reject` while clamd is down, or a policy
that refuses the tests' sender, the card is a warning, of which an operator
is told; where it does not get through, the refused tests are "not tested".
A refusal that an earlier release kept is sent again in the first run. A
deferral is no verdict: Stalwart defers a message
where a milter defers it, as a scanner that cannot scan does
(clamav-milter's `OnFail Defer` while clamd is down), and where it cannot
reach a milter whose entry says to defer then.
The results are those of the tests as configured: a change of
`recipient`, `sender`, `host`, `port` or `macro_document` sends the tests
anew in the next run, and nothing kept for what was configured before is
shown.

With `macro_document = true` a third message carries a document that a virus
scanner told to report macros takes for one with macros: a `.docm` whose
macro project has no module, so it holds no macro. It must be refused. Switch
this on once the scanner reports such documents and its milter refuses them:
with ClamAV, `AlertOLE2Macros yes` in clamd's configuration and an
`OnInfected` of clamav-milter that refuses
([installation](installation.md#10-mail-with-office-macros-optional)). Until
then the document is taken, and the check reports that nothing refused it.
ClamAV 1.0, 1.4 and 1.5 report the document (measured on 2026-11-26), and so
does a filter that goes by the name of the project's file.

## `clamav`

The card "Antivirus configuration" reads clamav-milter's file
(`milter_config`) and clamd's (`clamd_config`) as ClamAV reads them. It
holds clamav-milter's `OnInfected` against `expect_on_infected` (default
`Reject`) and `OnFail` against `expect_on_fail` (default `Defer`); one that
differs is a warning. A directive the file does not set counts with
clamav-milter's own default, `Quarantine` for an infected message and
`Defer` for a failure, so a file without `OnInfected` warns unless
`expect_on_infected` is `Quarantine`. A value counts in any case; of a
directive set twice the first counts, as ClamAV takes it, and the card says
so; every `ClamdSocket` counts, since clamav-milter takes turns with them. A
value clamav-milter does not take there, a typo or `Quarantine` and
`Blackhole` for `OnFail`, is a warning: clamav-milter does not start with
such a file. A file that cannot be read is named with why, and the card is
Unknown; a policy that was read stays a warning where only clamd's file
cannot be read. One that is not there names its option and
`garrison detect --format toml`, which prints where this host keeps it, as
the card "Signature databases" does where none of its files is in
`database_directory`; where the collector's user may not search that
folder, the card says so instead. `garrison check-config` takes for `expect_on_infected` only
`Accept`, `Reject`, `Defer`, `Blackhole` and `Quarantine`, and for
`expect_on_fail` only the first three.

A daily database that was not updated for 48 hours is held against the
newest one ClamAV has published, since ClamAV publishes none on some days.
The card "Signature databases" reads the version in the file's own header
and asks this host's resolver for the record freshclam asks,
`current.cvd.clamav.net`. Where that names the same version, the card stays
in order; where it names a newer one, the card warns with both versions,
since the updates do not arrive; and where the file names no version or the
record cannot be asked, the card warns and says which. A database of the
last two days is asked about nowhere.

Where `fangfrisch_database` names Fangfrisch's database, the card
"Signature databases" shows when Fangfrisch last checked each file, from
its whole refresh log; where that database cannot be read, the card says
why and is Partial where it would be OK. A file a check reads that is no
regular file, such as a named pipe in place of a database or of ClamAV's
files, is not opened, and the card says "not a regular file". One put in
place of a database or of its journal while the check opens it holds the
check five seconds at the most, and the card says that SQLite did not open
the database. A database another user writes is not read where a value in
it is longer than 16 MiB, more than Garrison or Fangfrisch writes in one:
the card says "string or blob too big".

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

Set `max_age_hours` for every job that runs on a schedule. Without it a
receipt has no age limit: the one of a job that stopped months ago stays in
order, and the card says so in a finding.

A receipt counts only if nobody else can have written it: it must belong to
root (or to the collector's own user) and must not be writable by others, nor
by its group unless that group is root. Otherwise the observation is Unknown.
Let the job write it as root with mode `0644`. Where the card cannot read the
receipt, it says why and what mends it: the collector's unit hides the place,
as it does `/home` and `/tmp` (see [below](#paths-the-collector-cannot-see));
there is no file at `path`, which the
job has not written; the collector's user may not search a folder on the way
there (let the job write it where that user may search, and set `path` to
it: opening the folder to every user would open what else it holds) or may
not open the file, as where a job
under umask 027 or 077 writes it with mode 0640 or 0600 (mode `0644` mends
it); it is a link, which is not followed, or no plain file; or it is larger
than 1024 KiB or no JSON object or list. A folder or a file that a mount
shows the collector at another place, as below, is named by its place on
the host, and a link on the way with where it leads.

A receipt can list results, one row each: `rows = []` where the file itself
is the list, or `rows = ["results"]` for a list under that key. `columns`
makes its table and `ok_rows` is what every row must meet. A list needs
`row_date`, the key of each row's date, the newest of which is the
receipt's; `fields`, `ok_when` and `date` read an object. A receipt of the
other shape, a list where the entry reads an object or the other way round,
is Unknown, and the card says how to read it. Every
row is judged, however many; the table shows the last 200, where a job that
appends a row for each run puts the newest, and the card says how many rows
the receipt lists where there are more. Where `rows` names no list, as where a
job that failed early wrote none, or `ok_rows` finds no row to judge, as in an
empty list, the card is Unknown and says so; a row that
is no JSON object is not read, and the card says how many and is Partial
where it would be in order.

Keys can be nested: `key = ["components", "stalwartlabs/stalwart", "installed"]`.
Formats: `text`, `number`, `bytes`, `datetime`, `duration` (seconds), `boolean`, `url`.
A `datetime` is a time with its offset (`2026-11-17T03:00:00+01:00` or
`2026-11-17T02:00:00Z`) or a plain date, taken as 00:00 UTC, as the receipt's
own `date` is read, or Unix seconds. A time written without its offset is not
shown, since every viewer would read it in their own time zone, and the card
says which field or column. A text is shown up to 300 characters; one cut
there ends in "…", and `ok_when` and `ok_rows` compare the whole text.

## Paths the collector cannot see

The collector runs in the sandbox of `garrison-collect.service`, which hides
some places of the host from it: `/home`, `/root` and `/run/user`
(`ProtectHome=true`), `/tmp` and `/var/tmp`, which are its own and empty
(`PrivateTmp=true`), `/dev`, which is its own but for `/dev/shm` and
`/dev/mqueue` (`PrivateDevices=true`), and the kernel's own files
`/proc/kallsyms`, `/proc/kcore` and `/proc/kmsg`. It sees `/lib/modules`,
where the `restart` check reads the installed kernels; the broker's unit
hides that too. `check-config`, and with it the installer before an upgrade,
refuses a path of a check that lies there, also through a link, and
`garrison doctor` names it: `disk_path` and `proc` of `host`, `disk_path`
and `root` of `host-care`, the `path` of `receipt` and `backup-check`, the files and the
database folder of `clamav`, `admin_directory` of `bulwark` and the program
a `version-command` runs. Root sees them there, the collector does not, so
the check would read nothing there, or the free space of the collector's
own `/home`. `disk_path = "/tmp"` and `"/var/tmp"` are in order: the
collector's own lie on the same file systems. The refusal is for the file the
units read, `/etc/garrison/garrison.toml`: for any other file named with
`--config`, such as a draft, `check-config` warns about such a path and about
an access policy in such a place, and the file counts as valid.

Keep such a file where the collector sees it, as under `/var/lib` or
`/srv`. Where a check must look at one place under `/home`, show the
collector that place read-only at another one, and name that one in the
option. For a folder, such as Bulwark's under `/home/webmail/bulwark`:

```sh
sudo mkdir -p /srv/garrison/bulwark
sudo systemctl edit garrison-collect.service
```

```ini
[Service]
BindReadOnlyPaths=/home/webmail/bulwark:/srv/garrison/bulwark
```

and `admin_directory = "/srv/garrison/bulwark"`. The collector then reads
that folder there and nothing else of `/home`; root sees an empty folder at
`/srv/garrison/bulwark`. The folder keeps its own mode there, so the
collector's user must be allowed to search it and read what the check reads.
For the free space of a file system mounted at
`/home`, show it an empty folder of that file system:
`sudo mkdir -p /home/.garrison-disk /srv/garrison/home-disk`, the line
`BindReadOnlyPaths=/home/.garrison-disk:/srv/garrison/home-disk` and
`disk_path = "/srv/garrison/home-disk"`.
