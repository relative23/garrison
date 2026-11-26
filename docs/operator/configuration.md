# Configuration reference

One file, `/etc/garrison/garrison.toml`, read by all services. Unknown
keys are errors, so a typo cannot silently fall back to a default. Check changes
with `garrison check-config`, then restart the affected services
(the collector picks changes up on its next run).

Secrets never appear in this file. A value `credential:NAME` refers to
`/etc/garrison/credentials/NAME`, which systemd hands to the service
with `LoadCredential=`. Each unit loads every secret under one name, the
default each setting below shows, and hands its service no other:
`check-config` refuses another name, and also a path, which the service
would have to read itself, as its own user; `garrison doctor` reports
either.

## Top level

| Key | Default | Meaning |
|---|---|---|
| `schema` | none | Must be `1`. |
| `credentials_directory` | `/etc/garrison/credentials` | Source of the `credential:` files. Keep the default: the units load every credential from there whatever this says, and `check-config` warns about another value. |
| `modules` | all modules | The modules this installation offers, as [module IDs](#module-ids). The dashboard and services are always on. Nobody is granted another module, whatever the access policy says, and without `actions` the broker runs no action. A user whose profiles name none of these modules is refused, as one without a profile is. An unknown ID is an error. `garrison modules` sets it. |

## `[deployment]`

| Key | Meaning |
|---|---|
| `public_origin` | `https://host` of Garrison's own host name, or `https://host:port` where nginx serves it on a port other than 443; users open `/admin/` on it. It must differ from the issuer and from `admin_url`'s origin. `garrison doctor` checks the certificate and Garrison's answer on that port. |
| `issuer` | Stalwart's OAuth issuer (`https://host`): the name Stalwart gives itself, `https://` and its Default Hostname, under which it sends every sign-in back; `garrison doctor` compares the two. |
| `stalwart_url` | Stalwart's HTTP listener, **loopback only** (e.g. `http://127.0.0.1:8080`). |
| `admin_url` | Native Stalwart administration (default `<issuer>/admin/`). |
| `links` | Extra header links, e.g. `{ webmail = "https://..." }`; at most 16. |

## `[web]`, `[ingest]`, `[collector]`, `[broker]`

| Key | Default | Meaning |
|---|---|---|
| `web.port` | 8091 | Loopback port behind nginx, 1024 to 65535; see below. |
| `web.session_minutes` | 30 | Session lifetime, 5 to 480 minutes (never longer than the token). |
| `web.bind_client_ip` | false | Answer the session's cookie from another client address than the sign-in's as if signed out; the session goes on from its own address, and a sign-out ends it from any. Breaks mobile users, whose address changes. |
| `ingest.port` | 8094 | Loopback port that Stalwart's webhook calls, 1024 to 65535. |
| `ingest.signature_key` | `credential:webhook-signature-key` | The key Stalwart signs its event batches with; `stalwart setup` writes it, also where the file is empty or holds no key, which is as good as none. |
| `ingest.retention_days` | 30 | Event history retention, 1 to 365 days. An event that is older than this when it arrives is not stored. |
| `ingest.max_events` / `max_database_mib` | 1000000 / 256 | Size limits, 1000 to 10 000 000 events and 16 to 16 384 MiB. When one is reached, the oldest events go before their retention ends; the event views say from when on events are kept. An event takes about 400 bytes, and a server on the internet records some 15,000 a day from unsolicited connections alone. |
| `collector.history_days` | 90 | Metric history retention, 1 to 730 days: every minute of the last eight days, ten-minute values before them. With every check that is about 21 MiB for eight days and 48 MiB for 90. Counted from the collector's own run time: a pause of more than ten minutes or a clock that jumps ahead is not counted, so the history keeps that much longer until the collector has run at the new time for a day. |
| `collector.native_key`, `broker.native_key` | `credential:collector-native-key`, `credential:broker-native-key` | The two read-only API keys; `stalwart setup` writes them, also where a file is empty or holds no key, which is as good as none. |
| `collector.metrics_credential` | `credential:metrics-credential` | User name and password for Stalwart's Prometheus exporter, which the `prometheus` check reads. `stalwart setup` writes the file while the exporter is Garrison's or off, also where it is there but holds no credential; for an exporter of another's, write its user and password into it as `{"username": "...", "secret": "..."}`. The installer keeps an empty file, which means none; `""` turns the setting off. Without a credential the metrics exporter's card says why, with the file and what fills it, as `garrison doctor` does. |
| `collector.dqs_key` | none | Where the key of Spamhaus' Data Query Service is read from: `credential:spamhaus-dqs-key`. The `reputation` check asks a list written without its key, such as `zen.dq.spamhaus.net`, with it, read anew for each run; the key goes into the question and nowhere else ([checks](checks.md#reputation)). Write the key into the file with `sudo sh -c 'cat > /etc/garrison/credentials/spamhaus-dqs-key'` (paste it, Enter, Ctrl-D); the installer keeps an empty file there, which means none, and such a list is then not asked. `check-config` refuses such a list without this setting, and `garrison doctor` fails the file where such a list is asked and it holds no key. |
| `broker.policy` | `/etc/garrison/access-policy.json` | Access policy, see [access.md](access.md). The broker reads it there, the installer starts Garrison once it is there and keeps it root's and readable only for the broker's group, `check-config` and `garrison doctor` check there that the broker may read it, and doctor also that it binds a role or an account, and `garrison uninstall --purge` removes it with its backups. It must be a file of its own: a folder or a link there is left as it is, and `check-config` refuses it. It must also lie where the broker sees it: its unit hides `/home`, `/root`, `/run/user`, `/tmp`, `/var/tmp` and `/dev` from it (all but `/dev/shm` and `/dev/mqueue`), and the kernel's own files, as the collector's unit hides them from the collector ([checks](checks.md#paths-the-collector-cannot-see)), so `check-config` refuses a policy there, or a folder link into them, and `garrison doctor` names it. |
| `broker.allowed_peers` | `["garrison"]` | System users allowed to use the broker socket. |
| `broker.socket` | `/run/garrison/broker.sock` | The broker's Unix socket. Keep the default: `garrison-broker.socket` listens there whatever this says. |

State directories are `/var/lib/garrison/<service>` (`state_directory` in
each of the four sections). Keep the defaults: systemd makes these
directories, and each service may write only in its own. To keep the data on
another disk, mount it at `/var/lib/garrison`. `check-config` warns about a
state directory, `credentials_directory` or `broker.socket` that the units do
not follow, and says what to do; so do the installer, as it starts the
services, and `garrison doctor`.

The installer writes `web.port` into nginx's include,
`/etc/nginx/snippets/garrison.conf`, and into the SELinux module that lets
nginx reach it; `check-config` and `garrison doctor` warn while the include
names another port.
After changing the port, run the installer again. Without it, restart
`garrison-web` and write the include anew; under SELinux nginx reaches the new
port only once the next run of the installer moves the module, and
`garrison doctor` fails it until then:

```sh
sudo sh -c 'garrison nginx --snippet > /etc/nginx/snippets/garrison.conf'
sudo nginx -t && sudo systemctl reload nginx
```

## `[notifications]`

Optional. With it, the collector sends a message on every channel that is
named here: an [ntfy](https://ntfy.sh) topic, a webhook, a mailbox, or
several of them. A message goes out

- when one of Garrison's checks is not in order in two runs in a row (the
  collector runs every minute), Failed or Warning or one after the other;
  one message, not one per run,
- when a check that was reported as a warning then fails in two runs in a
  row,
- when a check that was reported is in order again, whatever it was last,
- when a newer release exists (see the `releases` provider),
- when the collector itself has not finished a run for ten minutes, and when
  it runs again.

A message names each check with its title and its first finding. Only what
Garrison itself observes is reported, and a check that turns Unknown is not.
Neither is a check that a run does not report at all, because what it asks
is away (the checks of Stalwart while its API does not answer): it keeps its
place among the checks that are not in order, and its return is reported
when it is back and in order. A check that stays away, such as one taken out
of the configuration, is forgotten after a day.
A message counts as sent once one channel took it; a channel that did not
take it is not sent it again, and the Alerts page says which one that was.
ntfy and a webhook have taken it once the status line and headers of their
answer have arrived, with 200 from ntfy or anything from 200 to 299 from a
webhook, also where the receiver then ends the connection without TLS's
closing notice and gives its answer no length, as Python's `http.server`
behind `ssl` does.

All these messages come out of collection runs, so a collector that stops
could not report its own end. A watch beside it does (`garrison-watch.timer`,
every five minutes). It also works where the configuration no longer loads,
the usual reason for a collector that stops: it then uses the channels the
last run left. When the whole host is down, nothing on it can send a message;
only a monitor on another machine notices that.

| Key | Meaning |
|---|---|
| `ntfy_url` | An ntfy topic's address, `https://host/topic`, or the file it is kept in, `credential:ntfy-url` ([an address that is a secret](#an-address-that-is-a-secret)). |
| `token` | Where the topic's access token is read from; default `credential:ntfy-token`. |
| `webhook_url` | An `https://` address every message is posted to as JSON, or the file it is kept in, `credential:notify-webhook-url`. |
| `webhook_token` | Where a token for it is read from, sent as `Authorization: Bearer`; default `credential:notify-webhook-token`. |
| `mail_to`, `mail_from`, `mail_host` | The recipient, the sender and the mail server's host name. All three, or none. |
| `mail_user` | The account that signs in; default: the sender's address. |
| `mail_port` | The port for submission with TLS from the first byte; default 465. |
| `mail_password` | Where that account's password is read from; default `credential:notify-mail-password`. |

After a change, send a test message; it says how each channel took it:

```sh
sudo garrison notify-test
```

The secrets are files in `/etc/garrison/credentials` (root, mode 0600). The
installer keeps an empty file for each, which means that none is needed: a
topic or a webhook without a token, an address written in this file. Mail
is always submitted signed in, so its password file must hold the password.
To write one, run this with the file's name, paste the secret, press Enter
and then Ctrl-D:

```sh
sudo sh -c 'cat > /etc/garrison/credentials/ntfy-token'
```

A token is one line of 16 to 8192 printable characters without spaces. A
password is one line of text, which may be short and hold spaces, without
control characters such as a tab; spaces before and after it are not part
of it. An address is one line of printable characters without spaces. A
file that cannot be used, because other users may read it, it is missing or
it holds something else, is that channel's error: nothing goes out on the
channel, the channels' check on the Alerts page is Failed with it from the
next collection run on, and `garrison notify-test`, like the collector's
journal for a message that did not go out, names the setting and the file,
never what it holds.

### ntfy

```toml
[notifications]
ntfy_url = "https://ntfy.example.org/mailserver"
```

ntfy does not have to run on this host: any topic works, on a server of your
own or on ntfy.sh. `garrison detect` names an ntfy server that runs on this
host, with the address its configuration gives. A topic that needs an access
token gets it from the file `ntfy-token`. A topic without one is open to
whoever knows its address: keep that address in a file of its own
([an address that is a secret](#an-address-that-is-a-secret)).

### Webhook

```toml
[notifications]
webhook_url = "https://hooks.example.org/garrison"
```

Each message is one `POST` with a JSON body; any answer from 200 to 299
counts as taken. A token in the file `notify-webhook-token` goes along as
`Authorization: Bearer`. A key in a query follows a path:
`https://hooks.example.org/?key=…`; `check-config` refuses
`https://hooks.example.org?key=…`.

```json
{
  "source": "garrison",
  "host": "garrison.example.org",
  "title": "Garrison on garrison.example.org: 1 failed",
  "message": "Failed: Local full backup: The last run failed.",
  "level": "failed",
  "failed": ["Local full backup: The last run failed."],
  "warnings": [],
  "recovered": [],
  "sentAt": "2026-11-11T18:30:00+00:00"
}
```

`level` is `failed`, `warning` or `ok`.

### An address that is a secret

Every user of this host may read `garrison.toml`: the broker reads it as a
user of its own. Some addresses are a secret, though:
an ntfy topic that takes no token is open to whoever knows its address, and
some webhooks, such as Slack's and Discord's, carry their key in their
address. Keep such an address in a file of its own and name the file
instead. Write the address on one line, as for a secret above:

```sh
sudo sh -c 'cat > /etc/garrison/credentials/ntfy-url'
```

```toml
[notifications]
ntfy_url = "credential:ntfy-url"
# webhook_url = "credential:notify-webhook-url"
```

Use the names `ntfy-url` and `notify-webhook-url`: the units load only
those, `check-config` refuses another, and the installer keeps an empty file
for each. The address in the
file is held to the same rules as one written here; an empty file or one
that holds no such address is that channel's error. Such an address never
shows: the Alerts page, the journal and `garrison notify-test` name its
server only, and the status database, where the watch finds the channels
when the configuration does not load, holds the name of its file, which the
watch reads again. What the status database held of it before, as earlier
releases kept it, goes with the next collection run, free pages included.
`garrison doctor` warns of a topic or a webhook that
takes no token while its address is written in `garrison.toml`.

### Mail

```toml
[notifications]
mail_to = "admin@example.org"
mail_from = "garrison@example.org"
mail_host = "mail.example.org"
```

Garrison submits the mail as a mail program does: it signs in as the account
`mail_from` (or `mail_user`) with the password in the file
`notify-mail-password`, over TLS on port 465, and checks the server's
certificate for the name `mail_host`. Make an account for it in Stalwart, or
an app password of an existing one. Mail handed to port 25 without signing in
would be a stranger's mail to the server, which its spam filter files as such.

Mail through the mail server that Garrison watches does not arrive when that
server is what failed. Name a mailbox elsewhere, or a second channel, for
what must reach you then.

The Alerts page shows the channels, how many checks are not in order and when
the last message went out. Until a first notification has gone out on a
channel, its check of the channels is Unknown: that a channel is named does
not show that a message arrives. `garrison notify-test` shows that at once;
the check itself is in order with the first notification of a collection run
that each channel took. A channel whose secret cannot be used makes the check
Failed in every run, whether a message is due or not. A notification that a
channel did not take makes it Failed with the notification's time, until the
next notification goes out; `garrison notify-test` shows whether one goes
out now, but does not change the check. A channel taken out of this section,
or named otherwise, such as at another server, is no longer judged by it, and
one named since the last notification is Unknown until one has gone out on
it.

## `[milter]`

Gone. Releases up to 0.2 had a macro filter of their own, which this section
switched on: a service that Stalwart showed every incoming message. Garrison
no longer reads mail. A virus scanner refuses documents with macros instead
([installation](installation.md#10-mail-with-office-macros-optional)), and
the [mail test](checks.md#mail-test) shows that it does.

A file that still has the section is refused by name, and so is an upgrade:
this release takes the filter's service away, and Stalwart would defer all
mail while its entry still asks a filter that no longer answers. So have the
release that runs the filter switch it off before you upgrade:

1. Remove the `[milter]` section from `/etc/garrison/garrison.toml`.
2. Run `sudo garrison stalwart setup` with the release that is installed. It
   takes the filter's entry out of Stalwart and stops the filter.
3. Upgrade.

While `garrison-milter.service` still runs, the installer changes nothing and
says so (`install-macro-filter-runs`). Mail that the filter marked with
`X-Garrison-Macro` or `X-Garrison-Scan` keeps those headers; nothing sets
them any more, so a Sieve rule that goes by them matches no new mail.

## `[[actions]]`

Each action starts or restarts one existing systemd unit.

```toml
[[actions]]
id = "run_backup"                 # lowercase identifier, used in profiles
title = "Run full backup"
description = "Shown to the user before confirming."
confirmation = "RUN BACKUP"       # the user must type this exactly
unit = "backup.service"
operation = "start"               # start or restart
cooldown_seconds = 1800
timeout_seconds = 3600            # how long the broker waits for the result
operator = false                  # true: included in the default "operator" profile
```

Both times are required: `cooldown_seconds` from 0 to 86 400 (a day) and
`timeout_seconds` from 5 to 7200 (two hours), so a job that runs longer cannot
be an action. An action is not started again within its `cooldown_seconds`,
and no action within 30 seconds of any other job, counted from when each job
began. A job dated ahead of this host's clock, as after the clock went back,
holds nothing back.

After changing actions, give the profiles of the access policy the actions
as they are now, then run the installer again, or write the polkit rule and
restart the broker and the web service, which read `[[actions]]` only when
they start ([access](access.md#when-the-actions-change)):

```sh
sudo garrison access update
sudo sh -c 'garrison polkit-rule > /etc/polkit-1/rules.d/50-garrison.rules'
sudo systemctl restart garrison-broker garrison-web
```

The polkit rule is what allows the broker to run exactly these units.

### Example: system updates

The distribution's own update job can be an action, so that an administrator
installs pending updates from the Maintenance page, with a confirmation and
an entry in the audit, without a shell on the host:

```toml
[[actions]]
id = "install_updates"
title = "Install system updates"
description = "Installs the pending package updates now, as the nightly job would. Services that the updates restart are away for a moment."
confirmation = "INSTALL UPDATES"
unit = "dnf-automatic-install.service"   # Debian and Ubuntu: apt-daily-upgrade.service
operation = "start"
cooldown_seconds = 3600
timeout_seconds = 3600
```

`dnf-automatic-install.service` comes with the package `dnf-automatic` on the
RHEL family; on Debian and Ubuntu `apt-daily-upgrade.service` runs
`unattended-upgrades`. Other distributions name their job differently:
`systemctl list-unit-files` shows what is there. The same unit as a `systemd`
provider entry shows on the Services page when updates last ran and how the
run ended:

```toml
{ unit = "dnf-automatic-install.service", label = "System updates", modules = ["services"], expect = "idle", max_age_hours = 48 }
```

Garrison only starts the unit. What it installs, and whether it restarts
services or the host, is the job's own configuration. Added after `garrison
access init`, it reaches the Maintenance page once the profiles have it, as
above.

## `[[providers]]`

Each entry is one check: `type` names it, the other keys are its options.
The checks, their options and what each one shows are on a page of their
own: [checks](checks.md).

## Module IDs

`dashboard`, `antivirus`, `spam`, `attacks`, `dns_tls`, `backups`, `alerts`,
`services`, `logs`, `deliveries`, `sessions`, `actions`.
