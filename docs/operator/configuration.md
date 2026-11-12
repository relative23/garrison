# Configuration reference

One file, `/etc/garrison/garrison.toml`, read by all services. Unknown
keys are errors, so a typo cannot silently fall back to a default. Check changes
with `garrison check-config`, then restart the affected services
(the collector picks changes up on its next run).

Secrets never appear in this file. A value `credential:NAME` refers to
`/etc/garrison/credentials/NAME`, which systemd hands to the service
with `LoadCredential=`.

## Top level

| Key | Default | Meaning |
|---|---|---|
| `schema` | none | Must be `1`. |
| `credentials_directory` | `/etc/garrison/credentials` | Source of the `credential:` files. |
| `modules` | all modules | The modules this installation offers, as [module IDs](#module-ids). The dashboard and services are always on. Nobody is granted another module, whatever the access policy says, and without `actions` the broker runs no action. An unknown ID is an error. `garrison modules` sets it. |

## `[deployment]`

| Key | Meaning |
|---|---|
| `public_origin` | `https://host` of Garrison's own host name; users open `/admin/` on it. It must differ from the issuer and from `admin_url`'s origin. |
| `issuer` | Stalwart's OAuth issuer (`https://host`). |
| `stalwart_url` | Stalwart's HTTP listener, **loopback only** (e.g. `http://127.0.0.1:8080`). |
| `admin_url` | Native Stalwart administration (default `<issuer>/admin/`). |
| `links` | Extra header links, e.g. `{ webmail = "https://..." }`. |

## `[web]`, `[ingest]`, `[collector]`, `[broker]`

| Key | Default | Meaning |
|---|---|---|
| `web.port` | 8091 | Loopback port behind nginx. |
| `web.session_minutes` | 30 | Session lifetime (never longer than the token). |
| `web.bind_client_ip` | false | End the session when the client IP changes. Breaks mobile users. |
| `ingest.port` | 8094 | Loopback port that Stalwart's webhook calls. |
| `ingest.signature_key` | `credential:webhook-signature-key` | The key Stalwart signs its event batches with; `stalwart setup` writes it. |
| `ingest.retention_days` | 30 | Event history retention. |
| `ingest.max_events` / `max_database_mib` | 1000000 / 256 | Size limits. When one is reached, the oldest events go before their retention ends; the event views say from when on events are kept. An event takes about 400 bytes, and a server on the internet records some 15,000 a day from unsolicited connections alone. |
| `collector.history_days` | 90 | Metric history retention. |
| `collector.native_key`, `broker.native_key` | `credential:collector-native-key`, `credential:broker-native-key` | The two read-only API keys; `stalwart setup` writes them. |
| `collector.metrics_credential` | none | User name and password for Stalwart's Prometheus exporter; the example configuration names `credential:metrics-credential`, which `stalwart setup` writes. |
| `broker.policy` | `/etc/garrison/access-policy.json` | Access policy, see [access.md](access.md). |
| `broker.allowed_peers` | `["garrison"]` | System users allowed to use the broker socket. |
| `broker.socket` | `/run/garrison/broker.sock` | The broker's Unix socket. |

State directories default to `/var/lib/garrison/<service>`
(`state_directory` in each of the four sections).

## `[notifications]`

Optional. With it, the collector sends a message on every channel that is
named here: an [ntfy](https://ntfy.sh) topic, a webhook, a mailbox, or
several of them. A message goes out

- when one of Garrison's checks is Failed or Warning in two runs in a row
  (the collector runs every minute); one message, not one per run,
- when that check is in order again,
- when a newer release exists (see the `releases` provider),
- when the collector itself has not finished a run for ten minutes, and when
  it runs again.

A message names each check with its title and its first finding. Only what
Garrison itself observes is reported, and a check that turns Unknown is not.
A message counts as sent once one channel took it; a channel that did not
take it is not sent it again, and the Alerts page says which one that was.

All these messages come out of collection runs, so a collector that stops
could not report its own end. A watch beside it does (`garrison-watch.timer`,
every five minutes). It also works where the configuration no longer loads,
the usual reason for a collector that stops: it then uses the channels the
last run left. When the whole host is down, nothing on it can send a message;
only a monitor on another machine notices that.

| Key | Meaning |
|---|---|
| `ntfy_url` | An ntfy topic's address, `https://host/topic`. |
| `token` | Where the topic's access token is read from; default `credential:ntfy-token`. |
| `webhook_url` | An `https://` address every message is posted to as JSON. |
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
installer keeps an empty file for each, which means that none is needed. To
write one, run this with the file's name, paste the secret, press Enter and
then Ctrl-D:

```sh
sudo sh -c 'cat > /etc/garrison/credentials/ntfy-token'
```

### ntfy

```toml
[notifications]
ntfy_url = "https://ntfy.example.org/mailserver"
```

ntfy does not have to run on this host: any topic works, on a server of your
own or on ntfy.sh. `garrison detect` names an ntfy server that runs on this
host, with the address its configuration gives. A topic that needs an access
token gets it from the file `ntfy-token`.

### Webhook

```toml
[notifications]
webhook_url = "https://hooks.example.org/garrison"
```

Each message is one `POST` with a JSON body; any answer from 200 to 299
counts as taken. A token in the file `notify-webhook-token` goes along as
`Authorization: Bearer`.

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
the last message went out.

## `[milter]`

Optional, and the one part of Garrison that acts on mail. With this section
a filter runs (`garrison-milter.service`) that Stalwart shows every incoming
message before taking it. The filter looks for Office documents that carry
macros and has such a message refused or marked. Nothing else is judged, and
no message is kept or written anywhere.

| Key | Default | Meaning |
|---|---|---|
| `port` | 8096 | Loopback port the filter listens on. |
| `on_macro` | `"reject"` | `"reject"`: the sending server gets `550 5.7.1 Message refused: an attached Office document contains macros.` and tells its sender. `"tag"`: the message is taken with the header `X-Garrison-Macro: yes`, for a Sieve rule or a mail program to act on. |
| `max_message_mib` | 64 | A larger message is taken unscanned; at most 256. The filter holds 256 MiB of arriving mail in all and has the sending server bring a message again that finds no room. |
| `when_unreachable` | `"defer"` | What Stalwart does while the filter does not answer: `"defer"` has the sending server try again later, `"accept"` takes the mail unscanned. |

To switch it on, add the section (`[milter]` alone takes every default) and
run `garrison stalwart setup` as root. Setup starts the filter, makes sure it
answers and only then enters it in Stalwart (Settings ▸ MTA ▸ Milters shows
the entry for `127.0.0.1`). Run setup again after changing a key.

Then send the server a mail from outside and see that it arrives. Stalwart
must reach `127.0.0.1` of this host, as it does for the webhook; a Stalwart
in a container network of its own cannot, and would defer all mail. The
Antivirus page warns when Stalwart did not reach its milter.

To switch it off, remove the section and run `garrison stalwart setup` again:
it takes the entry out of Stalwart first and stops the filter afterwards.
Keep to that order. While Stalwart has the entry and the filter does not run,
Stalwart defers all incoming mail (or takes it unscanned, with `"accept"`).
For the same reason `garrison uninstall` refuses while the entry is there,
and `garrison doctor` reports a filter that Stalwart asks in vain.

What the filter finds: a VBA project in Word, Excel and PowerPoint files of
the newer format (`.docm`, `.xlsm`, `.pptm`, also under another name such as
`.docx`) and in Word and Excel files of the old one (`.doc`, `.xls`), Excel
4.0 macro sheets in the newer format, and Word's single-file web pages with
an embedded macro store, each also inside zip archives up to three levels
deep. A file counts as soon as it has a macro project, also an empty one.
What it does not see: an archive with a password, other archive formats such
as 7z and RAR, Excel 4.0 macro sheets in an old `.xls` file, the macros of an
old `.ppt` file, macros in LibreOffice's own formats, and a document behind
a link. It complements a virus scanner and does not replace one.

The Antivirus page lists the milters Stalwart asks, this one beside a
scanner's, and warns of each that lets mail pass while it is away (the
`stalwart` check; its `milter_host` and `milter_port` name one milter to look
at alone). It also counts what Stalwart heard from its milters by day
(`mail-flow`), and the [`mail-test`](checks.md#mail-test) check can send a harmless
test document through the mail server every day.

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

After changing actions, write the polkit rule again (or run the installer
again, which does the same):

```sh
sudo sh -c 'garrison polkit-rule > /etc/polkit-1/rules.d/50-garrison.rules'
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
services or the host, is the job's own configuration.

## `[[providers]]`

Each entry is one check: `type` names it, the other keys are its options.
The checks, their options and what each one shows are on a page of their
own: [checks](checks.md).

## Module IDs

`dashboard`, `antivirus`, `spam`, `attacks`, `dns_tls`, `backups`, `alerts`,
`services`, `logs`, `deliveries`, `sessions`, `actions`.
