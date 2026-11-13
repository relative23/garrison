# Operations

## Services

| Unit | Runs as | Purpose |
|---|---|---|
| `garrison-web.service` | garrison | Interface and API on 127.0.0.1:8091 |
| `garrison-ingest.service` | garrison-ingest | Receives Stalwart webhooks on 127.0.0.1:8094 |
| `garrison-collect.timer` | garrison-collector | Collects status every minute |
| `garrison-watch.timer` | garrison-collector | Looks every five minutes whether the collector still runs |
| `garrison-broker.socket` | garrison-broker | Starts the broker on demand for actions and access checks |
| `garrison-milter.service` | garrison-milter | Only with a `[milter]` section: refuses or marks mail with Office macros on 127.0.0.1:8096 |

```sh
systemctl status 'garrison-*'
journalctl -u garrison-web -n 50
```

Logs never contain tokens, cookies, message contents or request URLs.

The installer links Garrison's command into the search path as
`/usr/bin/garrison`; it points to `/opt/garrison/current/bin/garrison`.

## Health check

```sh
sudo garrison doctor         # the whole installation, from the services to what visitors see
sudo garrison check-config   # configuration, providers, access policy
sudo garrison self-check     # database integrity
```

`doctor` changes nothing. It checks the release and the services, that the
access policy and the credentials are private, the clock, free space, the
SELinux module and the last Stalwart event on this host, then, as a visitor
would, Garrison's certificate and answer under its own name, that Stalwart's
public hosts do not serve its metrics, that Stalwart knows Garrison's
sign-in client, where the macro filter is switched on that it answers and
that Stalwart was told of it, and that the issuer's name shows Stalwart's own
sign-in page with the scripts and style sheets it loads. For that it holds the page behind
the public name against the page Stalwart serves itself, so the check is the
same whatever else shares that name: a webmail that answers with a sign-in
page of its own fails it, and so does a proxy that passes the page but not
its files, which leaves a page nobody can sign in on. Every problem comes
with what to do; it exits with 1 when something fails. Run it after every
update of Stalwart, of the proxy in front of it or of an application beside
it.

In the interface, Services shows every unit and failed providers; Deliveries,
Sessions and Event history (under Mail flow) warn in their banner when the
event receiver stops reporting or when events may be missing inside the
history (a recording gap). The same banner says, without a warning, when a
size limit made the history shorter than its retention; raise
`ingest.max_events` or `ingest.max_database_mib` to keep more.

## Backup and restore

```sh
sudo garrison backup --to /var/backups/garrison/latest
```

Run it right before your backup job's snapshot (for example as `ExecStartPre=`
of the backup unit) and include `/var/backups/garrison` and
`/etc/garrison` in the backup. The copy contains no sessions and no
credentials. To verify a restored copy:

```sh
sudo garrison self-check --state /path/to/restored/latest
```

Your own backup of the mail data is watched in another way: where it is a
restic or borg repository, `garrison backup-check` reports its newest
snapshot, its size, an integrity check and a test restore to the Backups
page ([checks](checks.md#backup-check)).

A restore test can run this as a Maintenance action: a unit that restores the
latest snapshot of `/var/backups/garrison` into a temporary directory and
runs `self-check --state` on it, configured as an `[[actions]]` entry.

## Upgrade and rollback

Put the new archive and its `.minisig` signature side by side, then:

```sh
sudo garrison upgrade garrison-<version>-<arch>.tar.gz
```

The installed release checks the signature with the keys compiled into it,
refuses an archive for another architecture or a version that is not newer,
unpacks exactly the bytes it checked and runs the new release's installer.
Releases that trust no key yet, and every archive you checked by hand, are
installed directly:

```sh
tar xzf garrison-<version>-<arch>.tar.gz && cd garrison-<version>-<arch>
sudo ./bin/garrison install
```

The installer backs up the state to `/var/backups/garrison/pre-upgrade-*`,
switches `/opt/garrison/current` to the new release and starts it. The
services report ready only once they serve, and they must then stay up
without a restart for eight seconds, so a release that fails right after it
starts, or keeps restarting, counts as not started. If the new release does not start, or
anything fails after the old one stopped, the installer switches back and
starts the old release again. Installing the running release again backs up to
`pre-reinstall-*` and keeps the pre-upgrade copy that a rollback restores.

Before it changes anything, the installer checks that systemd, polkit and the
free space suffice: the release and a backup as large as the databases must
fit with room to spare. After a successful installation it keeps the running,
the previous and one older release, and the three newest of its own backups
plus the one a rollback restores; it removes the older ones. Backups you write
with `garrison backup --to` are left alone.

While one installer runs, a second one is refused. An installer that was
interrupted, even killed, leaves nothing a later run cannot finish: run it
again.

To return to the previous release:

```sh
sudo garrison install --rollback                  # keep current data
sudo garrison install --rollback --restore-state  # data as before the upgrade
```

A release refuses to open a database written by a newer release. The last line
of an upgrade names the rollback that works: when the new release changes a
database schema, it says `--rollback --restore-state`. When the previous
release cannot read the current data, `--rollback` stops before it changes
anything and asks for `--restore-state`; the data recorded since the upgrade
is then lost. A rollback also stops first when the previous release
cannot load today's configuration, for example because of a `modules` line it
does not know: remove that setting, or put back the file from before the
upgrade (`/var/backups/garrison/last-pre-upgrade/etc/garrison.toml`). With
`--restore-state` it first checks that the state from before the upgrade is
there. If a rollback fails after the services stopped, it starts the release
that ran before.

## Rotating secrets

```sh
sudo garrison stalwart setup --rotate
```

This replaces the two API keys, the webhook signature key and the metrics
credential with new secrets and restarts the services that hold them. A new
key is created before the old one goes, so nothing stops working in between.
Event batches that Stalwart sends while the signature key changes are refused
once and delivered again. Rotate after anyone who should not have them may
have seen the files in `/etc/garrison/credentials`, and from time to time.

## Uninstall

```sh
sudo garrison uninstall --dry-run   # lists what would go
sudo garrison uninstall             # program and system files
```

This stops and removes the services, the polkit rule, the nginx snippets, the
SELinux module, the command's link and `/opt/garrison`, and keeps `/etc/garrison`, the databases in
`/var/lib/garrison`, the installer's backups and the service users, so that
installing again continues with them. `--purge` removes those too, but not
backups you wrote yourself with `garrison backup --to`. After an uninstallation
the command lives on in every release archive: `./bin/garrison uninstall
--purge`. If a server block still includes a Garrison snippet by its exact name,
the uninstallation stops before changing anything and says so; remove the
include first. It also stops first while Stalwart still asks the macro
filter, which would leave Stalwart deferring all mail: remove the `[milter]`
section and run `garrison stalwart setup`, then uninstall. Garrison's
webhook, API keys and sign-in client in Stalwart stay; remove them in the
Stalwart WebUI if you no longer need them.

## Troubleshooting

| Symptom | Check |
|---|---|
| Sign-in fails | `journalctl -u garrison-web`: "token exchange" means OAuth (issuer, origin); "authorization" means policy or roles (`access check <subject>`). The message about too many sign-ins means more than 10 code exchanges in a minute from one network (an IPv4 address or IPv6 /64). |
| Stalwart's sign-in page shows but does nothing, or another application's sign-in appears | The `sign-in` check and `garrison doctor` name it: the proxy for the issuer's host must pass Stalwart's sign-in page, asked for with a `client_id`, and the scripts and style sheets that page names to Stalwart. This usually follows an update of Stalwart or of a webmail on the same name. |
| "Authorization is temporarily unavailable" | Broker or Stalwart unreachable: `systemctl status garrison-broker.socket`, Stalwart running? |
| No new events | The history banner says when events last arrived. `systemctl status garrison-ingest`; Stalwart's log shows `telemetry.webhook-error` if delivery fails; rerun `stalwart setup` after changing the port. |
| An error names a reference | `journalctl -u garrison-web --grep <reference>` shows what failed inside the service; the interface shows only the outcome. |
| A module shows Unknown | The provider cannot read its source; the card's footer names the source. File permissions for the collector user are the usual cause. |
| The firewall check warns though the host is filtered | A unit of the host's own loads the rules, for example one that runs `nft -f`, and the check knows only firewalld, nftables and ufw. Name that unit: `firewall_units = ["…service"]` in the `host-care` provider ([checks](checks.md#host-care)). |
| Pending updates are Unknown and name a dnf cache folder | Only root may read that folder in `/var/cache/dnf`, as a dnf run under umask 077 leaves it, and dnf then lists nothing for the collector's user. `chmod 755` on the folders named; the check asks again within five minutes. |
| Pending updates are Unknown on Fedora 41 or newer | The check reads `apt` and `dnf` 4; dnf 5 is not read yet. |
| A script no longer finds an observation | The id was renamed: [observation ids](observations.md) lists renamed ids, and for one release the observation carries its old id in `value.aliases`. |
| The metrics exporter warns that series are missing | Stalwart names its metrics differently from the release Garrison supports, usually after a Stalwart upgrade. The named counters stay empty instead of showing zero until Garrison supports that release. |
| The DNS records page says Stalwart did not give its domains | The collector's API key is older than this check; run `garrison stalwart setup` again, which gives it the permission to read domains. |
| The TLS certificates card says Stalwart did not give its listeners | As above: run `garrison stalwart setup` again, which lets the collector's key read them; or name `endpoints` for the `tls` provider. |
| A mail test says "not tested" | The mail server ended the session before the message, and the row says with which reply: usually the test mailbox does not exist, or the listener at `host` and `port` is not Stalwart's. |
| A notification says the collector has stopped | No collection run has finished for ten minutes, so nothing is checked. `systemctl status garrison-collect.service garrison-collect.timer` shows whether it fails or was stopped; `garrison check-config` names a configuration it no longer loads. A second message follows when it runs again. |
| No notification arrives | `garrison notify-test` says how each channel took the message. For ntfy and a webhook, 401 or 403 means the token in `/etc/garrison/credentials`; for mail, "did not sign in" means the account or its password, and a certificate error means that `mail_host` is not the name the server's certificate carries ([configuration](configuration.md#notifications)). The Alerts page shows the last failure. |
| Incoming mail is deferred since the macro filter was switched on | Stalwart cannot reach the filter on `127.0.0.1:8096`: `garrison doctor` says whether it answers, `systemctl status garrison-milter` why not. A Stalwart in a container network of its own cannot reach this host's loopback; run it in the host network. To stop asking the filter at once, remove the `[milter]` section and run `garrison stalwart setup`. |
| A sender is told "an attached Office document contains macros" | The macro filter refused the message ([configuration](configuration.md#milter)). `journalctl -u garrison-milter` shows when and what kind of document, never whose. With `on_macro = "tag"` such mail is taken and marked instead. |
| An action says "not installed or loaded" | The configured unit does not exist on this host. |
| An action is denied by systemd | The polkit rule is older than the configuration; run the installer again or write the rule (see [configuration](configuration.md#actions)). |
| nginx answers 502 for Garrison | `garrison doctor` names the cause. Under SELinux, `semodule -l` must list `garrison`, the module that lets nginx reach the web port; run the installer again to load it. Otherwise `systemctl status garrison-web`. |
| nginx answers 502 for Stalwart's own host | Under SELinux nginx may reach Stalwart's HTTP port 8080 (`http_cache_port_t`) only with `setsebool -P httpd_can_network_relay 1`. Garrison's own port needs no boolean: its module `garrison` covers it. |
| `nginx -t` says `unknown directive "http2"` | nginx before 1.25.1 knows only `listen 443 ssl http2;`. `garrison nginx` writes the form your nginx reads. |
| The installer says polkit or systemd is too old | Garrison needs systemd 247 and polkit 0.106 or newer, with JavaScript rules: Debian 12, Ubuntu 24.04, the RHEL 9 family or newer. Ubuntu 22.04 and Debian 11 ship polkit 0.105. |
| `stalwart setup` says Stalwart refuses an API key | Stalwart sees this host at another address than 127.0.0.1, as in a Docker or Podman bridge network. Run Stalwart in the host network (`--network host`, Compose `network_mode: host`) and run `stalwart setup` again. |
| The installer says how many MiB it needs | The release and a backup as large as the databases must fit; free space where it says, then run it again. Nothing was changed. |
| `garrison upgrade` refuses a signature | The archive or its `.minisig` changed after signing, belongs to another release, or was signed with a key the installed release does not trust. Download both again from the release page. |
