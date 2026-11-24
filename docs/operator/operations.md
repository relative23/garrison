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

`doctor` changes nothing. It checks the release and the services, when the
collector last finished a run (none for ten minutes is a problem, as for the
watch), the settings the units do not follow and the secrets they would not
hand to the services, as `check-config` names them, that the credentials
are private and that the broker may read the access policy, which only root
may change and which must bind a role or an account, the clock,
free space, that the SELinux module lets nginx reach `web.port`, and the
last Stalwart event on this host,
then, as a visitor
would, Garrison's certificate and answer under its own name and on the port
`public_origin` names, that Stalwart's
public hosts do not serve its metrics, that Stalwart knows Garrison's
sign-in client and names itself the `issuer` garrison.toml names (asked of
Stalwart's own listener), where the macro filter is switched on that it answers and
that Stalwart's entry asks it there (read with the collector's API key), and that the issuer's name shows Stalwart's own
sign-in page with the scripts and style sheets it loads. For that it holds the page behind
the public name against the page Stalwart serves itself, so the check is the
same whatever else shares that name: a webmail that answers with a sign-in
page of its own fails it, and so does a proxy that passes the page but not
its files, which leaves a page nobody can sign in on. Every problem comes
with what to do; it exits with 1 when something fails. Run it after every
update of Stalwart, of the proxy in front of it or of an application beside
it.

In the interface, Services shows every unit and failed providers; Deliveries,
Sessions and Event history (under Mail flow) and Attacks & bans warn in their
banner when the event receiver stops reporting, when it runs but stores
nothing of what Stalwart sends, or when events may be missing inside the
history (a recording gap). Where the banner cannot learn what the history
covers, it says that completeness is unknown. The same banner says, without
a warning, when a size limit made the history shorter than its retention;
raise `ingest.max_events` or `ingest.max_database_mib` to keep more.

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

To put such a copy back, on the host it came from or on a new one where
Garrison is installed and configured:

```sh
sudo garrison restore --from /path/to/restored/latest
```

Before anything stops, the command checks that the directory is a backup
(`backup.json`), that the running release reads it (a backup names the
release that wrote it, and no release reads what a newer one wrote), that
its copies pass `self-check --state`, that the running release's
`check-config` takes today's configuration with the access policy the
backup brings, which must go where `broker.policy` names it, and that each
copy fits beside the database it replaces. It then copies the state as it
is to
`/var/backups/garrison/pre-restore-*`, stops the services, puts every
database back with its owner and mode and the access policy as a file of
its own, root's and readable for the group `garrison-broker` alone, never
through a link or into a folder that `broker.policy` names, removes a
database that did not exist when the backup was made, and starts the
services. What was recorded since the backup is in the `pre-restore-*` copy
and no longer in Garrison; restore that copy to take the restore back.
Run again after it was interrupted, a restore finishes and names its first
run's copy as the state from before.

A backup holds neither sessions nor credentials. After a restore everyone
signs in again. On a new host, restore `/etc/garrison` from your host backup
first; where `/etc/garrison/credentials` is lost, `garrison stalwart setup`
makes new keys in Stalwart and here, before or after the restore. It also
makes new ones where Stalwart no longer knows the keys of the files, as
where that backup is older than the last `--rotate`.

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
starts, or keeps restarting, counts as not started; where the macro filter
runs, it must stay up as well. Installing the running release again backs up
to `pre-reinstall-*` and keeps the pre-upgrade copy that a rollback restores.

If the new release does not start, or anything fails after the old one
stopped, the installer switches back by itself:

1. It stops everything of Garrison that writes: the services, the timers and
   a collection run that is under way.
2. A new release may already have changed the schema of a database before it
   failed, and the old release refuses to open such a database. Each database
   whose schema rose goes back to its copy in `pre-upgrade-*`, and one that
   did not exist before the upgrade is removed; the installer names them.
   What they recorded between the backup and the stop, seconds as a rule, is
   lost. Every other database keeps its data.
3. It checks with the old release's own `self-check` that it reads every
   database, starts it and waits until it stays up. Only then does the
   installer say `the previous release is running`, and `previous` is again
   what it was before the upgrade.

If the old release does not start either, the installer says so and stops
what did start. `/opt/garrison/current` then still names the new release and
`previous` the old one, so that

```sh
sudo /opt/garrison/current/bin/garrison install --rollback --restore-state
```

returns to the old release with the whole state from before the upgrade. The
installer exits with 1 in both cases; the journal says why the new release
failed.

Before it changes anything, the installer checks that systemd, polkit and the
free space suffice: the release and a backup as large as the databases must
fit with room to spare. Where it started the services before, the new
release must load the configuration and find the access policy where
`broker.policy` names it, also outside `/etc/garrison`; otherwise nothing
changes. After a successful installation it keeps the running,
the previous and one older release, and the three newest of its own backups
plus the one a rollback restores; it removes the older ones. Backups you write
with `garrison backup --to` are left alone; the `pre-restore-*` copies of a
restore count among the installer's own.

While one installer runs, a second one is refused. An upgrade that was
interrupted, even killed, is finished by running its installer again, or
`garrison upgrade` with the same archive; `/opt/garrison/unfinished.json`
notes what the installer began until a release runs again. A rollback is
finished by running it again; one that went back to a release from before this
one is finished by the release it left, as its first line says: `sudo
/opt/garrison/releases/<release>/bin/garrison install --rollback`.

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
there, that no release newer than the one it returns to wrote it
(`backup.json` in a backup names the release), that the release it
returns to takes today's configuration with the access policy from before
the upgrade and that each copy fits beside the database it replaces; it
then puts back every
database and the access policy and removes a database that did not exist
when the backup was made. If a rollback fails after the services stopped, it
starts the release that ran before, and names what went back to its copy
from before the upgrade by then: the release that ran before runs on that,
and what was recorded there since the upgrade is lost. A restore that
fails names what went back likewise.

## Rotating secrets

```sh
sudo garrison stalwart setup --rotate
```

This replaces the two API keys, the webhook signature key and the metrics
credential with new secrets and restarts the services that hold them. A new
key is created and written first, and the old one goes only after the
services that hold it have restarted with the new one, so sign-in and the
checks of users' rights go on throughout. Event batches that Stalwart sends
while the signature key changes are refused once and delivered again.
Rotate after anyone who should not have them may have seen the files in
`/etc/garrison/credentials`, and from time to time.

Run it as root, so that it can restart the services itself. If it stops
with an error after it made new keys, it still restarts `garrison-ingest`
and `garrison-broker` and removes the old keys, since someone may have seen
them: once the cause is mended, run `sudo garrison stalwart setup --rotate`
again, as its message says, also after a run that was interrupted.

## Uninstall

```sh
sudo garrison uninstall --dry-run   # lists what would go
sudo garrison uninstall             # program and system files
```

This stops and removes the services, the polkit rule, the nginx snippets, the
SELinux module, the command's link and `/opt/garrison`, and keeps `/etc/garrison`, the databases in
`/var/lib/garrison`, the installer's backups and the service users, so that
installing again continues with them. `--purge` removes those too, but not
backups you wrote yourself with `garrison backup --to`; where `garrison.toml`
does not load, it leaves an access policy kept outside `/etc/garrison` and
says so. After an uninstallation
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
| Sign-in fails | `journalctl -u garrison-web`: "token exchange" means OAuth (issuer, origin); "authorization" means policy or roles (`access check <subject>`); "at the callback" names what the callback from Stalwart's sign-in page brought, where "it names the issuer …, where deployment.issuer is …" for every sign-in means that Stalwart names itself under another URL than `issuer` in garrison.toml: set it to the one the line names ([configuration](configuration.md#deployment)), as long as that is Stalwart's own. Where Garrison could not keep the sign-in itself, as on a full disk or with `web.sqlite` locked, the sign-in page's address says `login_error=internal` with a `reference`, under which `journalctl -u garrison-web --grep <reference>` says "the sign-in's session could not be stored" and why. The message about too many sign-ins from your network means more than 10 code exchanges in a minute from one network (an IPv4 address or IPv6 /64). The one about many networks means that more than 4096 networks tried within a minute, which is a flood: the journal warns of it, people already signed in stay signed in, and sign-in works again a minute after it ends. The message that Stalwart did not answer means that its token endpoint could not be reached or failed, "token exchange (Stalwart unavailable)" in the journal; the one that Stalwart is busy, that it refused the exchange for its rate limit, "token exchange (Stalwart's rate limit, HTTP 429)"; the one that access could not be checked, that the check of the user's rights answered 503, "Sign-in rejected by authorization (HTTP 503: …)" with the broker's words, and `journalctl -u garrison-broker` names why, or this journal, where the broker gave no answer, or that Stalwart answered the code exchange in a form this release of Garrison does not read, "token exchange (an answer this release does not read)" in the journal, as after an upgrade of Stalwart to a release Garrison does not support yet: the README names the supported releases. Stalwart's own limits count by the address it sees, which a failed sign-in at its page shows in the event history: at 127.0.0.1, where Stalwart runs on this host, they stop nothing. Under one other address that all clients share, as with Stalwart in a container behind a published port, sign-in failing for everyone, with Stalwart's own sign-in page saying "Unable to continue", usually means that Stalwart answers 429, which the journal names as "token exchange (Stalwart's rate limit, HTTP 429)": it takes 100 unauthenticated requests a minute from one address, failed sign-ins among them; it passes within a minute of the last failed sign-in, and people already signed in are not affected. Stalwart answering 403, or nothing, from that address may mean that it blocked the address after 100 failed password sign-ins in a day: remove it in the Stalwart WebUI under Settings → Security → Blocked IPs, then Management → Actions → Blocked IPs list, from another address, or wait for the duration you gave blocks. With the client's address forwarded ([installation](installation.md#client-addresses-for-stalwarts-limits)) both fall on one client alone, whose own address the event history then names; that client gets 403 from Stalwart, its sign-in page included, until the block's duration is over ([security model](../architecture/security.md#known-limits)). A client that nginx sees at loopback is not named and still counts under nginx's address: where that is not 127.0.0.1, every client getting 502 from nginx may mean that such a client's failed passwords blocked it, which allowing that address in Stalwart prevents ([installation](installation.md#client-addresses-for-stalwarts-limits)). |
| Attacks & bans and the Event history name 127.0.0.1 for every failed sign-in at Stalwart's page | Stalwart records a sign-in under the address it sees, and behind nginx on this host that is nginx's, which its limits and blocks pass over. With the client's address forwarded ([installation](installation.md#client-addresses-for-stalwarts-limits)) both name each client's own address, an IPv6 one too, for its failed sign-ins and for Stalwart's blocks. Successful sign-ins at Stalwart's page are not recorded. |
| Stalwart's sign-in page shows but does nothing, or another application's sign-in appears | The `sign-in` check and `garrison doctor` name it: the proxy for the issuer's host must pass Stalwart's sign-in page, asked for with a `client_id`, and the scripts and style sheets that page names to Stalwart, and also `/api/auth/client` and `/api/auth`, which the page asks; doctor says when something else answers its question there. This usually follows an update of Stalwart or of a webmail on the same name. |
| "Authorization is temporarily unavailable" | Broker or Stalwart unreachable: `systemctl status garrison-broker.socket`, Stalwart running? Where the broker gives no answer, every page says so in these words, the Maintenance page too, and `journalctl -u garrison-web` says "The broker gave the web service no answer it can use" with why (its socket could not be reached, no answer within 15 s, it closed the connection without an answer, or its answer could not be read) and the socket, at most once a minute with how many more there were. The broker serves 16 requests at once and closes a connection beyond them unanswered; `journalctl -u garrison-broker` then says "Closing broker connections". Where it says "Stalwart did not complete a check of a user's rights", Stalwart could not be reached or failed on its side: the line names the request, UserInfo or the management API, and how, such as "Stalwart is unavailable" for a connection it did not answer or "Stalwart answered HTTP 503", and comes at most once a minute with how many more failed; users stay signed in, and the checks work again once Stalwart answers. Where it says "Stalwart refused a check of a user's rights for its rate limit", Stalwart answered 429 to the broker's key, which every user's checks share, or to one user's token; the line names which, comes at most once a minute with how many more were refused, and the checks work again once Stalwart's minute is over. That happens only where Stalwart sees the broker under an address other than 127.0.0.1, beyond about 330 checks of users' rights a minute, which share the broker key's 1000 requests a minute ([security model](../architecture/security.md#known-limits)). Where it says "Stalwart answered in a form this release of Garrison does not read", Stalwart's answer to UserInfo or to the management API, which the line names, is not one this release reads, usually after an upgrade of Stalwart to a release Garrison does not support yet: users stay signed in, the README names the supported releases, and a Garrison release that supports Stalwart's mends it. Only a 401 of UserInfo ends a session; a line that names another status there, such as "UserInfo: Stalwart answered HTTP 403", may be an account removed while its user was signed in, whose token Stalwart then answers 403 (measured on 1.1.0; that session goes on getting this answer until its time ends), and where Stalwart sees the broker under an address other than 127.0.0.1, also a block of that address (see "Sign-in fails"). |
| "Garrison is not set up to check access rights; the broker's journal says why" | `journalctl -u garrison-broker` says why after "Access rights cannot be checked": the policy does not read or is not protected (`garrison access list`), names an action the configuration does not have, or binds a subject under `subjects` to an account Stalwart does not have, which the line names ("the policy binds subject … to account …"): correct or remove that entry ([access](access.md)); or the broker's API key is missing or no longer taken: `garrison stalwart setup`. People who are signed in stay signed in meanwhile. |
| "Garrison is not set up to check access rights", and `journalctl -u garrison-broker` says "Garrison access policy: unknown actions" | The access policy names an action that the broker does not know: one taken out of `garrison.toml`, or one that `garrison access update` gave the profiles while the broker still runs with the actions it read when it started. Run `sudo garrison access update`, then the installer again, or restart the broker with `sudo systemctl restart garrison-broker` ([access](access.md#when-the-actions-change)). |
| A page says "The broker returned an invalid authorization" | The broker's grant is one this web service does not read, and `journalctl -u garrison-web` says so: the two read different configurations, as after an action was added to `[[actions]]` in garrison.toml and only garrison-broker was restarted, or they run different releases. `sudo systemctl restart garrison-web garrison-broker`, as after every change of garrison.toml that both read. Where `journalctl -u garrison-broker` says "The broker could not read a request", the same holds for the web service's requests, whose pages say "Internal error" with a reference meanwhile. |
| A maintenance action answers "Audit capacity reached" | The broker keeps a record of every job for 30 days, at most 1000 of them, and drops none early, so that nothing done on the host goes unrecorded. Records leave by themselves after 30 days. To make room sooner, as root: `systemctl stop garrison-broker.socket garrison-broker.service`, move `/var/lib/garrison/broker/jobs.sqlite` and its `-wal` and `-shm` files, if there are any, to where such records are kept, and `systemctl start garrison-broker.socket`. The broker begins a new audit; the file that was moved is the old one. |
| A maintenance action answers "Allow the previous operation to settle first" or "This action is still in its cooldown period" | A job began less than 30 seconds ago, or this action ran within its `cooldown_seconds`; the Maintenance page lists the jobs with their times. Ask again once that time has passed. A job dated ahead of this host's clock, as after the clock went back, holds nothing back, since when it ran is not known; a job begun since does, as any. |
| A job ends as failed and says that nothing was run | The message names the reason: the broker could not start it, the audit did not take the record of its start, or the rights of whoever asked could not be confirmed when it started (changed, signed out, Stalwart not completing the check, refusing it for its rate limit or answering in a form this release does not read, or Garrison not set up to check them). `journalctl -u garrison-broker` has the cause in a line that names the job, for an outage the request that failed and how, for the rate limit whether Stalwart refused the broker's key or the user's token; ask for the action again once it is mended, or once Stalwart's minute is over. |
| The Management API card says "Stalwart refused the collector's key for its rate limit (HTTP 429)", or the DNS records, TLS certificates, Blocklists, Reverse names or Spam and ham by domain card says so of Stalwart's domains, listeners or accounts | Stalwart answered the collector's request 429. It counts the requests of each key, and those without one by address, only where it sees the collector under an address other than 127.0.0.1 ([security model](../architecture/security.md#known-limits)); the next run after Stalwart's minute reads the card again, the Blocklists and Reverse names cards too, and the Spam and ham by domain card within ten minutes, as it keeps its reading. |
| The DNS records, TLS certificates, Blocklists, Reverse names or Spam and ham by domain card says Stalwart did not complete the collector's request for its domains, listeners or accounts | Stalwart could not be reached or failed on its side, as the Management API card then says too, and the card names how in brackets, such as "Stalwart is unavailable" for a connection it did not take, "Stalwart answered HTTP 503" or "Stalwart could not complete the request" for the JMAP error serverFail: see whether Stalwart runs, and its log. The next run asks again, the Blocklists and Reverse names cards too, and the Spam and ham by domain card within ten minutes. |
| No new events | The history banner says when events last arrived. `systemctl status garrison-ingest`; Stalwart's log shows `telemetry.webhook-error` if delivery fails; rerun `stalwart setup` after changing the port. |
| An error names a reference | `journalctl -u garrison-web --grep <reference>` shows what failed inside the service; the interface shows only the outcome. |
| A page says "The query waited too long for another service's write" | The event receiver or the collector held its database for longer than the two seconds a page waits for it: the receiver while it removes a tenth of a full event history at its size limit, either of them on a slow disk. It passes; try again in a moment. Meanwhile `journalctl -u garrison-web` says so once a minute and names the database: "A reader of … waited 2 s for its writer and gave up". Where such lines go on for many minutes, its writer does not let go of it: `systemctl status garrison-ingest` for the event history, `systemctl status garrison-collect` for the status. |
| A module shows Unknown | The provider cannot read its source; the card's footer names the source. File permissions for the collector user are the usual cause. |
| The firewall check warns though the host is filtered | A unit of the host's own loads the rules, for example one that runs `nft -f`, and the check knows only firewalld, nftables and ufw. Name that unit: `firewall_units = ["…service"]` in the `host-care` provider ([checks](checks.md#host-care)). |
| Pending updates are Unknown and name a dnf cache folder | Only root may read that folder in `/var/cache/dnf`, as a dnf run under umask 077 leaves it, and dnf then lists nothing for the collector's user. `chmod 755` on the folders named; the check asks again within five minutes. |
| Pending updates are Unknown on Fedora 41 or newer | The check reads `apt` and `dnf` 4; dnf 5 is not read yet. |
| A script no longer finds an observation | The id was renamed: [observation ids](observations.md) lists renamed ids, and for one release the observation carries its old id in `value.aliases`. |
| The metrics exporter warns that series are missing | Stalwart names its metrics differently from the release Garrison supports, usually after a Stalwart upgrade. The named counters stay empty instead of showing zero until Garrison supports that release. |
| The DNS records page, or the Blocklists and Reverse names cards, say Stalwart did not give its domains, the Spam and ham by domain card its accounts, or the Management API card says "access denied" | Stalwart refused the collector's API key, usually one older than these checks; run `garrison stalwart setup` again, which gives it the permissions to read them. The DNS records, Blocklists and Reverse names cards follow with the next run, the Spam and ham by domain card within ten minutes. |
| The DNS records, Management API, TLS certificates, Blocklists, Reverse names or Spam and ham by domain card says that the collector has no API key for Stalwart | The collector read no key from `/etc/garrison/credentials/collector-native-key`: the file is missing, empty or holds no key. Run `garrison stalwart setup`, which makes it, also where the file is there and Stalwart still has the collector's key; `garrison doctor` names such a file, and the collector's journal says why it has no key once for each reason, and once that it has one again. Once the key is there, the next run reads each of these cards again, also the Spam and ham by domain, Blocklists and Reverse names cards, which keep a reading for a while otherwise. The cards that need no key, such as the other mail-flow cards, are read meanwhile, and the TLS certificates card checks the `endpoints` it is given. |
| The TLS certificates card says Stalwart did not give its listeners or its domains | As above: run `garrison stalwart setup` again, which lets the collector's key read them; or name `endpoints` for the `tls` provider. |
| A card says that Stalwart answered in a form this release of Garrison does not read, or the metrics exporter's that its answer could not be read | Stalwart runs a release whose answers this release does not read, usually after an upgrade of Stalwart; the card names the answer, and the README the supported releases. `garrison stalwart setup` does not mend it, a Garrison release that supports Stalwart's does; meanwhile the TLS certificates card checks the `endpoints` it is given. `garrison access` and `garrison stalwart setup` say the same of such an answer. |
| A mail test says "not tested" | The mail server ended the session before the message, and the row says with which reply: usually the test mailbox does not exist, or the listener at `host` and `port` is not Stalwart's. "not sent: the collection run's time was used up" means that the checks before it took the run's time; the next run sends it. |
| A check shows as "Provider …" with "Not run" | A collection run has 70 seconds for its checks, so that systemd never ends it with nothing stored. Checks that could not begin in that time are Unknown for this run; the others are stored as usual. A check that asks many times stops asking when the time is up and names what it left, such as an endpoint "not checked" on the TLS certificates card, a list "not asked" on the Blocklists card or a record "not asked" on a domain's DNS records; a later run asks it again. The collector's journal names a check that took ten seconds or more (`journalctl -u garrison-collect.service`): most often a resolver or a server that does not answer. |
| The event views say the receiver runs but has not stored what Stalwart sends | Every batch is refused, or events arrive that it cannot read; the checks that count events are Unknown meanwhile. `curl -s http://127.0.0.1:8094/health` says since when and how many were refused or unreadable, and `journalctl -u garrison-ingest.service` why. A signature that does not match: run `garrison stalwart setup` again, which gives Stalwart and the receiver the same key. Storage: free space on the disk of `/var/lib/garrison/ingest`, or raise `ingest.max_database_mib`. Unreadable events after a Stalwart upgrade: that release writes them differently; see the supported releases. An event dated more than five minutes ahead of this host's clock, or older than `ingest.retention_days`, counts as unreadable too, since retention goes by an event's own time: check the clock of the host Stalwart runs on. Once a batch is stored whole again, what was lost becomes a recording gap. |
| The collector's journal says a run is dated more than ten minutes after the collector's own run time | The clock jumped ahead, or the collector paused, as for a reboot or a stopped timer. Until the collector has run at the new time for a day, or the clock comes back, the metric history is cleaned up by the time the collector has run, so it keeps the pause a little longer. `timedatectl` shows the time and whether the clock follows a time server, as the clock check of Host care does. Once a clock that ran ahead is put right, the collector reaches the minutes it wrote ahead a second time: the charts there show the events of both times, and lose none. |
| The collector's journal says that the status database could not be cleared of a key of Spamhaus' Data Query Service | The rebuild that leaves no copy of a key an earlier release kept failed or did not finish; nothing else depends on it, and the web service reads on. Where it names a full disk, make room on the disk of `/var/lib/garrison/collector`: the next run tries again. Where it says "within the time this run left", the disk writes too slowly for the history in the eight minutes a run asks for, and a run tries again a day later; fewer `collector.history_days` make the file smaller over the following days. |
| `garrison doctor` says that the newest status snapshot, or the last Stalwart event, is dated minutes ahead of this host's clock | It was written before the clock went back, or while a clock that ran ahead was not yet put right, so how old it is is not known. `timedatectl` shows whether the clock follows a time server. The event line is right again once an event has arrived at the clock's time; the snapshot line once the ten snapshots the collector keeps are all from it, ten minutes of collection runs. |
| The collector's journal, or `garrison collect` run by hand, says "Another collection run is under way" | Two runs met, the timer's and one started by hand. The second ends at once, collects nothing and exits as a success; the run under way stores its snapshot as usual. Runs are kept apart because two whose readings of Stalwart's counters cross would count the same deliveries and sign-ins twice. To collect at once by hand, `sudo systemctl start garrison-collect.service` waits for a run that is under way instead of starting a second one. |
| `journalctl -u garrison-ingest` says that the signature key's file is empty, or `journalctl -u garrison-broker` that the broker's API key's file is | The file in `/etc/garrison/credentials` is there but holds no key, which is as good as none: the receiver does not start, and the broker checks no user's rights. The journal names the copy systemd hands the service (`/run/credentials/<unit>/<name>`), also where the file is missing or holds something else, and `garrison doctor` fails the file. Run `garrison stalwart setup`, which makes the key there and gives it to Stalwart; the receiver, which systemd starts again every two seconds meanwhile, and the broker then read it, as setup says. |
| `garrison-collect.service` or `garrison-watch.service` fails with `status=243/CREDENTIALS` | A file in `/etc/garrison/credentials` that the unit loads is missing, and systemd starts no unit without each of its credential files ("Failed to set up credentials" in its journal). `garrison doctor` names the file and the command that makes it; the installer keeps an empty one, which means none, for each that may be empty, such as `metrics-credential` where Stalwart's exporter is another's. |
| A notification says the collector has stopped | No collection run has finished for ten minutes, so nothing is checked. `systemctl status garrison-collect.service garrison-collect.timer` shows whether it fails or was stopped; `garrison check-config` names a configuration it no longer loads. A second message follows when it runs again. |
| No notification arrives | `garrison notify-test` says how each channel took the message. For ntfy and a webhook, 401 or 403 means the token in `/etc/garrison/credentials`; for mail, "did not sign in" means the account or its password, and "the certificate is not valid for this name" means that `mail_host` is not a name the server's certificate carries, which the message names ([configuration](configuration.md#notifications)). The Alerts page names the last notification a channel did not take, with its time, until the next one goes out; a channel taken out of the configuration is no longer named there. |
| Incoming mail is deferred since the macro filter was switched on | Stalwart cannot reach the filter where its entry asks it: `garrison doctor` says whether it answers and where Stalwart asks it, `systemctl status garrison-milter` why it does not answer. A Stalwart in a container network of its own cannot reach this host's loopback; run it in the host network. To stop asking the filter at once, remove the `[milter]` section and run `garrison stalwart setup`. |
| A sender is told "an attached Office document contains macros" | The macro filter refused the message ([configuration](configuration.md#milter)). `journalctl -u garrison-milter` shows when and what kind of document, never whose. With `on_macro = "tag"` such mail is taken and marked instead. |
| An action says "not installed or loaded" | The configured unit does not exist on this host. |
| An action is denied by systemd | The polkit rule is older than the configuration; run the installer again or write the rule (see [configuration](configuration.md#actions)). |
| nginx answers 502 for Garrison | `garrison doctor` names the cause. Under SELinux the module `garrison` must be loaded for `web.port`, which doctor compares; run the installer again to load it. `garrison check-config` warns when nginx's include names another port than `web.port`. Otherwise `systemctl status garrison-web`. |
| nginx answers 502 for Stalwart's own host | Under SELinux nginx may reach Stalwart's HTTP port 8080 (`http_cache_port_t`) only with `setsebool -P httpd_can_network_relay 1`. Garrison's own port needs no boolean: its module `garrison` covers it. |
| `nginx -t` says `unknown directive "http2"` | nginx before 1.25.1 knows only `listen 443 ssl http2;`. `garrison nginx` writes the form your nginx reads. |
| The browser says that Garrison's page redirects too many times | `public_origin` names a port other than 443, and nginx passes the host name without the port: an include of your own with `proxy_set_header Host $host;`. Garrison's include passes the host as the browser sent it (`$http_host`); write it anew: `sudo sh -c 'garrison nginx --snippet > /etc/nginx/snippets/garrison.conf' && sudo nginx -t && sudo systemctl reload nginx`. |
| The installer says polkit or systemd is too old | Garrison needs systemd 247 and polkit 0.106 or newer, with JavaScript rules: Debian 12, Ubuntu 24.04, the RHEL 9 family or newer. Ubuntu 22.04 and Debian 11 ship polkit 0.105. |
| `stalwart setup` says Stalwart refuses an API key | Stalwart answered HTTP 403: it knows the key but sees this host at another address than 127.0.0.1, as in a Docker or Podman bridge network. Run Stalwart in the host network (`--network host`, Compose `network_mode: host`) and run `stalwart setup` again. A key Stalwart does not know at all (HTTP 401), as where `/etc/garrison/credentials` was put back from a copy older than the last rotation, setup makes anew by itself and says so. |
| `stalwart setup` says it cannot write the credentials folder | It writes the keys Stalwart makes to `/etc/garrison/credentials`, which is root's: run it as root, with `sudo`. It stopped before it asked for the administrator and changed nothing. Run as root, it names the reason, such as a file system mounted read-only. |
| `stalwart setup` says Stalwart refused the administrator | HTTP 401: Stalwart does not know the user name and password, or the API key, that setup was given; check them and run it again. HTTP 403: Stalwart knows the credential but does not take it from this host's address, as for an API key whose networks leave this host out, or for an address it blocked after failed sign-ins (see "Sign-in fails"). Setup changed nothing. Where it says that Stalwart refused the administrator an API key, setup was given an account without Stalwart's administrator rights: run it as an administrator. |
| The installer says how many MiB it needs | The release and a backup as large as the databases must fit; free space where it says, then run it again. Nothing was changed. |
| `garrison upgrade` refuses a signature | The archive or its `.minisig` changed after signing, belongs to another release, or was signed with a key the installed release does not trust. Download both again from the release page. |
