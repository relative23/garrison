# Changelog

Notable changes for operators and users. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Upgrade notes

- **Run `garrison stalwart setup` again after the upgrade.** The webhook then
  asks Stalwart for four event types more, those of the two additions below.
  Until it has run, the card "Milter verdicts" and Attacks & bans count none
  of them; everything else works as before.

### Added

- **The card "Milter verdicts" counts and warns of a milter answer that
  Stalwart does not read:** one that is larger than Stalwart reads, and one
  that is no answer of the milter protocol. Stalwart then defers the mail or
  lets it pass unscanned, as the milter's entry says, and recorded nothing
  the card counted: a scanner that answered so let the card stay in order
  while every message was deferred. Of an answer that is no answer of the
  protocol Garrison keeps the event and its session alone; the text Stalwart
  sends with it is the milter's frame and is dropped before anything is
  stored.
- **Attacks & bans warns of a listener that was full.** A listener that holds
  as many connections as its limit allows closes each further one, a
  legitimate one too. The page names the listener and how many connections it
  refused in the period, and the Event history shows each with its address
  under the new category "Limits". See
  [operations](docs/operator/operations.md#troubleshooting).

### Fixed

- A resolver that sends its answer over TCP an octet now and then no longer
  holds a DNS question beyond its three seconds. The wait began anew with
  each octet, so one question of the DNS, blocklist or signature checks could
  take the time of the whole collection run.
- The card "Antivirus configuration" says first what made it a warning.
  Where a directive was set twice, which is a note, and another let mail
  pass, the note came first, and a notification, which carries a card's
  first finding, told of the note alone.
- The TLS check probes a port on every single address Stalwart binds it to.
  A port bound to two addresses, by one listener or by two, was probed on
  the first alone, and the card could be in order whatever the other
  presented. The rows of such a port now say on which address each probe
  was, as `mail.example.com:465 on 192.0.2.10`
  ([tls](docs/operator/checks.md#tls)).
- An account or a domain removed while Stalwart's list is read costs no
  other one. With more than 500 of them the list is read in pages, and one
  removed between two pages moved the later ones up a place, so the page
  that followed left one out: its mailbox was not judged in that run and
  the card said nothing. Each page now begins with the last object read,
  and is asked again from further back where that object is gone.
- A page of Stalwart's accounts that fails takes nothing of the pages
  before it. With more than 500 accounts, a later page answered with an
  error left the card "Mailbox storage" Unknown, and a full mailbox of the
  first page was not warned of. The pages read now stand, the card says how
  many accounts were read and why not the rest, and the card "Management
  API" names the request that failed.
- The card "Management API" names the request Stalwart refused: a key that
  may list the accounts and not read them was told "access denied to
  x:Account/query", the request that had answered. An account removed while
  one page is read is no longer taken for a refusal with the setup's advice;
  it is left out, as it is gone.
- The security model names the keys' permissions as they are: four for the
  broker's key and twelve for the collector's, where it said ten, and it no
  longer names the macro filter's entry, which went with 0.3.0
  ([security](docs/architecture/security.md)).
- The backup check's card says where its report belongs when the collector's
  unit hides the place it lies in, such as `/root` or `/tmp`: it said "no
  report at …; `garrison backup-check` writes it", and writing it there
  again mends nothing
  ([paths the collector cannot see](docs/operator/checks.md#paths-the-collector-cannot-see)).
- A backup check's report on a file system that does not answer, as on a
  hard NFS mount whose server is gone, no longer holds the collection run:
  after eight seconds the card is Unknown and says so, as a receipt's does.
- So do the two antivirus cards for clamav-milter's and clamd's files, the
  signature files and Fangfrisch's database, which an operator may keep on
  such a file system: each card waits eight seconds for its files.
- A command that cannot be started or ended in its time no longer holds
  whoever ran it. Starting a script waits for the file system of its
  interpreter, and ending a command for the kernel to let it go; a
  `version-command` of that kind held the collection run, and the broker's
  commands run the same way. The caller now has its timeout a quarter of a
  second after the command's time
  ([checks](docs/operator/checks.md)).
- A restart of the broker no longer costs a request its answer. A rights
  check or a sign-in that was under way when `garrison stalwart setup
  --rotate` or an upgrade restarted `garrison-broker` got none, and its user
  "Authorization is temporarily unavailable" once. The broker now answers
  the requests under way before it stops and accepts no further one, which
  waits in its socket for the broker that starts
  ([rotating secrets](docs/operator/operations.md#rotating-secrets)).
- A clock that runs ahead no longer empties the event history. The receiver
  removed events older than `ingest.retention_days` by the host's clock, so
  one clean-up at a time a month ahead, as on a host that starts with a
  wrong clock before its time server answers, took every event and left a
  history that read complete. It now removes them by a run time of its own,
  as the collector does for the metric history: the clock's time counts
  again once it is back within ten minutes of that run time, or after the
  receiver has run at it for a day, and the journal says when such a stretch
  begins and ends
  ([operations](docs/operator/operations.md#troubleshooting)).
- A start of the receiver while the clock is ahead no longer leaves a window
  of lost events that reaches to that clock's time. By a clock a month ahead
  the receiver had been away for a month, and for as long the checks that
  count events stayed Unknown. Such a window goes once the clock is back
  within ten minutes of the receiver's run time, and where the receiver was
  away for longer it ends an hour before the time the receiver has run at
  for a day.
- The polkit rule's first lines name `garrison access update` before the
  installer for a change of `[[actions]]`. They named the installer alone,
  after which the rule held a new action and no profile did, so that nobody
  was offered it and nothing said why
  ([access](docs/operator/access.md#when-the-actions-change)).
- With `web.bind_client_ip`, a sign-in from another address no longer ends
  a session whose cookie it brings along. Someone with a copy of that cookie
  and an account of their own could sign the owner out that way; the copy
  alone counted as signed out there already
  ([configuration](docs/operator/configuration.md#web-ingest-collector-broker)).
- A revocation that Stalwart refuses no longer counts as one. Any answer
  but a failure on Stalwart's side was taken for the end of a session's
  token; a refusal (a 4xx) now gets a line in the web service's journal,
  which says that the token serves until it expires. The lines for a
  revocation Stalwart could not take say what happened, in the broker's
  words: it could not be reached or failed on its side, or it refused for
  its rate limit, where both read "did not answer". What a revocation's
  answer cannot tell is in the
  [security model](docs/architecture/security.md#known-limits).
- `garrison restore`, a rollback with `--restore-state` and `garrison
  uninstall --purge` have Stalwart revoke the tokens of the sessions they
  end. They replace or remove the web service's database, which ended every
  session without a revocation, so each token served on until it expired.
  The commands say how many were revoked, and which Stalwart did not take
  ([backup and restore](docs/operator/operations.md#backup-and-restore)).
- Three more cards say first what made them a warning or failed, which is
  what a notification carries: the host's resources named a file that
  could not be read before the memory or disk that ran short, and a job's
  receipt and the backup repository named an age that alone is a warning
  before the failed result or the failed integrity check. A test now holds
  the rule over every card of the host checks, as over the others.
- `garrison stalwart setup` makes a new API key in the account of the key
  it replaces. Run by a second administrator, it made the new keys in that
  one's own account and removed the first one's afterwards: a run that
  stopped in between left a valid key in an account that no key file named
  any more, where no later run found it. Garrison's keys now stay in the
  account that got them first, whoever runs setup, and a full account is
  named as the one it is
  ([operations](docs/operator/operations.md#troubleshooting)).
- The Alerts page shows its largest text with its first paint on a phone
  too. The sentence under the notification card, which comes with the
  status, was larger than the page's introduction, so the page counted as
  drawn only then; the introduction says more now and the card's sentence
  less.
- The tests pass again after 2026-11-28. A test of the services sent the
  receiver an event with a fixed date, and the receiver takes none from
  before what its history keeps, thirty days by default: whoever runs the
  tests of 0.2.0 to 0.3.1 sees that one fail since that day. Nothing of an
  installation is touched by it.

## [0.3.1] - 2026-11-27

### Fixed

- The card "Signature databases" no longer warns for a daily database that
  is the newest ClamAV has published. One that was not updated for 48 hours
  counted as "the updates do not arrive", but ClamAV publishes none on some
  days, as from 2026-11-25 to 27. The card now reads the version in the
  file's own header and asks this host's resolver for the record freshclam
  asks (`current.cvd.clamav.net`): it warns where a newer database is
  published, with both versions, and where that cannot be asked, and says
  which. A database of the last two days is asked about nowhere
  ([clamav](docs/operator/checks.md#clamav)).

## [0.3.0] - 2026-11-27

### Upgrade notes

- An installation that runs the macro filter (a `[milter]` section in
  `garrison.toml`) switches it off **before** the upgrade, with the release
  that is installed: remove `[milter]` from `garrison.toml` and run `garrison
  stalwart setup`, which takes the filter out of Stalwart and stops it. Until
  then this release changes nothing: its installer refuses while the filter
  runs (`install-macro-filter-runs`), and its `check-config` refuses the
  section by name. Otherwise Stalwart would defer all mail for a filter that
  no longer answers
  ([configuration](docs/operator/configuration.md#milter)). Without
  `[milter]`, as an installation is by default, nothing is to do.
- To have documents with macros refused from now on, tell the virus scanner:
  with ClamAV, `AlertOLE2Macros yes` in clamd's configuration
  ([installation](docs/operator/installation.md#10-mail-with-office-macros-optional)).

### Removed

- **The macro filter is gone.** Garrison no longer reads mail: the section
  `[milter]`, the service `garrison-milter.service`, the command `garrison
  milter` and, on new installations, the user `garrison-milter`. A virus
  scanner refuses documents with macros instead (see the upgrade notes).
  Nothing sets the headers `X-Garrison-Macro` and `X-Garrison-Scan` any more.
- With the filter go its states: `install-milter-held`, `-asked`, `-unasked`,
  `-unseen`, `-unloaded`, `-kept` and `-still-asked`; `setup-milter-unseen`,
  `-port-taken`, `-silent` and `-stranded`, and `setup-milters-unreadable`;
  `doctor-milter-answers`, `-silent`, `-when-unreachable`,
  `doctor-milter-entries-several` and `doctor-milter-entry-asked`, `-moved`,
  `-unanswered`, `-missing`, `-off`, `-conditional`, `-before-data`,
  `-dropped` and `-unknown`.

### Changed

- Every release of Stalwart's 1.2 line is supported (1.2.x), where 1.2.0
  alone was: the contract tests run against 1.2.0 and 1.2.1, and against
  each new release of the line when it is published.
- With `macro_document = true` the mail test sends a document that a virus
  scanner reports: a `.docm` with a real macro project that has no module,
  where it sent one that only carried a project's file name. ClamAV 1.0, 1.4
  and 1.5 with `AlertOLE2Macros yes` report it; switch the test on once the
  scanner's milter refuses such mail ([mail-test](docs/operator/checks.md#mail-test)).
- `garrison doctor` still names every milter that Stalwart asks where none
  answers (`doctor-milter-stranded`, `doctor-milter-stranded-unscanned`), as
  a virus scanner's that is down, and now says to start it.
- `garrison stalwart setup` no longer reads Stalwart's milters, and no longer
  stops for one that does not answer. A user without administrator rights is
  told so at the first read Stalwart refuses, of the webhooks
  (`setup-webhooks-unreadable`).

### Fixed

- The collector starts once in every minute, by the clock, at the thirtieth
  second. Its timer counted a minute from the last run and came five seconds
  late or more each time, so the runs lay 65 seconds apart and about one
  minute in thirteen had no run and no samples; what was counted in it was
  stored with the next run. After an installation the first run comes within
  a minute, and `garrison doctor` says until then that none has finished.
- The mail test waits a quarter of a second before each of its sessions. A
  run opens up to eight, and Stalwart takes five connections a second from
  one address as it comes: with `macro_document = true` and a scanner that
  refuses the tests, the harmless messages after them were turned away and
  the card said "not tested: the server closed the session".

## [0.2.1] - 2026-11-25

### Added

- The page [state names](docs/operator/states.md) lists every state a command
  ends with and every line of `garrison doctor`, each with an example of its
  line, for scripts that look for the names.

### Changed

- The documents name what they left out: `backup-check --report`,
  `self-check --receipt`, `upgrade --signature`, `garrison stalwart-switch`,
  every variable of the Ansible role, and that `check-config` only warns
  about a path the collector cannot see in a file other than
  `/etc/garrison/garrison.toml`. The installation guide's tested systems and
  memory figures are those of 2026-11-25.

### Fixed

- The collector's own unit no longer ends it while it rebuilds the status
  database. After an upgrade from 0.1 with a notification channel or a list
  of Spamhaus' Data Query Service configured, the first collection run of
  0.2.0 rebuilds that database so that no freed page keeps a secret, and it
  asked for the copy's owner on the way, which `garrison-collect.service`
  forbids: the run ended with a core dump (`status=31/SYS` in the journal)
  once its snapshot was stored, and the rebuild, which is tried again a day
  later, could not finish. The runs between were not affected. With this
  release the rebuild finishes in the first run a day after the last try. A
  core dump that systemd kept of such a run holds what the collector had in
  memory and is root's alone: `coredumpctl list garrison` shows it.

## [0.2.0] - 2026-11-25

### Upgrade notes

- **This release needs Stalwart 1.2.0: update Stalwart first.** Garrison's
  contract tests run against 1.2.0 alone, so nothing is known of it beside
  Stalwart 1.1.
- **Run `garrison stalwart setup` again after the upgrade, as `garrison
  doctor` says.** Until then the collector's key lacks `sysDomainQuery` and
  `sysAccountQuery`: the DNS records, Blocklists, Reverse names, TLS
  certificates, Mailbox storage and Spam and ham by domain cards stay Unknown
  without a notification, and Attacks & bans shows the connections Stalwart
  refused from a blocked address as "Not recorded yet".
- **`garrison check-config`, and with it the upgrade, refuses more settings
  before anything stops, and names what mends each.** Among them an option
  that its check would not use, such as `disk_path` without the `disk` check,
  a version `pattern` without a group or a receipt's `columns` without `rows`,
  and a blocklist zone or host that is no DNS name. The notes below name the
  others.
- `expect = "idle"` or `max_age_hours` on a `systemd` timer, socket or path
  unit is refused: put them on the service the unit starts, such as
  `backup.service` for `backup.timer`.
- A secret that `garrison.toml` names by its path, such as `token =
  "/etc/garrison/ntfy.token"`, or by a credential name other than the one its
  unit loads, is refused: move the file to `/etc/garrison/credentials/<name>`
  (root, mode 0600) and write `credential:<name>`.
- A check's path that the collector's unit hides from it, such as a `receipt`
  or a `disk_path` under `/home`, or a file in `/tmp`, is refused: keep it
  where the collector sees it, or show it the place read-only with a drop-in,
  as [checks](docs/operator/checks.md#paths-the-collector-cannot-see) shows.
- An `expect_on_infected` or `expect_on_fail` of the `clamav` check that
  clamav-milter does not take is refused: write one of `Accept`, `Reject`,
  `Defer`, `Blackhole` and `Quarantine`, for `expect_on_fail` one of the first
  three, in any case.
- A notification address with a query right after its server, such as
  `https://hooks.example.org?key=…`, on which nothing ever went out, is
  refused: write `https://hooks.example.org/?key=…`.
- An access policy that names an action `garrison.toml` does not have is
  refused, with the action's name: `garrison access update` mends it.
- The installer refuses `/opt/garrison` where a link puts it under `/home`,
  `/root`, `/tmp` or `/var/tmp`, where no service could start: link it
  elsewhere or mount the disk at `/opt/garrison`.
- A zone of Spamhaus' Data Query Service written with its key in `lists`, such
  as `KEY.zen.dq.spamhaus.net`, keeps working, and `check-config`, the
  installer and `garrison doctor` warn of it. Once the upgrade is done, since
  a release before this one refuses `collector.dqs_key`: write the zone
  without the key, `zen.dq.spamhaus.net`, keep the key in
  `/etc/garrison/credentials/spamhaus-dqs-key` (root, mode 0600) and set
  `collector.dqs_key = "credential:spamhaus-dqs-key"`. A zone written without
  its key while that setting is missing is refused.
- **Every play of the Ansible role runs the installer and, where
  `garrison_stalwart_admin` is set, `garrison stalwart setup`; each changes
  nothing where all is as asked.** Stalwart must answer in every play, and
  that administrator must still work.
- After the upgrade, a backup's card with `verify_days` warns until the next
  `garrison backup-check` run with `--verify`, and one with `restore_days`
  until the next with `--restore`.
- `garrison install --rollback` to a release before this one refuses, before
  anything stops, while `ntfy_url` or `webhook_url` is `credential:…`: write
  the address into `garrison.toml` again first.
### Added

- **The key of Spamhaus' Data Query Service has a credential file.** With
  `collector.dqs_key = "credential:spamhaus-dqs-key"` the collector reads the
  key from `/etc/garrison/credentials/spamhaus-dqs-key` and asks a zone
  written without it; the first collection run rebuilds the status database,
  so that no copy of a key an earlier release kept there is left. See
  [checks](docs/operator/checks.md#reputation).
- **Stalwart can count and block each client under its own address.** Behind
  nginx it saw every client at nginx's address, so password guesses at its
  sign-in page went unlimited, or one client's mistakes blocked everyone. The
  installation guide shows how to forward the client's address, and `garrison
  nginx` prints the lines. See
  [installation](docs/operator/installation.md#client-addresses-for-stalwarts-limits).
- **`garrison restore --from DIR` puts back a backup.** It checks the backup
  before anything stops, keeps the state as it is in
  `/var/backups/garrison/pre-restore-*`, puts every database and the access
  policy back with the right owner and mode, and starts the services. See
  [operations](docs/operator/operations.md#backup-and-restore).
- **`on_incomplete` in `[milter]`: what a message gets that the macro filter
  could not scan completely.** `"tag"`, the default, takes it with the header
  `X-Garrison-Scan: unscanned`; `"defer"` has the sending server bring it
  again; `"refuse"` refuses it. See
  [configuration](docs/operator/configuration.md#milter).
- **An ntfy topic's or a webhook's address can be kept in a file of its own.**
  `ntfy_url` and `webhook_url` take `credential:NAME`, read as the tokens are;
  such an address shows on no page, in no journal and not in the status
  database. `garrison doctor` now looks at the channels and fails one that
  cannot send. See
  [configuration](docs/operator/configuration.md#an-address-that-is-a-secret).
- **Attacks & bans and the Sessions page show more of what Stalwart 1.2.0
  reports.** The connections Stalwart refused from an address it blocks, by
  address and network; a sign-in refused for a missing second factor, from an
  address its credential does not allow or after too many in one mail session,
  as a failed sign-in; the /64 that Stalwart blocks with a banned IPv6
  address; and, in a session, refusals such as too many invalid recipients, a
  mail loop or a command out of order.
### Changed

- **What the commands refuse, the outcomes scripts act on and every line of
  `garrison doctor` end with a name in brackets, such as `[install-no-room]`
  or `[doctor-clock-synchronized]`.** The name stays the same across releases
  while the words may change: a script looks for the name.
- **The installer and `garrison stalwart setup` change nothing where they find
  everything as asked, and say so** (`[install-as-installed]`,
  `[setup-as-asked]`), with exit status 0. The installer starts the services
  where `garrison.toml` changed since they started; setup still has Stalwart
  reload its settings; and `garrison upgrade` hands the archive of the release
  that runs to its installer.
- **The installer names the rollback that works.** After an upgrade that
  changes a database schema its last line says `garrison install --rollback
  --restore-state`, and that the data recorded since the upgrade would be
  lost.
- **"Sending accounts" is called "Sending addresses".** The check always
  counted by a message's sender address; nothing is counted differently, and
  the observation keeps the id `senders.accounts`.
- **A card says when its answer is from, not when the collector last ran,**
  and is marked stale once a new answer is three minutes overdue: the pending
  updates and the blocklists are asked every six hours, the release lists once
  a day. See [checks](docs/operator/checks.md).
- **A test message that could not be sent is tried again after an hour,** not
  with the next test a day later; the tests that did happen keep their result
  and their time.
- **A check that fails says which one it is,** by the entry's place in the
  configuration, such as `systemd (providers[3])`: on its card, on the
  Services page and in the collector's journal.
- **Commands refuse what they would have ignored, and say why on standard
  error.** `garrison install`, `uninstall`, `setup`, `upgrade`, `restore`,
  `backup-check` and `detect` refuse `--config`, which none of them follows;
  `notify-test` without root, and `modules --set` without `--yes` where no
  terminal answers, end with 2; `check-config`, the installer, `garrison
  access` and `backup-check` write their refusals to standard error.
- **The web service, the event receiver and the macro filter see no other
  process:** their units set `ProtectProc=invisible` and `ProcSubset=pid`.
- **The README's title is Garrison, and the byline shows relative23's logo.**
### Fixed

- **An upgrade, a rollback or a restore that was interrupted is finished by
  running it again:** the upgrade with its installer or `garrison upgrade` and
  the same archive, the rollback with the command its first line names. A
  release that does not start is stopped, and the answer names `install
  --rollback`.
- **A failed upgrade returns to a release that can read its data.** The
  installer stops every writer first and puts back each database whose schema
  rose; a rollback that fails once the state went back says what went back,
  and a switch back that finds no room for a copy says so and puts nothing
  back.
- **`garrison restore` and `install --rollback --restore-state` check before
  anything stops,** and an installation whose services ran is upgraded only
  with a configuration the new release loads and its access policy in place. A
  restored policy is the broker's to read and never written through a link,
  and a `garrison.toml` put back from a backup's copy is read by the services
  again.
- **The installer and an uninstallation no longer stop or move the macro
  filter while Stalwart still asks it,** which left Stalwart deferring all
  incoming mail; they say that `garrison stalwart setup` takes the filter out
  or moves it.
- **Smaller faults of the installer are gone.** It keeps the rollback release
  under a linked `/opt`, loads the SELinux module again where its last load
  failed, backs up into a folder of its own in every run, says which file it
  could not write, and no longer makes another user's policy file the
  broker's; an uninstallation's test of nginx no longer renames Garrison's
  snippets, and a purge keeps a backup you wrote into `/var/backups/garrison`
  under a name such as `pre-upgrade-before-migration`.
- **`garrison stalwart setup` keeps every service on a secret Stalwart takes,
  wherever a run stops.** Rotating the API keys no longer leaves a time in
  which sign-in fails (a request that is under way while the broker restarts
  is still answered "Authorization is temporarily unavailable" once);
  a stopped run leaves Stalwart no signature key or scrape credential that no
  file holds; and a failed run names the run that mends it and no longer takes
  the receiver down.
- **Setup makes a key where a key file is empty or Stalwart no longer knows
  its key,** replaces the keys a stopped rotation left side by side, gives a
  new secret to a key whose file other users may read, and, run as another
  administrator, keeps or with `--rotate` removes the keys the one before
  made.
- **Setup refuses before it changes anything:** without root, where Stalwart
  refuses the administrator, which it now says, and where an account has no
  room for one more API key, where it names the account's keys.
- **Setup leaves one entry for the macro filter in Stalwart, found by the
  address it asks.** It no longer ends in success while Stalwart asks a milter
  where nothing answers, and no longer moves the filter to a port another
  program holds.
- **`garrison access` follows no link beside the policy and writes none larger
  than the broker reads.** `init` makes the policy's folder, leaves a way in
  where no role of Stalwart's qualifies and works with more than 64 roles; an
  action added to `garrison.toml` later reaches its users; and no command
  waits without a word for a lock.
- **Another `broker.policy` is followed everywhere:** by the installer,
  `garrison doctor` and `uninstall --purge` as by the broker. `check-config`
  and doctor judge the policy as the broker's own reading takes it, and
  `garrison access check` shows what the broker grants.
- **`garrison doctor` fails what it passed before:** an `issuer` that is not
  the name Stalwart gives itself, an access policy the broker may not read or
  that binds nobody, a credential file that holds none where a check reads it,
  an SELinux module or a macro filter entry for another port, and an API key
  Stalwart does not take, which it now tries.
- **`garrison doctor` no longer misreads what it finds.** It judges the
  collector by its last finished run, checks the certificate on the port
  `public_origin` names, tells another application's answer at the issuer and
  a 502 from nginx for what they are, takes no events database it cannot read
  for an empty one, and names what makes each file.
- **`check-config`, an upgrade and `garrison doctor` name the settings that
  the units do not follow,** such as a `credentials_directory` other than the
  one the units load.
- **The backup check reads its report as a receipt is read:** no link is
  followed, and only a plain file counts. A backup's card shows only that
  repository's own integrity check and test restore, two runs that write one
  report take turns, and an interrupted test restore no longer leaves its copy
  of the mail behind.
- **Requests to Garrison are no longer written to nginx's access log.** The
  snippet `garrison.conf` and the server block `garrison nginx` prints say
  `access_log off;`, and the installer reloads nginx; a server block of your
  own may say it too. Earlier lines stay in nginx's logs until they rotate.
- **Garrison works on another port.** The nginx include follows `web.port`,
  the block `garrison nginx` prints listens on the port `public_origin` names,
  a Garrison on a port other than 443 no longer sends requests back to itself,
  and a request to such a port names it.
- **A file, a row or a server that misbehaves no longer stops the collector:**
  a named pipe in place of a file, a file system that does not answer, a mail
  server that sends a line without end, an overlong value or a time that is
  none in a database.
- **A collection run keeps to its time and counts once.** A check that asks
  many times stops when the run's time is up, a slow check no longer costs the
  whole status, and two runs at once or within a minute no longer count events
  twice or erase what the first counted.
- **A clock that jumps costs less data and no order.** One that jumps ahead
  no longer takes the metric history with it; a job, an event or a signature
  database dated ahead of the clock no longer holds back every action or
  passes as fresh; and a session ends when the server ends it, whatever the
  browser's clock says. The event history is still cleaned up by the host's
  clock: see [operations](docs/operator/operations.md#troubleshooting).
- **A notification channel shows only its server.** Its name and its errors no
  longer show an address's path or key, and the Alerts page no longer shows an
  earlier release's record of a failed notification, which could hold a
  webhook's whole address.
- **Notifications no longer lose a return to order or a lasting problem.** The
  channels are in order only once a message went out, their check judges the
  channels configured now, a secret that cannot be used is that channel's
  error, and a notification names what made a card a warning.
- **The Test messages card is in order only where the server refused each test
  twice and then took a harmless message.** A test the server deferred is no
  longer counted as refused, and the results are those of the listener and the
  mailbox configured now.
- **The mail flow, the milter verdicts and the sending addresses count what
  happened.** A milter's own replies are counted apart, and mail a milter
  refused no longer counts as waiting; the lists say what they left out; a
  slow Stalwart or one damaged event no longer costs the counts; and the
  sending addresses' limits apply at once.
- **The ClamAV cards read what clamav-milter reads.** They name the setting
  for a file they do not find, the signature age is that of the database the
  card judges, and signature files that are no longer updated, or are dated
  ahead of the clock, are a warning.
- **A DNS answer counts only for the question it repeats, and is read to its
  last record.** A long answer where the resolver refuses TCP, a name longer
  than DNS takes and a record that could not be read are each named and no
  longer stop the DNS and reputation checks.
- **Only a blocklist's own answer is a listing.** A list that gives no verdict
  keeps the Blocklists card from being OK, a listing names every code the list
  gave, one address's or mail host's unusable answer no longer ends the
  reading, and the check reads again at once after its options change.
- **The TLS and MTA-STS checks judge what senders meet.** A listener bound to
  one address is probed there, the card says where an SMTP listener stopped
  before TLS and names a certificate's fault as what it is, and an MTA-STS
  policy that stops senders is a warning and is read again once its record
  changes.
- **The checks say what they leave out, and take Stalwart's oldest first.**
  The DNS, reputation and TLS checks take the `max_domains` oldest domains and
  count the rest, the mailbox storage card the oldest accounts up to
  `max_accounts`, Spam and ham by domain those of the 20 000 oldest accounts.
- **A card says how Stalwart failed it:** that Stalwart did not answer, that
  it refused the collector's key for its rate limit, or that it did not give
  the key its domains, listeners or accounts, with `garrison stalwart setup`
  where that mends it. An answer Garrison cannot read is no refusal, and the
  collector starts where setup wrote no metrics credential.
- **A kernel update is seen on Debian, Ubuntu and the RHEL family,** and a
  second kernel flavor is none. The updates card warns where the package lists
  are a week old, and its advice for a dnf cache that only root may read mends
  it.
- **Receipts are judged as written.** Every row of a list receipt counts, one
  without an age limit says so, one whose `ok_rows` finds no row to judge is
  no longer in order, and one the card cannot read says why and what mends it,
  without asking to open a folder to every user.
- **The systemd, host and webmail cards say what they do not know.** A
  `systemd` entry may name an alias, and a job's card says that a run is under
  way; the firewall card is Unknown where systemctl gives no state; a command
  the collector ended after 8 seconds is named as one that did not finish; a
  count a file system does not keep is no longer read as 0; and a webmail
  plugin whose bundle cannot be checked is named.
- **Sign-ins are limited for every network.** Networks beyond the 4096 the web
  service counts share one budget, and each IPv4 client keeps its own where
  nginx listens on one socket for both.
- **A session ends when the server ends it, at Stalwart too, and a broken
  setup no longer signs everyone out.** Signing out says when it did not work,
  the sign-in page says when Stalwart did not answer or was busy, and of two
  sign-ins begun in one browser the one begun last completes.
- **The broker tells a refusal from a fault.** A user whose profiles name no
  module the installation offers and an account of a tenant are refused, not
  taken for a broken setup; a fault of the broker's own no longer blocks the
  other maintenance jobs; and both journals say how Stalwart failed a check of
  rights.
- **The API answers every error with its detail, after the caller's rights,**
  and a state a page does not know no longer stops it or reads as OK. Quick
  filter changes no longer end in "Too many concurrent history queries".
- **A page no longer shows old data as current.** After a computer slept,
  while the status stops arriving, with a stale event history or a receiver
  that stores nothing, the cards and lists say so and since when, and Attacks
  & bans says how complete its numbers are.
- **The keyboard keeps its place.** Paging through a list, opening the menu on
  a phone, starting a maintenance action and a button that goes once pressed
  leave the focus where the work is; screen readers announce news, not the
  page; and Ctrl+K opens the page search on a narrow screen too.
- **Tabs follow each other.** A sign-in, a theme or a setting changed in one
  tab reaches the others without undoing what they saved; a page starts in the
  chosen theme and asks for its first answers once; and the Maintenance page
  keeps following a job, and keeps its dialog.
- **Pages show what the server said.** A ban reason the page does not know is
  shown as the server named it, hidden characters in delivery problems and
  findings are shown, a request that fails is said in Garrison's words, and an
  address with a stray "%" no longer leaves the page blank.
- **The "Switch to Garrison WebUI" row shows only when Garrison says so,**
  which needs Garrison and the Stalwart WebUI under one registered domain.
- **The macro filter no longer passes what it could not scan as clean.** A
  message that is too large, an archive that unpacks to more than the filter
  unpacks, or one packed in a way it does not read, gets what `on_incomplete`
  says; mail with large archives, which arrived unmarked before, now carries
  the header.
- **The macro filter answers in time and keeps to its memory, whatever a
  message holds.** It reads base64, quoted-printable and uuencode wherever
  they stand in a message, and finds a document in a zip archive whose headers
  disagree and a VBA project named in lower case; the
  [configuration](docs/operator/configuration.md#milter) names what it does
  not read.
- **The event receiver bounds what it reads, and the history finds what was
  asked.** The lists and details of deliveries and sessions keep to a size, a
  search finds what the events say, an event's own time is believed only where
  it can be true, and one event the history cannot read is no longer the
  request's fault.
- **The Ansible role finishes a play that stopped.** It unpacks a release
  again where a stopped play left it unpacked in part, shows what `garrison
  stalwart setup` said, finds the access policy where `[broker] policy` keeps
  it, and a dry run (`ansible-playbook --check`) runs to its end on a host the
  role set up.

## [0.1.2] - 2026-11-13

### Added

- **The sign-in page is checked all the time.** The new check `sign-in`
  loads Stalwart's sign-in page under the issuer's name every five minutes,
  with every script and style sheet it names, as `garrison doctor` does when
  it is called. A page that does not answer, is not Stalwart's or cannot load
  its files is a failure, and the notifications report it within minutes:
  after a Stalwart release that loads files the proxy does not pass, nobody
  can sign in. The example configuration has the entry; an installation adds
  `[[providers]]` with `type = "sign-in"` to `garrison.toml`.
- **What Garrison needs of the host.** The [installation](docs/operator/installation.md)
  guide names the memory each service held under load and the disk the event
  and metric histories take.
- **Observation ids are documented and kept.** The new page
  [observation ids](docs/operator/observations.md) lists the id of every
  observation the checks report, for scripts that read Garrison's status. A
  release that renames one names it there and here, and for one more release
  the observation carries its old id in `value.aliases`, while notifications
  keep what they remembered under the new id.
- **`garrison detect` finds the host's own firewall units.** Where none of
  firewalld, nftables and ufw runs, it looks for a running unit that loads
  the rules: a known loader such as `netfilter-persistent`, a unit named for a
  firewall, or one that runs `nft -f` or `iptables-restore`. It lists them
  with the services to watch and names them for `firewall_units`.

### Changed

- **The metric history takes a fifth of the space.** It keeps every minute
  of the last eight days, which the 24-hour and 7-day views draw, and one
  value per ten minutes before them, each counting for the minutes it holds,
  so the 30-day and 90-day views show the same. With every check, 90 days
  take about 48 MiB instead of about 250. An existing history is thinned
  within some 80 minutes after the upgrade. Earlier releases cannot write
  the changed table: a rollback to one needs `--restore-state`.
- **The switch rows are off until a user turns them on.** The row to the
  Stalwart WebUI in Garrison's menu and the "Switch to Garrison WebUI" row in
  the Stalwart WebUI start hidden; each user turns them on in the settings.
  A setting a user saved before keeps its value.
- **The logo names only Garrison.** "for Stalwart" stays in the text that
  says what Garrison works with, and is no longer part of the logo.

## [0.1.1] - 2026-11-13

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

[Unreleased]: https://github.com/relative23/garrison/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/relative23/garrison/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/relative23/garrison/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/relative23/garrison/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/relative23/garrison/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/relative23/garrison/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/relative23/garrison/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/relative23/garrison/releases/tag/v0.1.0
