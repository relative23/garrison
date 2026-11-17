# Changelog

Notable changes for operators and users. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Upgrade notes

- A zone of Spamhaus' Data Query Service written with its key in `lists`,
  such as `KEY.zen.dq.spamhaus.net`, keeps working, and `check-config`,
  the installer and `garrison doctor` warn of it: write the zone without
  the key, `zen.dq.spamhaus.net`, keep the key in
  `/etc/garrison/credentials/spamhaus-dqs-key` (root, mode 0600) and set
  `collector.dqs_key = "credential:spamhaus-dqs-key"`. A zone written
  without its key while that setting is missing is refused, and with it the
  upgrade, before anything stops.
- A secret that `garrison.toml` names by its path, such as `token =
  "/etc/garrison/ntfy.token"`, or by a credential name other than the one
  its unit loads, is refused by `garrison check-config` now, and with it
  the upgrade, before anything stops. Move the file to
  `/etc/garrison/credentials/<name>` (root, mode 0600) and write
  `credential:<name>`; check-config names the setting and the name.
- A check's path that the collector's unit hides from it, such as a
  `receipt` or a `disk_path` under `/home`, or a file in `/tmp`, is refused
  by `garrison check-config` now, and with it the upgrade, before anything
  stops. Keep it where the collector sees it, or show it the place
  read-only with a drop-in, as
  [checks](docs/operator/checks.md#paths-the-collector-cannot-see) shows.
- An `expect_on_infected` or `expect_on_fail` of the `clamav` check that
  clamav-milter does not take there is refused by `garrison check-config`
  now, and with it the upgrade, before anything stops. Such a value never
  matched a file, so the card warned of it in every run: write one of
  `Accept`, `Reject`, `Defer`, `Blackhole` and `Quarantine`, for
  `expect_on_fail` one of the first three, in any case.

### Added

- **The key of Spamhaus' Data Query Service has a credential file.** A
  zone of the service holds the subscriber's key in its name, and
  `garrison.toml`, where it stood, is read by every user of the host. With
  `collector.dqs_key = "credential:spamhaus-dqs-key"` the collector reads
  the key from `/etc/garrison/credentials/spamhaus-dqs-key` for each run
  and asks a zone written without it, such as `zen.dq.spamhaus.net`, with
  it; the key goes into the question and nowhere else. The collector's unit
  loads the file, and the installer keeps an empty one, which means none:
  such a zone is then not asked, and the card says why. Earlier releases
  kept the key with the zone's name in the status database, which the group
  `garrison` reads, and SQLite leaves what it frees in place: the first
  collection run of this release names such a zone without its key in every
  row and, once its snapshot is stored, rebuilds the file beside it and puts
  the copy in its place, with the file's owner, mode and SELinux label, so
  that no copy of the key is left in it, and the collector's journal says
  so. The web service reads on meanwhile (measured: 90 days of history in
  some 20 seconds on a disk that writes 2 MB a second, a reader waiting a
  quarter of a second at the most). A rebuild asks systemd for more time
  while it runs, eight minutes at the most; one that does not finish then
  is tried again a day later, one that fails, as on a full disk, in the next
  run. See [checks](docs/operator/checks.md#reputation).
- **Stalwart can count and block each client under its own address.**
  Behind nginx, Stalwart sees every client at nginx's address: on
  Garrison's host that is 127.0.0.1, which Stalwart neither limits nor
  blocks, so password guesses at its sign-in page went unlimited; elsewhere
  one address for all, which one client's 100 mistyped passwords block for
  everyone. The installation guide now shows how to forward the client's
  address: a `map` and an `X-Forwarded-For` line in nginx, Stalwart's
  "Client IP source" setting, its listeners kept out of reach, and an end
  for a block, which Stalwart, as the client IP source, takes only once
  its settings are reloaded. It says what a blocked client sees, at the
  sign-in page and at each of Stalwart's mail listeners, and that
  Garrison's event history then names each client's own address, an IPv6
  client's too, for its failed sign-ins and for Stalwart's blocks. Where
  Stalwart sees nginx under another address, as behind a published port,
  the guide has that address allowed in Stalwart, since the clients nginx
  sees at loopback still count under it and could block it for everyone.
  Garrison names the user's address when it exchanges a sign-in code, but
  not one of loopback, which Stalwart answers with 400. `garrison nginx`
  prints the same `map` and line, as optional ones. See
  [installation](docs/operator/installation.md#client-addresses-for-stalwarts-limits).
- **`garrison restore --from DIR` puts back a backup.** What `garrison
  backup` wrote had no way back but by hand. The command checks the backup
  before anything stops, keeps the state as it is in
  `/var/backups/garrison/pre-restore-*`, puts every database and the access
  policy back with the right owner and mode, and starts the services. See
  [operations](docs/operator/operations.md#backup-and-restore).
- **`on_incomplete` in `[milter]`: what a message gets that the macro filter
  could not scan completely.** `"tag"`, the default, takes it with the header
  `X-Garrison-Scan: unscanned`; `"defer"` has the sending server bring it
  again; `"refuse"` refuses it. See
  [configuration](docs/operator/configuration.md#milter).
- **An ntfy topic's or a webhook's address can be kept in a file of its
  own.** Every user of the host may read `garrison.toml`, and some addresses
  are the secret themselves: an ntfy topic that takes no token, a webhook
  that carries its key in its address. `ntfy_url` and `webhook_url` now also
  take `credential:NAME`, read as the tokens are; the
  collector and the watch load `ntfy-url` and `notify-webhook-url`, and the
  installer keeps an empty file for each. Such an address never shows on the
  Alerts page, in the journal or in `garrison notify-test`, and the status
  database, which the group `garrison` reads, keeps only the file's name for
  the watch. `garrison doctor` now looks at the channels: it fails on one
  that cannot send and warns of a topic or a webhook that takes no token
  while its address is written in `garrison.toml`. A release before this
  one does not load such a setting, so `garrison install --rollback`
  refuses, before anything stops, until the address is written into
  `garrison.toml` again. See
  [configuration](docs/operator/configuration.md#an-address-that-is-a-secret).

### Changed

- **The installer names the rollback that works.** After an upgrade that
  changes a database schema, as from 0.1.1 to 0.1.2, its last line says
  `garrison install --rollback --restore-state` and that the data recorded
  since the upgrade would be lost. Before, it named the plain rollback, which
  then refused and only named `--restore-state` when it was run.
- **"Sending accounts" is called "Sending addresses".** The check counts by
  the sender address of a message, since Stalwart's event for mail that a
  signed-in account hands in names that address and not the account: an
  account that sends under two of its addresses always was two rows, each
  with its own usual volume. The card, its table, its findings, the
  notifications and the documentation now say so. Nothing is counted
  differently, and the observation keeps the id `senders.accounts`.
- **A card says when its answer is from, not when the collector last ran.**
  Some checks ask their source only now and then: the pending updates and
  the blocklists every six hours, the release lists once a day, the sign-in
  page every five minutes, the test messages once in `every_hours`, the
  counts from the event history every ten minutes. Their cards said "Checked
  a minute ago" for an answer hours old, and were marked stale only when the
  collector stopped. They now carry the time the source was asked, and are
  marked stale once a new answer is three minutes overdue. See
  [checks](docs/operator/checks.md).
- **A test message that could not be sent is tried again after an hour.**
  A `mail-test` whose session did not come about, or was turned away before
  the message, stayed "not tested" until the next test, a day later by
  default. That test alone is now sent again after an hour; the tests that
  did happen keep their result and their time, which the table shows for
  each.
- **A check that fails says which one it is.** Where several providers of
  one type are configured, such as two `systemd` or `receipt` entries, a
  failure named only the type: on its card, in the notice on the Services
  page and in the collector's journal. All three now also name the entry's
  place in the configuration, as `garrison check-config` does: `systemd
  (providers[3])`.
- **The web service, the event receiver and the macro filter see no other
  process.** Their units set `ProtectProc=invisible` and `ProcSubset=pid`:
  under `/proc` each sees only its own process, which is all that any of
  them reads there, and neither the host's other processes nor the kernel's
  files beside them. `systemd-analyze security` rates each of the three 1.1
  instead of 1.3.
- **The README's title is Garrison**, as the logo has been since 0.1.2.
  Stalwart is named where the text says what Garrison is for; the Ansible
  role's description says the same.
- **The byline shows relative23's logo.** "by relative23" under the name on
  the large logos, the byline logos and the sign-in page now reads "by" and
  relative23's own logo, the tile and the word, in its colours.

### Fixed

- **The collector starts where setup wrote no metrics credential.** Its
  unit loads `metrics-credential`, and systemd starts no unit whose
  credential file is missing ("Failed to set up credentials",
  `status=243/CREDENTIALS`), while setup writes none where Stalwart's
  exporter is another's: no collection ran at all. The installer now keeps
  an empty file there, as for the notification files, which the collector
  reads as none and setup fills where the exporter is Garrison's. `garrison
  doctor` checks every file the units load, names a missing one with the
  command that makes it, and calls an empty one in order unless the
  configuration reads it.
- **A check that asks many times stops when the run's time is up.** The
  TLS, reputation, sign-in page and test message checks went on asking
  after the run's 70 seconds: five seconds for each listener that did not
  answer, three for each question a resolver let pass, up to twenty for
  each file of the sign-in page and ten for each step of a test message,
  and a server that sent a line now and then held one probe or session for
  as long as it liked. systemd then ended the run, and nothing of it was
  stored. They, and the check of Stalwart's API, now ask only while the run
  has time and say what they left, an endpoint "not checked", a list or a
  file "not asked", a test message "not sent", and are not in order for it.
  A TLS probe has ten seconds in all and a test message's session twenty; a
  reputation reading cut short is asked again after an hour, and a test
  message the run had no time for is sent in the next run. The DNS records
  of a domain, which already stopped asking, said that the resolver gave no
  answer for the records left; they now say "not asked" too, and a domain's
  MTA-STS policy, which was still fetched then, is fetched in the next run.
- **A named pipe in place of a file a check reads no longer holds the
  collection run.** The user that writes the event history or Fangfrisch's
  database could put a named pipe in its place, and root with ClamAV's
  files: opening it waited for a writer, so the run never reached its
  snapshot and systemd ended it, run after run. A reader of a database that
  another user writes, the web service's history queries and root's
  commands among them, now refuses one that is no regular file before
  SQLite opens it, and the checks say "not a regular file" on their cards.
  The Signature databases card also says when Fangfrisch's database cannot
  be read, and is Partial then; it reads Fangfrisch's whole refresh log,
  where it read its first 512 rows.
- **A mail server that sends a line without end no longer stops the
  collector.** The test messages and the mail notifications read each line
  of a reply whole before they looked at its length, so a listener that
  sent data without an end of line filled the collector's memory until
  systemd ended it, and the run with it. A line is now read up to 2 KiB,
  and such a reply is "the server's reply is too long".
- **A test message the server deferred is no longer counted as refused.**
  The mail test took any reply from 400 to 599 to its message for a
  refusal. Where clamd was down and clamav-milter deferred every message,
  as its default `OnFail Defer` has it, or where a milter Stalwart names
  could not be reached, Stalwart answered 451 (measured with Stalwart
  1.1.0), and the Test messages card was in order for a day although
  nothing had been scanned. A temporary reply (4xx) is now "not tested",
  Unknown, and that test is tried again after an hour.
- **The milter verdicts card counts a milter's own replies apart, and
  warns where a milter judged nothing.** It counted a reply of the milter's
  own as deferred, though such a reply refuses a message as well: Garrison's
  macro filter refuses with one, so its refusals showed as deferrals.
  Stalwart's event for it names no code (measured with Stalwart 1.1.0), so
  they now have a column of their own. A milter that deferred every message
  it was shown since yesterday, as clamav-milter does while clamd is down,
  left the card in order; it is now a warning.
- **The test messages' results are those of the listener and the mailbox
  configured.** After a change of `recipient`, `sender`, `host` or `port`,
  the Test messages card showed the results kept for the old ones under the
  new names until each test was due again, a day later by default and up to
  a week. Such a change now sends the tests anew in the next run, as a
  change of `macro_document` already did; results kept by an earlier
  release count as made for the configuration as it is.
- **The sending addresses' limits apply at once.** A change of
  `min_recipients`, `factor`, `burst` or `bounces` reached the card only
  with the next reading of the event history, up to ten minutes later,
  since the reading kept the reasons found with the limits of its time. The
  card now applies the limits configured in each run.
- **The dashboard's signature age is that of the database the card
  judges.** Where an old `daily.cvd` lies beside the `daily.cld` that the
  updates keep current, the Signature databases card judged the newer file
  and the dashboard's "Signature age" showed the older one's, often days.
  Both now take the newer daily database.
- **The antivirus configuration card reads clamav-milter's file as
  clamav-milter does.** A file that set no `OnInfected`, as the sample file
  of the RHEL family's package, one that set it twice or in lower case, and
  one with a value clamav-milter does not take, left the card in order,
  while the milter quarantined (its default), did what the first line said,
  or did not start at all. The card now counts a directive the file does
  not set with clamav-milter's default, Quarantine for an infected message
  and Defer for a failure, takes a value in any case and the first of two
  lines, as clamav-milter 1.4 does, and warns of a value it does not take,
  with which it does not start. The scanner's limits show the first value
  too, every scanner socket is listed, and a file that cannot be read is
  named with why. See [checks](docs/operator/checks.md#clamav).
- **On a phone, the menu takes the keyboard as it opens.** The menu stayed
  hidden while it slid in, so a Tab pressed in that moment passed it by.
  It is now shown as it opens, and hidden only once it has slid out.
- **A tab follows what changes beside it.** The page that says the session
  has ended stayed so after a sign-in in another tab, a sign-out reached the
  other tabs only with their next request, and a change of a user's rights
  reached the menu only with a reload. A tab that signs in, signs out or
  saves its settings now tells the browser's other tabs, which read the
  session again at once: the page that said the session had ended shows the
  new session's page, a sign-out ends every tab's page, and a theme saved in
  one tab is taken by the others. A change of rights reaches the menu with
  the next refresh of the status, within a minute, or at once when a
  request is refused, and a page the profile no longer grants leads to one
  it grants. The session read that brings it costs Stalwart nothing: the
  web service answers it from the check of that refresh.
- **A page starts in the theme chosen in the settings.** A theme chosen
  against the system's, light where the system asks for dark or dark where
  it asks for light, was taken only once a page had its session, so every
  page and every reload showed the other theme first and then changed. The
  web service now sends a signed-in user's pages in that user's theme from
  the first paint. Without a session, and with "Follow the system", pages
  start in the system's theme as before.
- **A list gives no count before it is there.** Event history, Deliveries
  and Sessions said "Showing 0 entries" under a list while it loaded and
  after it failed, as if nothing matched. They now give the count once
  the list has arrived.
- **A page opened in Firefox asks for its data once.** Each page starts
  its first requests while its code loads. The interface then asked for the
  same answers in a way Firefox does not answer from requests already on
  their way, so Firefox sent each of them a second time; Chrome took them.
- **The menu on a phone keeps the keyboard's place.** Escape now closes
  it, and closed by Escape or by its button it leaves the focus on the
  button that opened it; a page chosen in it takes the focus to that
  page's content. Before, the focus went with the menu, out of sight.
- **Start keeps the keyboard's place while a maintenance action starts.**
  The button was disabled while the request was under way, which drops the
  focus, so a start that failed left a keyboard user nowhere in the
  dialog. It now only says that it is busy, and a second press while it
  starts sends nothing.
- **A channel's error no longer shows its whole address.** An answer that
  was no HTTP answer was reported with the address it came from, on the
  Alerts page, in the journal and by `garrison notify-test`; for a webhook
  that carries its key in its address, that was the key. Such an error now
  names the server only.
- **A state that a page does not know no longer stops it or reads as OK.**
  A page opened before an upgrade that brings a new state of a check failed
  on such a state and showed its error instead of its checks, and the
  dashboard counted a module with such a check as OK. The page now shows the
  state as the service names it, in Unknown's colours with a hint to reload
  the page, and the dashboard counts it as Unknown.
- **The API answers every error with its detail, after the caller's
  rights.** A path segment that does not decode and a request body over
  2 MiB were answered by the web framework in plain text, before the
  caller's rights were checked; they now get `{"detail": "..."}` like every
  other refusal, and a stranger gets 401 first. The OpenAPI document,
  `frontend/api/openapi.json`, names for every route the status codes it
  can answer, and the web tests fail on one that a route does not declare.
  Each answer in it now also says what it means, as OpenAPI 3.1 requires
  of every answer: the successful ones said nothing, so a strict reader of
  the document refused it.
- **Rotating the API keys no longer interrupts the checks of users'
  rights.** `garrison stalwart setup --rotate` removed the broker's old key
  in Stalwart as soon as it had written the new one, while the running
  broker held the old one until the command restarted it at its end: for
  that time every check of a signed-in user's rights answered "Garrison is
  not set up to check access rights", the broker's journal logged an error,
  and nobody could sign in. The old keys now go only after the services
  that hold them have restarted with the new ones. If the command stops
  with an error after it made new keys, they are removed all the same, and
  it says to restart the services.
- **`check-config` and the installer say why on standard error.**
  `check-config` printed an access policy it could not use on standard
  output, and the installer printed there what a failed `check-config` had
  said, so a script that looks for the reason on standard error, where the
  installation guide says it is, learned no more than "check-config
  failed". Both now write the reason to standard error.
- **Sign-ins from more networks than the web service counts are limited
  too.** The web service lets each client network (an IPv4 address or an
  IPv6 /64) exchange 10 sign-in codes a minute at Stalwart and counts up to
  4096 networks at once; while all of them had tried within the last minute,
  any further network passed without a limit, and a single IPv6 /48 holds
  65 536 networks. All networks beyond those 4096 now share 10 exchanges a
  minute, so such a flood reaches Stalwart with at most 40 970 a minute, and
  a sign-in it turns away is told so on the sign-in page. While a flood
  lasts, people signing in from a network that has not tried within the
  minute are likely to be turned away; people already signed in stay signed
  in, and a minute after the flood ends sign-in works again. Stalwart's own
  limits count by the address Stalwart sees: where it runs on Garrison's
  host it sees Garrison at 127.0.0.1 and limits none of it; where it sees
  Garrison under another address, as in a container behind a published
  port, it takes 100 unauthenticated requests a minute from that address
  and counts all of Garrison's as one, so 100 failed sign-ins in a minute
  still stop every sign-in, at Stalwart's own page too, until that minute is
  over; people already signed in are not affected
  ([security model](docs/architecture/security.md#known-limits)).
- **Each IPv4 client keeps its own sign-in budget where nginx listens on one
  socket for both.** With `listen [::]:443 ipv6only=off` nginx names an IPv4
  client in IPv6's form, such as `::ffff:192.0.2.7`, and the web service
  took all such clients for one IPv6 network: ten sign-ins a minute from any
  of them used up the budget of all the others. Such an address now counts
  as the IPv4 address it holds. The server block of the installation guide
  and of `garrison nginx` listens on two sockets and was not affected.
- **Quick filter changes no longer end in "Too many concurrent history
  queries".** The web service runs two history queries at a time and refused
  a third at once, and a query kept its turn until it ended even when the
  browser had given up its request for a newer filter: three quick steps
  through the categories of the Event history while a search was set showed
  that error instead of the list. A query whose request goes away now stops,
  also while it waits for the receiver's or the collector's commit, and
  gives its turn to the next, and a further query waits up to two
  seconds for a turn. It is refused only when eight are waiting already, or
  when no turn came within those two seconds.
- **An event the history cannot read is no longer the request's fault.** A
  stored event whose fields could not be read made Event history,
  Deliveries and Sessions answer 400 "Invalid query", as if the filter were
  wrong. They now answer "Internal error", and the web service's journal
  names the event under the request's reference.
- **The macro filter no longer passes what it could not scan as clean.** A
  message larger than `max_message_mib`, an archive that unpacks to more than
  the filter unpacks (16 MiB a file, 64 MiB together), and a zip archive
  packed with bzip2, LZMA, zstd or Deflate64 were answered like a message
  without macros: a document with macros behind four large files of zeros
  passed. Such a message now gets what the new `on_incomplete` says, by
  default the header `X-Garrison-Scan: unscanned`, and the journal names the
  kind of reason. Macros the filter did see are refused or marked as before.
  Mail with large archives, which arrived unmarked before, now carries that
  header.
- **A zip archive whose headers disagree no longer hides a document from the
  macro filter.** An archive says twice how each file is packed and how long
  it is: in the header before the file and in its directory at the end,
  which Office and most other programs go by. The filter took both from the
  header before the file, so a document with macros passed as clean where
  that header called the file stored, or one byte long, and the directory
  said deflated. The filter now tries every file as deflate, whatever the
  header before it says.
- **The macro filter finds a VBA project named in lower case.** An old Word
  or Excel file (`.doc`, `.xls`) keeps its macros under the name
  `_VBA_PROJECT`, and its directory finds a name in any case, as the
  format's specification and Windows do. The filter looked for the name in
  capitals only, so a file that wrote it `_vba_project` passed as clean. It
  now finds it in any case.
- **`garrison doctor` judges the collector by its last finished run.** It
  called the last collection run successful whenever systemd said so of the
  unit, and systemd says "success" also of a unit that has never run. Doctor
  now reads when the collector last finished a run, as the watch does: within
  ten minutes is in order, longer ago is a problem, no run yet a warning,
  and a status database it cannot read is unknown. A last run that failed is
  still named as a warning.
- **The nginx include follows `web.port`.** The include
  `/etc/nginx/snippets/garrison.conf` sent every request to port 8091,
  whatever `web.port` said, so a Garrison on another port got only 502 from
  nginx. The installer now writes it for the configured port, as it already
  did the SELinux module, and reloads nginx when it changes;
  `garrison nginx --snippet` prints it. An installation on another port gets
  it with the next run of the installer.
- **`check-config` names settings that the units do not follow.** A state
  directory other than `/var/lib/garrison/<service>`, a
  `credentials_directory` other than `/etc/garrison/credentials` and a
  `broker.socket` other than `/run/garrison/broker.sock` were taken without
  a word, although the systemd units keep to their own places: a service
  could not write its data, the web service found no broker, or no service
  read the credentials that setup wrote. `check-config` now warns of each,
  with what does not follow it and what to do, and also when nginx's include
  names another port than `web.port`. The settings stay, so that a file that
  names them still loads.
- **A notification secret that cannot be used is that channel's error.** A
  token or password file that other users could read, that was missing, or
  that did not hold what a token holds was read as if it were empty: ntfy
  and the webhook were asked without their token, mail signed in with an
  empty password, and whatever then failed named neither the setting nor the
  file. Only an empty file now means "no token". Any other file that cannot
  be used stops that channel with an error that names the setting and the
  file, never what it holds: the channels' check on the Alerts page is
  Failed with it in every run, and `garrison notify-test` says it, as the
  journal does for a message that did not go out.
  A mail password may now be shorter than 16 characters and hold spaces; an
  empty one is an error, since mail is always submitted signed in.
- **The backup check reads its report as a receipt is read.** The report of
  `garrison backup-check` was read through a link, a list of values counted
  as a report, its size was checked on another look at the file than the
  one that was read, and a pipe at its path kept the collection run waiting.
  The check now reads it as the `receipt` check reads its file: no link is
  followed, only a plain file of at most 256 KiB of valid JSON that is one
  object, judged by the owner and mode of the file that was read. Anything
  else makes it Unknown, also a `path` that names a link. `garrison
  backup-check` reads the report it wrote last the same way, where it had
  read it through a link, whole and from a pipe that kept it waiting: from
  anything but such a file it keeps no last check or restore and says so.
- **A clock that jumps ahead no longer takes the metric history with it.**
  The history keeps `collector.history_days` and every minute of the last
  eight, counted from the time of each collection run: a clock set a year
  ahead removed all of it in one run, and one a few days ahead thinned
  minutes that the 24-hour and 7-day views still draw. The history is now
  cleaned up by the collector's own run time: each step from one run to the
  next of at most ten minutes counts, a longer one, a pause or a jump, does
  not. A run's own time counts again once it is within ten minutes of that,
  as when a clock is put right, or once the collector has run at the new
  time for a day, as after a long downtime; the collector's journal says
  when such a stretch begins and ends. No pattern of pauses, a host that is
  off every night included, stops the clean-up: it lags by the pauses not
  yet counted. Where a clock that ran ahead had carried the thinning past
  the present, it takes up again from the oldest sample, so the minutes
  written since, by this release or an earlier one, are thinned as well.
- **A secret under a name its unit does not load, or named by its path, is
  refused.** systemd hands a service only the credentials its unit loads,
  each under one name, such as `credential:collector-native-key`. A setting
  that named another passed `garrison check-config`, though the service
  never got that file, and `garrison notify-test`, which reads the
  credentials directory as root, even sent with it. A secret named by its
  path the service reads itself, as its own user and in its sandbox:
  `notify-test` and `garrison doctor`, which read it as root, called a file
  usable that the collector could not read, and the other way round.
  `check-config`, and with it the installer, now refuse both and give the
  name to use; `garrison doctor` reports them, and `notify-test` sends
  nothing on a channel whose secret the collector would not have.
- **Setup restarts the services that still hold replaced secrets.** After
  a rotation that stopped with an error once it had made the new keys, the
  old keys are gone, but a plain `garrison stalwart setup` restarted
  neither the receiver nor the broker, which went on with the old
  signature key and API key: no event batch was taken and no rights could
  be checked until someone restarted them. The same happened where setup
  made a key anew because Stalwart no longer had it. Setup now compares
  what each running service was handed with its file and restarts the
  service where they differ.
- **The installer says which file it could not write from the
  configuration.** Where `garrison.toml` was there but did not load, the
  installer left the polkit rule and the switch row's include as they were
  without a word. It now names each with the reason, in the words of the
  command that makes it.
- **What the units do not follow is said during an upgrade and by
  `garrison doctor`.** `check-config` warns of a state directory,
  `credentials_directory` or `broker.socket` that the units do not follow,
  and of an nginx include for another port, but the installer showed what
  check-config said only when it failed, and doctor did not look. The
  installer now passes its warnings on as it starts the services, and
  doctor lists each setting as a warning with what to do.
- **Another `broker.policy` is followed everywhere.** The broker and
  `garrison access` used the policy the setting names, but the installer
  counted an installation as configured only with
  `/etc/garrison/access-policy.json`, so with a policy elsewhere it never
  started the services, and it set the owner and mode of that file alone;
  `garrison doctor` checked that file, and `garrison uninstall --purge` left
  a policy kept elsewhere. The installer and doctor now take the policy
  from where the setting names it, and a purge removes it there with the
  lock and the backups `garrison access` keeps beside it. Both act only on
  a file, as the broker reads only one: a folder or a link the setting
  names stays as it is, and `check-config` refuses it. A policy under
  `/home`, `/root`, `/run/user`, `/tmp`, `/var/tmp` or `/dev`, which the
  broker's unit hides from it, was called valid by `check-config`, which
  reads it as root, while the broker could not read it and nobody could
  sign in; `check-config`, and with it the installer, now refuses it with
  the setting that hides it, and `garrison doctor` names it.
- **`check-config` refuses a check's path that the collector cannot see.**
  The collector's unit hides `/home`, `/root`, `/run/user`, `/tmp`,
  `/var/tmp`, `/dev` and the kernel's own files from the collector, as the
  broker's does from the broker, while `check-config` reads as root: a `receipt` or a `backup-check` report under
  `/home` or in `/tmp`, a ClamAV or Bulwark folder there, a
  `version-command` program there, passed, and the check read nothing, or a
  `disk_path` of `/home` reported the free space of the empty place the
  unit puts there. `check-config`, and with it the installer before an
  upgrade, now refuses such a path, also where a link leads there, with the
  setting that hides it and what to do; another configuration file than
  the one the units read gets the same words as a warning, and `garrison
  doctor` names it. `disk_path = "/tmp"` stays in order: the collector's
  own `/tmp` lies on the same file system. See
  [checks](docs/operator/checks.md#paths-the-collector-cannot-see).
- **The restart card sees a kernel update on the RHEL family.** The
  collector's unit hid `/lib/modules` from the collector
  (`ProtectKernelModules=true`), so host care's restart check found no
  kernel installed: on AlmaLinux, Rocky Linux, CentOS Stream, Fedora,
  Amazon Linux and openSUSE, which write no `/run/reboot-required`, the card
  stayed in order after a kernel update. The unit now lets the collector
  read the installed kernels; loading a module stays out of its reach, as
  it holds no capability and may not make such a call. Where the kernels
  cannot be read, the card says so and is Unknown, never in order.
- **`garrison doctor` names what makes each file.** For a missing access
  policy it said to run `garrison stalwart setup` or the installer, neither
  of which makes one; it now names `garrison access init`, and `garrison
  stalwart setup` for a missing credential. For a credential with the wrong
  owner or mode it named the installer, which leaves credentials as they
  are; it now gives the `chown` and `chmod`. A link or a folder in a file's
  place is called so, with what makes the file once it is removed.
- **`garrison access check` shows what the broker grants.** It listed the
  modules and actions of a user's profiles, also those the installation
  does not offer, and showed a user the broker refuses, because none of
  those modules is offered, as one with access. It now narrows them as the
  broker does and says so where the broker refuses.
- **Two collection runs at once no longer count events twice.** A
  `garrison collect` started by hand beside the timer's run could read
  Stalwart's counters after it and store before it, and the next run
  counted the deliveries, sign-ins and other events between the two
  readings a second time. One run at a time now holds the collector's
  state directory: a run that finds another under way ends at once without
  collecting, says so in its journal and exits as a success.
- **A status database with a time that is none no longer stops every
  collection run.** A counter's reading or a sample at a time no clock
  gives, in a database that was edited by hand or damaged, made each run
  fail before it stored anything. Such a time now counts as no interval.
  A reading of the free disk space kept so made the disk forecast crash in
  every run, or stayed kept while the run's own reading was not; it is now
  left out, and the readings are kept again without it.
  A newest snapshot dated so made the watch over the collector and
  `garrison doctor` stop with an error, or call the collector running; they
  now say that whether it runs is not known, and the watch tells nobody.
  A release GitHub named, kept dated so, made the releases check crash
  until GitHub answered again, or call the running release the newest for
  as long as GitHub gave no answer; while none comes, the card now says
  that GitHub has not answered since an earlier run and is not in order.
- **A time that is none in the event history no longer stops a check or a
  page.** The event receiver's heartbeat at a time no clock gives, in a
  history that was edited by hand or damaged, made the checks that read the
  history crash in every run, each of their cards saying so, or take the
  history for current. They now say that what the receiver recorded about
  itself cannot be read. On the pages of the history such a heartbeat
  called the receiver running or failed the request with a panic; they now
  say that what the history covers is not known. `garrison doctor` said
  that a newest event recorded at such a time arrived a negative number of
  minutes ago, or that there had been none for billions of hours; it now
  says that the newest event is recorded at no time.
- **A maintenance job recorded at a time that is none no longer holds back
  every action.** A job in the broker's audit at a time no clock gives, in
  a database that was edited by hand or damaged, made every action wait for
  it to settle for as long as its record stayed, or failed the request with
  an internal error. Such a job now holds no action back, the newest job at
  a time still does, and the Maintenance page shows its time as Unknown.
- **`garrison doctor` gives the last Stalwart event no age below zero.** It
  said that an event recorded ahead of this host's clock, as after the
  clock went back, arrived a negative number of minutes ago. As of the
  newest status snapshot, it now warns that such an event is recorded so
  many minutes ahead and that when it arrived is not known, and calls one
  a few minutes ahead just arrived. It takes the event stored last, so one
  received since at the clock's time counts again, and no longer reads the
  whole history to find it.
- **A maintenance job dated ahead of the clock no longer holds back every
  action.** After the clock went back, or once a clock that ran ahead was
  put right, the broker's audit holds jobs dated ahead of the clock, and
  every action was refused with "Allow the previous operation to settle
  first", or for its cooldown, until the clock had reached such a job and
  that time had passed: after a clock put back by a day, for a day. When
  such a job ran is not known, so it now holds no action back; the job
  begun last counts, so one begun since at the clock's time holds its 30
  seconds and its action's cooldown as before.
- **A `systemd` entry may name an alias.** systemd answers for an alias,
  such as `sshd.service` where the unit is `ssh.service`, under the name of
  the unit it stands for, and the check looked for the answer under the
  alias: such an entry stayed Unknown, without a reason. Each entry now
  takes the answer that lists it among the unit's names, and its card names
  the unit it stands for ("Alias of"). A unit that
  systemd gives no answer for, and every unit while `systemctl` cannot be
  run, is Unknown and says why.
- **Only a blocklist's own answer is a listing.** Any address a resolver
  gave for a list's question counted as a listing, so a resolver that
  answers names that do not exist with an address of its own, as some
  providers' resolvers do for a search page, put the mail server on every
  list and the blocklists card at Failed. A listing is now an answer within
  127.0.0.0/8, where lists give theirs; another address leaves that list
  without a verdict, and such a resolver leaves the card Unknown. Spamhaus'
  errors also say which one it gave: a mistyped list name, a public
  resolver, or too many questions. The zones of Spamhaus' Data Query
  Service, under `dq.spamhaus.net`, were not taken for Spamhaus', so a key
  it reports as disabled counted as a listing; they are now read by
  Spamhaus' own codes as well. Such a zone holds the subscriber's key as
  its first label, which showed on the card and stood in the status
  database: it is now named without it, `….zen.dq.spamhaus.net`, and a
  reading kept with the key is asked again in the first run.
- **check-config refuses a blocklist that DNS can never ask.** A zone in
  `lists` or `lists_ipv6`, or a name in `hosts`, with a label longer than
  63 octets, or longer than 253 octets as the `reputation` check asks it,
  with the reversed address before a list's zone, was taken, and every
  reading said of it "no verdict: … is no DNS name". `garrison check-config`,
  and with it the installer before an upgrade, now refuses it and names the
  entry and why.
- **A Garrison on a port other than 443 no longer sends requests back to
  itself.** The web service answers only under `public_origin`, port
  included, and the nginx include passed the host name without the port the
  browser asked for (`$host`): with a `public_origin` such as
  `https://garrison.example.org:8443`, every request was redirected to the
  address it came to, without end. The include now passes the host as the
  browser sent it (`$http_host`), which nginx 1.18 to 1.31 do with the port
  over HTTP/1.1 and HTTP/2 (measured); the installer writes it and reloads
  nginx. On 443 nothing changes, and a request under another port of
  Garrison's name now goes to `public_origin` too.
- **A name longer than DNS takes is not asked, and the checks say so.** The
  DNS client refused a label longer than 63 octets, but sent a name longer
  than DNS takes, 253 octets as written, which resolvers answer with an
  error (unbound) or as a name that does not exist (dnsmasq). So the `dns`
  check called such a record of Stalwart's, as a long domain's DKIM record,
  "no answer" or "missing", and a mail host of Stalwart's that long left the
  `reputation` check without its addresses, or without any reading. The
  client now refuses such a name as no DNS name; the `dns` check says so of
  the record, and a needed one is a warning, since no server can publish
  it; the `reputation` check leaves the host out, asks the others and says
  so. An answer that names one is malformed, as no resolver's can be: the
  client read names of up to 255 octets as written from an answer, so a
  reverse name of 254 or 255 octets was taken, and then refused as a
  question.
- **One address's unusable answer no longer ends the reputation reading.**
  A malformed answer, or an error of the resolver, for one address's
  reverse name or for whether that name leads back to it ended the whole
  reading: both cards said "Nothing could be asked: …", and no list was
  asked about any address. Such an answer now counts for that address
  alone: the Reverse names card names the address and why, and is Partial
  where it would be OK, or Unknown where no address could be read; the
  other addresses and every list are asked as before, and the reading is
  asked again after an hour.
- **A mail host's unusable answer no longer ends the reputation reading.**
  A malformed answer, or an error of the resolver such as SERVFAIL or
  REFUSED, for a mail host's IPv4 or IPv6 addresses ended the whole
  reading: both cards said "Nothing could be asked: …", and no list was
  asked about any address. Such an answer now counts for that host alone:
  both cards name the host and why, and are Partial where they would be OK,
  or Unknown where no address could be read; the other hosts, and that
  host's other addresses, are asked as before, and the reading is asked
  again after an hour. A resolver that does not answer at all still ends
  the reading, as the `dns` check stops asking it: each further question
  would wait out its time.
- **A resolver that does not answer reverse names costs one wait.** Where
  the resolver did not answer the reputation check's question for an
  address's reverse name, or for where that name leads, the check asked
  the same of every further address, each question waiting out its three
  seconds, so that twelve addresses could take most of a collection run's
  time and leave the checks after it not run. Once such a question goes
  unanswered, no more of that kind are asked in the reading: the addresses
  after it say so, and the lists are asked as before.
- **What the reputation check read before its resolver went silent
  counts.** Where the resolver stopped answering for a later mail host's
  addresses, the whole reading was dropped: both cards said "Nothing could
  be asked: …", and a listing found for an earlier host's address went
  unreported for at least an hour. What was asked now counts: the cards
  show it and say that not every address or list was asked, and why, and
  the reading is asked again after an hour.
- **A name that is the root reads as `.`.** Where a resolver's answer named
  the root, the name without labels, it read as no name at all: a reverse
  name that is the root gave the Reverse names card "names ; whether that
  leads back to it could not be read:  is no DNS name", and the DNS
  records card showed a null MX as "0 " and an SRV record of a service
  that is not offered as "0 0 0 ". Such a name now reads as `.`, as a zone
  file writes it: the Reverse names card says that the address names the
  root, which is no host's name, a warning, without asking where it
  leads, and the DNS records card shows "0 ." and "0 0 0 .".
- **A DNS answer counts only for the question it repeats.** The `dns` and
  `reputation` checks numbered their questions in order, from the clock or
  counting from one, and took any answer with that number: whoever could
  send this host packets in the resolver's name had only the port to guess,
  and an answer to another question was read as the answer. A question now
  carries a random number, and an answer counts only where it repeats the
  question as asked, its name, type and class; any other is dropped, and the
  wait for the real one goes on within the question's three seconds.
- **The DNS check says when it leaves domains out.** It checks the first
  `max_domains` (20) of Stalwart's domains and left the others out without
  a word. Where Stalwart has more, the card "DNS records" is now Unknown
  and says how many it has. `max_domains` takes at most 100, since every
  run asks all the records of each domain again; with more domains than
  that, the card stays Unknown.
- **The TLS and reputation checks take as many domains as they are told.**
  Without `endpoints` or `hosts` they took the mail hosts of the first 20 of
  Stalwart's domains, whatever the DNS check's `max_domains` said, and said
  nothing of the rest. Both now have `max_domains` of their own, 20 by
  default, and their cards say when Stalwart has more domains.
- **The reputation check says what its own limits leave out.** It asks
  about eight mail hosts and twelve addresses at the most, and asks the
  lists for 30 seconds in all. The hosts and addresses beyond were left out
  without a word, and a list left unasked showed only in its row, so the
  cards were OK for what was not looked at. The cards now name what was
  left out and are Partial where they would be OK, and a reading whose
  lists ran out of time is asked again after an hour.
- **The TLS check says when it leaves endpoints out.** Without endpoints of
  its own it probes Stalwart's listeners under each mail host, 24 at the
  most, and left the others out without a word: the card was OK for what
  it had not probed. It now says how many endpoints there are and is
  Partial where it would be OK.
- **A fault of a server's certificate is named as what it is.** The
  checks and the notifications called every fault of a certificate "not
  valid for this name", with the TLS library's own text after it, or "not
  trusted": an expired certificate read "the certificate is not valid for
  this name: ExpiredContext { time: UnixTime(…), not_after: UnixTime(…) }".
  They now say that it expired and when, that it is not valid yet, that it
  is not from an authority this host trusts, or which names it is for, and
  the TLS card says "certificate expired" or "certificate not valid for this
  name" where it said "certificate not trusted".
- **The sign-in check says when it leaves files out.** It asks for the
  first twelve scripts and style sheets the sign-in page names and left
  the others out without a word, so the card was OK for files it had not
  asked for. It now says how many files the page loads and is Partial
  where it would be OK.
- **The "Switch to Garrison WebUI" row shows only when Garrison says so.**
  The row in the Stalwart WebUI appeared whenever Garrison gave no answer:
  when Garrison could not be reached, answered with an error or the browser
  blocked the question, although the switch rows are off until a user turns
  them on. It now appears only when Garrison answers that the signed-in user
  turned it on. That needs Garrison and the Stalwart WebUI under one
  registered domain, such as `garrison.example.org` and `mail.example.org`:
  across two domains the browser does not send Garrison's session cookie
  with the question, and the row stays away, as it did before for a user
  who was signed in.
- **Pages start in the system's theme, and follow it.** Every page started
  light and turned dark only once its session had arrived, and with "Follow
  the system" a change of the system's theme while a page was open was not
  followed. Pages now start in the system's theme from the first paint and
  follow its changes; a theme chosen in the settings is the first paint's
  as well (see above).
- **Ctrl+K opens the page search on a narrow screen too.** Where the header
  has no room for the search button, on a phone or in a narrow window, the
  shortcut opened the search where it was not drawn: nothing could be seen,
  and the page took no click until Escape was pressed. The search now opens
  at every width.
- **The evidence labels are explained once on a page, not at a tab stop
  each.** Every label beside a check's state, such as Configuration or
  Probe, was a stop for the keyboard that only showed what the label means;
  on a status page they were all the stops it had. The labels are no stops
  now. Each page that shows them explains the kinds it shows once, in "What
  the evidence labels mean" below its checks, which a keyboard, a screen
  reader and a touch screen reach as well; a pointer that rests on a label
  still shows its meaning.
- **Screen readers announce news, not the page.** Every notice was a live
  region, so screen readers announced text that belongs to a page as if it
  had just happened: the coverage of the event history, for one, again each
  minute as its "last received" time changed. Only what reports a change is
  announced now: an error, a failed refresh, a saved setting, the state of a
  started job and the end of a session.
- **Delivery problems and the checks' findings show hidden characters.**
  A receiving server writes its own replies, and a domain's DNS names its
  mail hosts. Delivery problems showed such text as it came, so a character
  that hides or reorders text, such as a right-to-left override, could make
  a reply or a host name read as something else; so did the findings of
  the checks, which may quote what another server sent. Both now show such
  a character as its code point, such as `[U+202E]`, as the event history
  already did.
- **The table of processes and schedules shows all that the check found.**
  Its Details column left out a unit's findings, such as "No run since the
  host started.", its first property, the load state, which is where a
  missing unit file shows, and every property without a value. It now shows
  the findings first, then every property, with Unknown for one without a
  value.
- **A tab follows a sign-in made in another one.** Every tab shares the
  browser's session cookie, but each read its session only once: after a
  sign-in in a second tab the first went on naming the account it had
  started with while it worked with the new session, and every change it
  saved was refused with "Origin or CSRF validation failed". A tab now reads
  the session again whenever it is shown and when a change it saves is
  refused: for another session it shows that session's account and rights,
  and after a sign-out elsewhere the page that says the session has ended.
- **Settings are saved one at a time.** Two quick clicks of the header's
  theme button sent two saves at once: the first answer took the look back
  to the first click's theme while the second was under way, and the server
  kept whichever save it finished last. The Settings page showed nothing
  while it saved, and pressing Save again sent the save again. While a save
  is under way the Settings page now says "Saving…", and both Save and the
  theme button wait for it to end.
- **Back leaves a page the interface led away from.** An address that
  names no page of the profile, such as an old bookmark or a page the
  profile no longer grants, leads to the first page it does grant. That page
  was added after the address, so Back returned to the address and was led
  away again, and no number of Backs got past it. The address is now
  replaced, and Back returns to the page before it.
- **The closed menu on a narrow screen is out of the way.** Where the menu
  folds away, on a phone or in a narrow window, it was only moved out of
  sight while closed: Tab led through every one of its entries before the
  page, and screen readers read them. While closed it is now hidden from
  both, and Tab goes from the header straight to the page.
- **Attacks & bans says how complete its numbers are.** The page asked for
  what the event history covers, which only Event history, Deliveries and
  Sessions could read: a profile with Attacks & bans but none of them got a
  refusal every minute, no banner, and numbers that looked complete. Attacks
  & bans may now read it. Where it cannot be read, every view of the event
  history says that completeness is unknown, with the reason and a retry,
  instead of showing no banner or the one it read before.
- **An address with a stray "%" no longer leaves the page blank.** A link
  to Garrison whose path holds a "%" that starts no escape, such as
  `/admin/logs/%zz` from a link cut short or typed by hand, stopped the
  interface before it showed anything, signed in or not. Such a part of the
  address is now taken as written and handled like any unknown name: an
  unknown page leads to the first page the profile grants, and an unknown
  detail of Deliveries or Sessions shows that page's error.
- **A user whose profiles name no module the installation offers is
  refused.** The broker answered such a user with a grant of no module at
  all, which the web service had to take for a broken answer: the sign-in
  was turned away as HTTP 502, an open session got "The broker returned an
  invalid authorization" on every request and stayed, and no journal named
  the cause. Such a user is now refused like one without a profile: the
  session ends with its token, and the broker's journal says that the
  profiles grant no module this installation offers.
- **A maintenance job no longer blocks the others for a fault of the
  broker's own.** A job the broker could find no thread for, one whose
  record could not be written, or one during which the broker itself
  failed stayed "queued" or "running", and every action was answered
  "Another maintenance operation is in progress" until the broker was
  started anew. Such a job now ends: failed where nothing ran, uncertain
  where that is not known. A job whose start the audit does not take is
  not run, and a result it did not take is written with the next request
  it does take.
- **A job that did not start says why.** "Authorization changed before
  execution" also stood for a Stalwart that did not answer, a sign-in that
  had ended and an access policy that could not be read. Each has its own
  message now.
- **A user who may not speak to the broker takes none of its places.**
  The broker looked at who had connected only after it had given the
  connection one of its sixteen places and a thread, and wrote a line to
  the journal for each. It looks where it accepts the connection, and the
  journal gets the first such connection and every hundredth.
- **A page costs the broker one question.** When a session's rights had to
  be confirmed again, every request of a page asked the broker on its own;
  two such pages took all sixteen places. Requests of one session that
  arrive together now share one question and its answer.
- **The macro filter counts the memory it holds.** The 256 MiB for arriving
  messages counted what was written into their buffers, which held up to
  twice that; the scan decoded every attachment of a message before it
  looked at one, beside a copy of each; and the unit's limit of 1 GiB was
  not set against a `max_message_mib` of 256. The filter counts what the
  buffers hold, decodes and scans one attachment at a time, and takes
  864 MiB at the most, which a test holds against the unit's limit. A
  connection that ends in an error of the filter gives its place back, so
  64 such ends no longer leave a filter that answers nobody, and the
  journal says when the mail server opens more connections than the filter
  takes.
- **The event receiver bounds what it reads at a time.** Every connection
  to its port was read at once, up to 8 MiB each and several times that
  once parsed, in a service that is allowed 256 MiB; a sender that stalled
  kept its connection for ever; and the batch that filled the history
  waited for its answer until a tenth of the history was removed, which
  can take longer than the five seconds Stalwart waits. The receiver reads
  two batches at a time, the others wait before any of their body is read;
  a batch that has not got its turn and arrived whole within ten seconds
  is answered 503 or 408 and counted as refused; and the history's limits
  are kept by the maintenance task, at once when a thousand events have
  arrived or a batch could not be stored.
- **The lists and details of deliveries and sessions keep to a size.** A
  session listed every recipient its commands named, up to 25 600 where a
  delivery lists a hundred, and a delivery every recipient's outcome; a
  page of such sessions or deliveries, and the events of one of them, went
  out however large. A session lists its first hundred recipients, a
  delivery the outcomes of the recipients it lists, and a page or a detail
  ends at 768 kB like the list of events: the page continues on the next,
  the detail says that it shows only the first events.
- **An event's own time is believed only where it can be true.** The event
  history is kept by the time an event says it happened, so one dated years
  ahead outlived retention and both size limits, and enough of them left no
  room for real events. An event dated more than five minutes ahead of the
  receiver's clock, or older than `ingest.retention_days`, is no longer
  stored; it is counted and reported like an event that cannot be read.
- **Searching the events finds what they say.** A search also matched the
  names of the stored fields, so a word such as "domain" found nearly every
  event; it never found a quote or a backslash; and capital letters beyond
  ASCII in the search term were folded where stored ones were not. A search
  now reads the recorded values and the type's name, finds every character
  as it was written, and treats every letter alike in either case, those
  beyond ASCII too: "müller" finds "MÜLLER", "strasse" finds "Straße".
- **The event history finds a rare category without reading everything.**
  Choosing a category with few events, such as Security, walked the whole
  history from its newest event and could run into the two seconds a query
  has. The page is now read through the index by event type, in the same
  time whatever the history's size.
- **Mail a milter refused no longer counts as waiting.** Delivery problems
  listed a message that a milter or a hook had refused among the messages
  waiting for delivery, for seven days. Such a message never reached the
  queue and is not counted there any more.
- **An installation under a linked `/opt` keeps its rollback release.**
  Where `/opt` or `/opt/garrison` is a link to another disk, every upgrade
  removed all releases but the newest, the one to roll back to included; a
  reinstall counted as an upgrade; and `garrison upgrade` refused to run.
  All three now compare releases the same way whatever the path.
- **Notification channels are in order only once a message went out.** The
  Alerts page called the channels in order as soon as they were named.
  Their check is now Unknown until the first notification has gone out;
  `garrison notify-test` shows at once whether a message arrives.
- **A release list that stops answering is said.** While GitHub gave no
  answer, the release checks kept the last release it had named without a
  word. They now say since when no answer came, and after three days "the
  running release is the newest" turns Unknown; a newer release that was
  seen stays a warning.
- **A date from the future is no fresh date.** A receipt, a backup's newest
  snapshot or a backup report dated ahead of the host's clock counted as
  just written, however long that state lasted. More than five minutes
  ahead is now a warning that says a clock is wrong.
- **A receipt without an age limit says so.** Without `max_age_hours` the
  receipt of a job that stopped running long ago stayed in order with
  nothing to show it. Its card now carries a finding that no limit is set;
  set one for every job that runs on a schedule.
- **Signature files that are no longer updated are a warning.** The
  antivirus check called the signature databases in order as soon as one
  file existed, and showed the age of the daily one without judging it. A
  daily database older than 48 hours is now a warning, and files without a
  daily database among them are Unknown.
- **The Maintenance page keeps following a job, and keeps its dialog.** One
  failed look at a started job ended the following for good, and the notice
  stayed at "Queued"; it now looks again, later each time, and says
  meanwhile that the status could not be read. A refresh of the page that
  failed in the background replaced everything with the error, an open
  confirmation dialog included; the page now keeps what it shows and says
  so above it. An error for which the server gives no reason, as a proxy's
  over HTTP/2, no longer shows an empty notice.
- **A receiver that runs but stores nothing no longer looks healthy.** With
  a signature key that no longer matched, a database that was full or could
  not be written, or events that Stalwart had begun to write differently,
  the event receiver kept its heartbeat, Stalwart dropped what it could not
  deliver after an hour, and nothing recorded that events were missing. The
  receiver now keeps since when it stores nothing: the event views say so,
  the checks that count events are Unknown meanwhile, and once a batch is
  stored whole again the time that was lost is a recording gap, with its
  reason. `/health` of the receiver names the time and counts refused
  batches and unreadable events; the journal gets the first refusal and
  every hundredth instead of one line each.
- **Requests to Garrison are no longer written to nginx's access log.**
  The security model said so, but nothing configured it: with the access
  log that most distributions switch on for all of nginx, searched
  addresses and the parameters of the sign-in's answer, which travel in a
  request's address, were logged outside Garrison's retention. The snippet
  `garrison.conf`, which every installation rewrites, and the server block
  `garrison nginx` prints now say `access_log off;`. The installer reloads
  nginx with the new snippet; a server block of your own may say it too.
  Earlier lines stay in nginx's logs until they rotate.
- **Two checks that report the same observation no longer cost every
  snapshot.** Two `http` or `receipt` entries with one `id`, a unit in two
  `systemd` entries, or a `version-command` for Stalwart beside the
  `stalwart` check passed `garrison check-config`, and then every
  collection run ended without storing anything. `check-config`, and with
  it the installer before an upgrade, now refuses such a configuration and
  names both entries by their place. A run that meets a repeated
  observation all the same keeps the first, stores the snapshot and says so
  in the new observation `collector.duplicates`. Two failing checks of one
  type stand in as `collector.<type>` and `collector.<type>.2`.
- **Signing out says when it did not work.** Where the session could not
  be deleted, because the database was busy or could not be written, the
  sign-out still answered "ok" and removed the cookie, while a copy of the
  cookie went on working. It now answers with an error, keeps the cookie
  for another try and revokes the token at Stalwart either way. A session
  that the policy ends, and the one a browser held when it signs in again,
  now have their tokens revoked as well.
- **A second collection run within a minute no longer erases what the
  first one counted.** The charts keep one value a minute, and a run by
  hand (`systemctl start garrison-collect.service`) right after the timer's
  replaced that minute's deliveries, sign-ins and other counts with its
  own, usually zero. The counts of one minute are now added; readings such
  as load or queue length are still replaced by the newer one.
- **A broken setup no longer signs everyone out.** A typo in the access
  policy, a broker key that was rotated or removed, or an answer of
  Stalwart's about rights that Garrison could not use was answered as "not
  authorized": every signed-in user was signed out, nobody could sign in,
  and the cause stood in the broker's journal as an informational line. It
  is now answered as unavailable (503): sessions stay, the page says that
  rights cannot be checked, and the journal names the cause as an error.
  Only what the policy says of a user is a refusal.
- **The broker's journal names Stalwart's rate limit.** Where Stalwart
  refused a check of a user's rights for its limit (HTTP 429), users saw
  "Authorization is temporarily unavailable" and no journal said why. The
  broker now writes "Stalwart refused a check of a user's rights for its
  rate limit", with whether Stalwart refused the broker's key or the user's
  token, at once and then at most once a minute with how many more it
  refused, so that a flood of checks does not fill the journal.
- **Stalwart's rate limit is named wherever it shows.** Where Stalwart
  answered 429, the web service's journal said "Sign-in rejected at token
  exchange (Stalwart unavailable)", the Management API card "Not readable:
  Stalwart unavailable." and a job whose start met the limit "Stalwart did
  not answer", though Stalwart had answered. They now say "token exchange
  (Stalwart's rate limit, HTTP 429)", "Stalwart refused the collector's key
  for its rate limit (HTTP 429)" and "Stalwart refused the check for its
  rate limit (HTTP 429)"; an outage keeps its words.
- **The checks that read Stalwart's domains or accounts say why they could
  not.** The DNS records card said to run `garrison stalwart setup` again
  whenever Stalwart's domains could not be read, also where Stalwart did
  not answer or refused the collector's key for its rate limit, and the
  Blocklists, Reverse names and TLS certificates cards said that Stalwart
  did not give its domains, or its listeners, whatever had happened. The
  Spam and ham by domain card counted all mail under "unknown" where
  Stalwart did not give its accounts, without a word, and was in order.
  Each now says that Stalwart did not answer the collector's request, that
  it refused the collector's key for its rate limit (HTTP 429), both of
  which pass by themselves, or that it did not give the key its domains,
  listeners or accounts, with the advice to run `garrison stalwart setup`
  again, which the Blocklists, Reverse names and Spam and ham by domain
  cards now give as well; that card is Unknown then. The Management API
  card, which said "Not readable: access denied." where Stalwart refused
  the collector's key, gives the same advice now, and it names the calls
  of the check that Stalwart refused, as it refuses every one of them to a
  key made before they were needed, or answered in a form this release
  does not read: then it said nothing, and the cards those calls fill were
  Unknown without a word.
- **Every card that needs the collector's key for Stalwart says where it
  has none, and what makes one.** Without the collector's API key, its
  credential file empty or missing, the DNS records and Management API
  cards said "No API key is configured." and the Blocklists, Reverse names
  and TLS certificates cards that the collector's API key could not be
  read, none of them what makes one, while the mail flow asked Stalwart for
  no accounts, counted all mail it filed under "unknown", and the Spam and
  ham by domain card was in order without a word. Each of these cards now
  says in the same words that the collector has no API key for Stalwart and
  that `garrison stalwart setup` makes one, the TLS certificates card also
  that `endpoints` named for it need none. The Spam and ham by domain card
  is Unknown then; its counts stay, and the other mail-flow cards, which
  need no key, are as before.
- **An answer of Stalwart's that Garrison cannot read is no refusal.** An
  answer in a form this release does not read, as a Stalwart release it
  does not support yet may give after an upgrade (no JSON, an object it
  does not know, more than it reads, without what was asked, or the error
  `unknownMethod` for a method it does not know), was taken for a refusal:
  the broker answered a user 403 for such an answer to UserInfo, which
  ended that user's session, a status of UserInfo other than 401, such as
  404 where the endpoint moved, ended every user's session as if the
  sign-in had expired, and the cards and `garrison access` gave the advice
  to run `garrison stalwart setup` again, which cannot mend it. Such an
  answer now grants nothing and refuses nobody:
  the broker answers 503 "Authorization is temporarily unavailable" and its
  journal names the answer as an error, a job whose start meets one runs
  nothing and says so, and the sign-in page says that access could not be
  checked, with "token exchange (an answer this release does not read)" in
  the web service's journal. The DNS records, TLS certificates, Blocklists,
  Reverse names, Spam and ham by domain, Management API and metrics
  exporter cards, `garrison access` and `garrison stalwart setup` name the
  answer and point to the supported Stalwart releases in the README; the
  TLS certificates card also to naming `endpoints`.
- **The sign-in page says when Stalwart did not answer or was busy.** Where
  Stalwart did not answer a sign-in's code exchange, or turned it away for
  its rate limit, or the user's rights could not be checked just then, the
  sign-in page said "Your account may not have Garrison access, or the
  sign-in expired", and only the journals said what had happened. It now
  says that Stalwart did not answer, that it is busy, or that access could
  not be checked, and when to try again; a code Stalwart refused and a user
  the policy refuses keep their words.
- **The sign-in page asks for an administrator only where access may be
  why.** It put "Ask your administrator if you need access." after every
  reason, also where Stalwart did not answer or was busy, access could not
  be checked just then, too many sign-ins came from one network or from
  many, or the sign-in did not start from the page. The sentence now
  follows a failed sign-in alone.
- **A failed sign-out names the connection only where no answer came.**
  The account page said "Check the connection and try again." also where
  the web service had answered, such as that the session could not be ended
  there. It now says "Try again." where an answer came, and names the
  connection where none did.
- **The broker admits an allowed user from another PID namespace.** The
  broker read its peer's credentials into a type whose PID is never 0,
  while the kernel gives 0 for a peer whose PID the broker's PID namespace
  cannot see, as with the broker or the web service in a container of its
  own, or a unit with `PrivatePIDs=`: reading such a peer was undefined
  behaviour, and it was refused as "an unexpected user" although
  `broker.allowed_peers` named its user. The broker now reads the peer's
  user alone, with a type that takes any PID, and admits an allowed one
  wherever it runs. No unit of Garrison's gives a service a PID namespace
  of its own, so an installation as the guide makes it did not meet this.
- **An answer that arrived counts, also where the server ends TLS without
  its closing notice.** Many servers just close the connection. Garrison
  then threw away what it had read: a notification that ntfy or a webhook
  had taken counted as failed and was sent again every minute, and the
  sign-in check, the MTA-STS policy and the release list could fail without
  a reason. A notification now counts as taken once the receiver's status
  line and headers have arrived with a status from 200 to 299 (ntfy: 200),
  whatever becomes of the rest, also where the answer gives no length, as
  Python's `http.server` behind `ssl` answers: `garrison notify-test` says
  "the test message is out", and the Alerts page no longer calls it lost.
  The checks read the body, so they take an answer that its own length
  calls complete, and still not one without a length.
- **Notifications no longer lose a return to order or a lasting problem.**
  A check that was reported as failed, warned for one run and was then in
  order sent no "in order again"; one that failed and warned by turns was
  never reported at all; and one whose observation was missing from a run,
  as Stalwart's are while its API is away, lost its return. Failed and
  Warning now count together as not in order, a return is reported whenever
  something was reported, and a check that is missing from a run keeps its
  place for up to a day.
- **A slow check no longer costs the whole status.** A resolver that did not
  answer was asked again for every domain, three seconds each, and with
  notification channels that did not answer either a collection run passed
  the two minutes systemd gives it: the run was ended and nothing was
  stored, the quick checks included. A run now keeps its own time. A silent
  resolver is asked once in a run; no check begins after 70 seconds, and
  one that did not begin shows as Unknown with "Not run"; every HTTPS
  request, name lookup included, and every notification has a time for all
  of it; the journal names a check that took ten seconds or more.
- **A failed upgrade returns to a release that can read its data.** A new
  release that changed a database schema and then failed to start, or to
  stay up, left that database behind: the old release started again, the
  installer said so, and its collector could no longer open the status
  database. The installer now stops every writer first, a collection run
  included, puts each database whose schema rose back to its copy from
  before the upgrade (the others keep their data), and counts the old
  release as running only after its own self-check and start. Where the old
  release does not start either, the links stay as the upgrade set them, so
  `garrison install --rollback --restore-state` is the second attempt; the
  installer names it. The macro filter must now stay up after a start like
  the other services, and a backup names the release that wrote it:
  `--restore-state` refuses a state written by a newer release than the one
  it returns to, and removes a database that did not exist at the backup.
- **A stale event history no longer reads as a quiet mail server.** The
  mail-flow summaries and the sending accounts counted whatever the event
  history held and called it in order, also when the event receiver had not
  run for a day. They are now Unknown, with the reason and since when, while
  the receiver has not reported for five minutes or where it lost events
  inside the days they count; numbers that were read stay in view and a
  warning stays a warning. The Stalwart version is Unknown likewise once a
  later start of Stalwart may be missing from the history.
- **A status that stops arriving no longer looks current.** When the status
  could not be refreshed (the broker or the web service away, the network
  down), the dashboard and the status pages kept their last tiles, "OK"
  included, without a word. They now say that the refresh failed and of when
  the status is, and each check turns stale on the page once it is older than
  it may be, without a new answer and whatever the browser's clock says. The
  dashboard also says when there is no status at all or none yet.
- **A list no longer shows another filter's rows after a failed request.**
  When the request for a new search, category or page failed, the event
  history, Deliveries, Sessions, Attacks & bans and Delivery problems kept
  the previous filter's rows under the error, with its link to older pages.
  They now show the error alone; a failed refresh of the same filter still
  keeps its rows.
- **The macro filter answers in time whatever a message holds.** A crafted
  attachment could keep the filter's one scan busy for seconds to minutes (a
  megabyte of zip directory headers took eight seconds), and all other mail
  waited behind it. The scan's work now grows with the size of the message
  alone, whatever its archives' headers claim, and the filter answers within
  20 seconds of a message's end, the wait for its turn included. A message
  whose scan is not done by then gets what `on_incomplete` says.

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

[Unreleased]: https://github.com/relative23/garrison/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/relative23/garrison/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/relative23/garrison/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/relative23/garrison/releases/tag/v0.1.0
