# Changelog

Notable changes for operators and users. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Upgrade notes

- **`garrison check-config`, and with it the upgrade, refuses an option
  that its check would not use.** Such as `disk_path` without the `disk`
  check, a version `pattern` without a group, or a receipt's `columns`
  without `rows`; the message names what mends it.
- `expect = "idle"` or `max_age_hours` on a `systemd` timer, socket or path
  unit is refused by `garrison check-config` now, and with it the upgrade,
  before anything stops. Put them on the service the unit starts, such as
  `backup.service` for `backup.timer`; check-config names it.
- A zone of Spamhaus' Data Query Service written with its key in `lists`,
  such as `KEY.zen.dq.spamhaus.net`, keeps working, and `check-config`,
  the installer and `garrison doctor` warn of it. Once the upgrade is done,
  since a release before this one refuses `collector.dqs_key`: write the
  zone without the key, `zen.dq.spamhaus.net`, keep the key in
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
- A notification address with a query right after its server, such as
  `https://hooks.example.org?key=…`, on which nothing ever went out, is
  refused by `check-config`, and with it the upgrade. Write
  `https://hooks.example.org/?key=…`.
- Run `garrison stalwart setup` again after the upgrade: the collector's key
  needs `sysDomainQuery` and `sysAccountQuery` now, to find the domains and
  accounts the checks read. Until then the DNS records, Blocklists, Reverse
  names and TLS certificates cards say that Stalwart did not give its
  domains, and the Management API card that it refused `x:Account/query`.

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

- **After a computer slept, a page no longer shows its checks as current.**
  A page counted the time it waited with the browser's monotonic clock,
  which stops while a computer sleeps on Linux and macOS (measured in Chrome
  and Firefox), so a page left open overnight showed its last status as
  current, "OK" included, for up to a minute after waking, and a refresh
  that failed then said that checks grown too old were marked stale while
  none was. A page now counts the larger of the browser's two clocks, and
  its checks turn stale within fifteen seconds of waking.
- **A card says how old its check is by the server's clock.** "Checked …
  ago" on every card and "last received …" above the event views compared
  the server's times with the browser's own clock: a browser two hours
  ahead called a fresh check "Checked 2.0 h ago" beside a badge that was
  not stale, and one behind said "Checked in 10 min", or "last received
  just now" of a webhook silent for hours. Both now count on from the age
  the server gives in its answer; the coverage answer of the API carries
  it in the new field `lastBatchAge`.
- **A session ends when the server ends it, whatever the browser's clock
  says.** A page ended its session by comparing the session's end, a time
  of the host's, with the browser's own clock: a browser ahead of the host
  by ten minutes said "Your session has ended" ten minutes early, and one
  ahead by more than a session lasts, 30 minutes by default, ended every
  sign-in at once, while the server kept the session. A page now counts
  down the time the session has left, which the session's answer of the
  API gives in the new field `expiresIn`, and then asks the server, whose
  answer says whether the session has ended.
- **Paging through a list keeps the keyboard's place.** "Older" and
  "Newest" under Event history, Deliveries and Sessions turned disabled
  while the next page loaded and at either end of the list, and a button
  that turns disabled drops the focus to the page, in Chrome and Firefox
  alike: each step from the keyboard left it nowhere. So did Start in a
  maintenance dialog where a refresh of the list changed the phrase it
  waits for. Such buttons now only say that they cannot act, keep the
  focus, and do nothing when pressed.
- **Attacks & bans says when its checks could not be read.** Below its
  summary the page shows what the collector's checks say of the module,
  such as the sending addresses that send unusually much. Where the status
  could not be read, that card was simply missing, as if there was nothing
  to report, and after a refresh that failed the cards stayed without the
  notice the dashboard and the status pages give. The page now says that
  the module's checks could not be read and why, that a refresh failed and
  of when the status is, or that the collector has produced none yet, as
  every page that shows checks does.
- **A write without an answer no longer says what became of it.** Where
  no answer of Garrison's came, as when the connection broke after the
  request went out or nginx answered 502 while the web service restarted,
  the maintenance dialog said "The request could not be sent."
  though the broker may have started the job, the account page said that
  the browser was still signed in though the session may have ended, and
  the settings said they could not be saved though they may have been.
  Each now says that it is not known whether it was done. Start sends the
  same request again and starts no job twice, and the dialog then says
  where an earlier request had started it; a sign-out or a save can simply
  be repeated.
- **A page ends its session when the server refuses it.** When the access
  policy comes to refuse a signed-in user, as when the user's binding is
  removed, the web service ends the session at its next request and
  answers it 403. Where that request was the page's own question for its
  session, as when a tab is shown again or another tab starts, the page
  stayed signed in, its menu and data in view, until a later request was
  refused, up to a minute later. It now says that the session has ended.
- **A document with macros is found however the message wraps it.** The scan
  undid quoted-printable only when the message held one of four byte strings,
  so an Office document written as quoted-printable on a single line, in
  lower-case hexadecimal, or with only some bytes escaped passed as clean;
  base64 a sender broke up with white space or with characters outside its
  alphabet was not read, nor was a uuencoded attachment; and a document
  behind an odd boundary, an unusual `Content-Type` or deep nesting was
  missed. The scan now finds the document without reading the message's
  structure: it undoes quoted-printable over the whole message, decodes the
  base64 of the whole message on each of the four grids a run of symbols can
  sit on (ignoring every byte outside the alphabet, so boundaries, headers
  and junk fall away), and reads a uuencode `begin`/`end` block wherever it
  stands. It reads each encoding as the mail programs do that read it most
  freely: base64 written in padded pieces, quoted-printable around base64,
  uuencode in the characters and `begin` lines such a program takes, and
  the base64 inside Word's XML files. No boundary, nesting depth or header
  is read to decide this, so none of them hides a document. A part that
  declares a transfer encoding the scan cannot decode, a yEnc or BinHex
  block, or a uuencode block begun and not ended, is marked unscanned
  (`on_incomplete`), not passed as clean
  (see [configuration](docs/operator/configuration.md#milter)).
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
- **The ClamAV cards name the setting for a file they do not find.** A
  missing configuration file, or a signature directory without the listed
  files, names its option and `garrison detect --format toml`, which prints
  where this host keeps it.
- **A daily signature database dated ahead of the clock is a warning.** The
  Signature databases card called it current however long updates had
  stopped; it now says that one of the two clocks is wrong.
- **One damaged event in the history no longer stops the mail flow and the
  sending addresses.** Its time or fields of another type made all their
  cards Unknown; such an event is now left out, and the cards say how many
  were.
- **The Test messages card is no longer in order where the server refuses
  every message.** A refusal counts only where the server takes a harmless
  message sent after it, which lands in the test mailbox once a day by
  default.
- **The milter verdicts card counts a milter's own replies apart, and
  warns where a milter judged nothing.** It counted a reply of the milter's
  own as deferred, though such a reply refuses a message as well: Garrison's
  macro filter refuses with one, so its refusals showed as deferrals.
  Stalwart's event for it names no code (measured with Stalwart 1.1.0), so
  they now have a column of their own. Where every message the milters were
  shown since yesterday was deferred, as clamav-milter does while clamd is
  down, the card was in order, also where another milter passed them first;
  it is now a warning.
- **A Stalwart that is slow to give its accounts no longer costs the mail
  flow its counts.** The mail flow opened the event history, whose reading
  has two seconds, and then asked Stalwart for its accounts, which may take
  eight: where the answer took more than two seconds, every card of the
  mail flow was Unknown for ten minutes with "the event history could not
  be read: interrupted", which blamed the history. Stalwart is now asked
  first; the counts stand, and only the card by domain says where the
  domains are not known.
- **The mail flow's lists say what they left out, and its TLS numbers are
  of one week.** Past 50 000 events of a kind in the week, the TLS card set
  the newest 50 000 MAIL FROMs against the newest 50 000 STARTTLS events,
  which reach back to other times, so mail that had TLS counted as mail
  without it and its domains were listed as plain, on a card in order; the
  one word of the cut went to the first card in name order and spoke only
  of the lists. The numbers of incoming mail with and without TLS now count
  all of the week in one query, a card whose list read only the newest
  events says so and is Partial where it would be in order, and a list that
  shows its 20 busiest rows of more says how many there are.
- **Past 200 000 submissions, an address's usual volume is that of the days
  that were read.** The sending addresses check read the newest 200 000
  submissions of its 15 days and divided what it read of the days before by
  every day the history held, so each usual volume was too low and an
  ordinary day could warn, naming the address; the card said only "More
  mail was handed in than is counted here.". The usual volume is now that
  of the whole days before the last one that were read, none is named where
  fewer than three were, the card says how many, and a last day or bounces
  past the limit make it Partial where it would be in order.
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
- **A channel's name and errors show only its server, also for an address
  with its key right after the server**, which put the key on the Alerts
  page and in the journal, even when kept in a file. Such an address is
  now refused, without the key.
- **The Alerts page no longer shows an earlier release's record of a failed
  notification, which could hold a webhook's whole address and key.** The
  first collection run clears it from the status database; renew a key
  that showed there.
- **A notification mail's sender is one mailbox, also where
  `public_origin` is an IPv6 address or names a port.** Its name was not
  quoted, so a mail program could read the From line as a group or find no
  address in it.
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
  that hold them have restarted with the new ones; where Stalwart's limit
  of five API keys an account leaves no room, the broker's goes first, and
  setup restarts the broker as soon as its new key is written. If the
  command stops with an error after it made new keys, they are removed all
  the same, and it says to restart the services.
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
- **An interrupted test restore no longer leaves its copy of the mail
  behind.** `garrison backup-check --restore` restores into a directory of
  its own under `/var/tmp` and removes it, but one stopped on the way, as by
  a reboot, a stopped unit or the kernel's out-of-memory killer, left the
  restored mail there, and each later run made and removed only its own, so
  copies piled up with each interrupted run. A test restore now first
  removes the copies earlier runs left, those of its own making that have
  not changed for an hour and that no run holds, and says so; a link,
  another user's folder or anything else of that name stays as it is. A
  copy that cannot be removed, the run's own included, is named with how to
  remove it, and the command then ends with 1.
- **`garrison access` follows no link beside the policy.** Root runs it,
  and `broker.policy` may name a folder that another user can write to,
  such as a service's state directory. The command opened its lock through
  a link put at `<policy>.lock`, which emptied the file the link named, such
  as `/etc/passwd`, and copied the policy over the file a link at the
  backup's name named and made it root's alone. Every file beside the
  policy is now reached by its name in the policy's folder, never through a
  link: a lock that is a link, another user's file or a second name of
  another file (a hard link) is refused and left as it is, the policy is
  read no further than the broker reads it (64 KiB), a backup takes a name
  that nothing has (`<timestamp>-1` and so on after the time), and
  the new policy is written to a file of its own, made root's and readable
  for the broker's group before it takes the policy's place. Each error
  names the file it is about, where it named none, and says so where the
  command was run without root; a save names the backup it kept.
- **`garrison access init` makes the policy's folder.** Where
  `broker.policy` named a folder that was not made yet, `garrison doctor`
  said to run `garrison access init`, which asked Stalwart for its roles and
  then failed with "No such file or directory (os error 2)". It now makes
  the folder, root's with mode 755 as `/etc/garrison` whatever the umask,
  so that the broker reaches the policy in it; the other commands say that
  the policy is missing and that `init` makes it.
- **`garrison access init` leaves a way in where no role of Stalwart's
  qualifies.** Where Stalwart's default administrator role lacked one of the
  five rights the administrator profile requires, or the administrators had
  a role of their own, `init` wrote nothing, and every other `garrison
  access` command failed for want of a policy, so no command led to one. It
  now writes the default profiles without a binding and ends with 1, and
  says on standard error what the administrator profile requires and, for
  each of Stalwart's default administrator roles, which of those rights it
  lacks, that Stalwart's administrator gives them to the role, and which
  profiles it meets as it is, or why it leaves the role out. `garrison
  access bind-role` says the same of a role it binds to a profile whose
  rights the role lacks, whose users would get nothing of it. Where a policy
  that reads is there, `init --force` keeps it in that case, since a new one
  would bind nobody and sign everyone out, and says what keeps the kept one
  from working.
- **`garrison access init` and `bind-role` work on a Stalwart with more than
  64 roles, and `bind-role` names why a role's rights cannot be evaluated.**
- **A `garrison access` command no longer waits without a word for a lock
  that another process holds.** Where no command runs, remove
  `access-policy.json.lock`, which an earlier release made readable for
  others.
- **No `garrison access` command writes a policy larger than the broker
  reads (64 KiB), which the broker and every command then refused.**
- **An action added after `garrison access init` reaches its users.**
  `init` gives the `administrator` profile every action of `[[actions]]`
  and the `operator` profile those marked `operator = true`, as
  `garrison.toml` has them then, and nothing changed them later: an action
  added afterwards was granted to nobody and missing from the Maintenance
  page, and one taken out left a policy that names it, so that nobody could
  use Garrison and every `garrison access` command and the installer
  refused it. `garrison access update` gives the two profiles the actions
  as `garrison.toml` names them now and takes from every profile those it
  no longer has; role bindings, accounts and denials stay, and the previous
  file is kept. A policy that names an action `garrison.toml` no longer has
  is said so, with `update` as the way out. The broker reads `[[actions]]`
  only when it starts: after `update`, run the installer again or restart
  the broker and the web service, as [access](docs/operator/access.md#when-the-actions-change)
  says, which also says what `init --force` drops and how the policy file
  is written.
- **A backup's card shows only that repository's own integrity check and
  test restore.** After the upgrade, a card that expects them warns until
  the next `garrison backup-check` run with `--verify` or `--restore`.
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
- **A kernel update on Debian and Ubuntu counts as a pending update.** The
  updates card asked apt what `apt-get upgrade` would install, which keeps
  back every update that needs a package not installed yet, as each kernel
  update with a new ABI does, security fixes included, and prints no line
  for it: a host whose only pending security update was its kernel's
  counted none and was in order (measured on Debian 13 and Ubuntu 24.04).
  The card now asks what a full upgrade installs (`apt-get -s
  dist-upgrade`) and counts each installed package it would update, by the
  archive the update comes from, never by the package's name; a package it
  installs new, such as the kernel's image, is part of the update that
  needs it. A host whose apt has fetched no package lists, as a container
  image leaves it, is Unknown and says so, where apt's "0 upgraded" made it
  in order; once the lists are fetched it is asked again within five
  minutes.
- **A second kernel flavor is no kernel update.** The restart card took
  every kernel in `/lib/modules` whose release sorts after the running
  one's for an update of it, so a second flavor of the same release
  installed beside it, Debian's `-cloud-amd64` beside `-amd64`, Ubuntu's
  `-lowlatency` beside `-generic` or AlmaLinux's debug kernel (`+debug`),
  made it call a restart due (names measured on each). It now holds only
  the kernels of the running one's flavor against it; Debian's backports
  kernel, `6.12.95+deb12-cloud-amd64` beside the stock
  `6.1.0-56-cloud-amd64`, still counts as the update it is.
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
- **A value of another kind in the status database no longer stops the
  collector, the watch or the charts.** A value the collector never
  writes, in a status database that was edited by hand or damaged, such as
  text where a time or a counter's reading belongs, bytes where text does,
  or text that is no UTF-8, made every collection run fail before it
  stored its snapshot, the watch over the collector stop with an error and
  tell nobody, the metric history fail every request, or the thinning of
  the history and the clearing of a key of Spamhaus' Data Query Service
  warn in every run without getting on. Each such value now costs only
  itself: a snapshot so dated gives no time, and where no snapshot gives
  one, the watch and `garrison doctor` say that when the collector last
  ran is not known; a counter's reading so stored counts no interval; a
  sample so stored is left out of the history and its thinning, as is one
  that says it holds more minutes than a step of ten; and a value of the
  collector's memory that is no text is said once in its journal and taken
  out.
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
- **A job's expectation on a systemd timer is refused.** `expect = "idle"`
  and `max_age_hours` were taken on a timer, a socket or a path unit. A
  stopped timer is inactive with a successful result (measured), which
  "idle" takes for a job at rest, so a backup schedule that no longer fired
  was in order, and `max_age_hours` did nothing on such a unit. `garrison
  check-config`, and with it the installer before an upgrade, refuses both
  there now and names the service to put them on.
- **A job's card says that a run is under way.** systemd forgets when a
  job's last run ended as soon as it starts the next one (measured), so a
  job with `max_age_hours`, such as a backup, was Unknown with "No run since
  the host started." for as long as it ran. Its card now says since when the
  run is under way and holds that start to the limit. Where systemd
  remembers no run, after a restart of the host or right after the run of a
  job that no timer or other unit refers to, which systemd unloads with what
  it knew of the run (measured), the card says so, where it said that the
  job had not run.
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
- **A resolver's answer is read to its last record.** The DNS client read
  the first 64 records of an answer and left the others without a word, so
  an SPF policy that came after 64 other texts of a domain, such as
  verification tokens, was "missing", a warning, and where the resolver
  changes the order of the records, the card changed from run to run. Every
  record of an answer is read now.
- **The DNS check says when it leaves a domain's records out.** It asks the
  first 60 records Stalwart names for a domain and left the others out
  without a word, so the card was OK for records it never asked, and an MX
  record after the 60th gave the reputation and TLS checks no mail host.
  The card now says how many records Stalwart names and is Partial where it
  would be OK, and every MX record names a mail host.
- **A resolver that gives no answer is said to have given none in its
  time.** Where a question of the `dns` or `reputation` check went
  unanswered, the cards said "the resolver 127.0.0.53:53 did not answer:
  Resource temporarily unavailable (os error 11)", the system's words for
  a wait that ran out. They now say "… did not answer: no answer within
  3 s".
- **A DNS record that could not be read is named, optional as it may be.**
  Where the resolver answered a record's question with an error, such as
  SERVFAIL for a zone whose DNSSEC signatures expired, or with an answer
  that is malformed or cut off, the row said "no answer" and the card "The
  resolver gave no answer for 1 of the needed records.", as for a resolver
  that is silent; and for an optional record, such as a TLSA record or the
  record of an MTA-STS policy, the card stayed OK, so that the TLSA record
  and the policy were not checked without a word. The row now says "not
  read" and why, the card names the records and why, and is Unknown for a
  needed record and Partial for an optional one where it would be OK; where
  the record for an MTA-STS policy could not be read, the card says that
  the policy was not checked.
- **An MTA-STS policy that stops senders is a warning beside what could not
  be checked.** A policy that leaves a mail host out, or that cannot be
  read, made the domain's card a warning only where everything else was in
  order. Beside a needed record that could not be read, or records the
  run's time left unasked, as after a policy taken from within the hour,
  the card stayed Unknown or Partial, which sends no notification. It is a
  warning in either case now.
- **A notification of the TLS certificates or a domain's DNS records card
  names what made it a warning or a failure.**
- **A long DNS answer no longer stops the DNS and reputation checks where
  the resolver refuses TCP.** That record or host is named with why; let the
  resolver answer over TCP on port 53.
- **The DNS, reputation and TLS checks take their first `max_domains`
  domains however many Stalwart has, and count the rest.**
- **The mailbox storage card reads Stalwart's accounts up to `max_accounts`
  and says how many it leaves.** Raise `max_accounts` where it names some.
- **The TLS check probes a listener Stalwart binds to one address on that
  address.**
- **The TLS certificates card says where an SMTP listener stopped before
  TLS**: a closed connection, its greeting, EHLO or STARTTLS.
- **The metrics exporter's card names what writes a scrape credential that
  Stalwart refuses**, `garrison stalwart setup`.
- **A name lookup that failed is named in the system's words** on the
  sign-in and DNS records cards and in notifications, which tell a name
  that does not exist from one that could not be looked up now.
- **The Sign-in page card and `garrison doctor` say what mends the page by
  its cause**: the certificate of the issuer's host, its name, or the proxy.
- **A blocklist that gives no verdict keeps the Blocklists card from being
  OK.** A list that refused this resolver, as Spamhaus refuses public ones,
  answered with an error or did not answer at all, showed only in its row:
  where another list gave a verdict, the card was OK without a finding, also
  where no list judged an address at all, as the IPv6 address that only
  Spamhaus is asked about by default, and the reading was kept for six
  hours. The card now names each list that gave no verdict, the addresses
  and why, and an address no list judged, is Partial where it would be OK,
  and the reading is asked again after an hour. The addresses after a
  list's question that got no usable answer said "the list did not answer
  before", also where it had answered with an error; they now say that the
  list was not asked again and after which address.
- **The reputation check reads again at once after its options change.** It
  used its reading for up to six hours after `resolver`, `hosts`,
  `max_domains`, `lists` or `lists_ipv6` changed, or the resolver
  `/etc/resolv.conf` names: a list taken out still showed, a listing on it
  Failed, one added did not show, and a resolver named because the card
  said that Spamhaus refuses the one before was asked hours later. A
  reading now notes what it was made with, and one made otherwise is made
  again in the next run. A reading an earlier release kept says nothing of
  it, and the first run after the upgrade makes it again.
- **The Blocklists, Reverse names and Spam and ham by domain cards follow
  Stalwart with the next run.** Where Stalwart did not give the collector's
  key the mail hosts or the accounts, as before `garrison stalwart setup`
  gave the key its rights, while it was down or over its rate limit, the
  reading kept that problem for an hour, or ten minutes: the cards still
  said to run setup again, or that Stalwart did not answer, long after it
  was mended. Such a reading is now made again in the
  next run, which asks Stalwart alone, one request a minute while it lasts,
  as one made without the key is once there is one.
- **The DNS and reputation cards name the option that gives them a
  resolver.** Where `/etc/resolv.conf` names no resolver, they said only
  that; they now add "name one with `resolver`".
- **The DNS, TLS, reputation and Spam and ham by domain cards say how
  Stalwart failed a request.** Where Stalwart answered the collector's
  request for its domains, listeners or accounts with HTTP 5xx or 408, or
  with the JMAP error serverFail, the
  cards said "Stalwart did not answer the collector's request", as where it
  could not be reached. They now say that Stalwart did not complete the
  request and how, such as "(Stalwart answered HTTP 503)" or "(Stalwart is
  unavailable)" for a connection it did not take.
- **An MTA-STS policy longer than is read is not judged by its start.** The
  HTTPS client reads 256 KiB of an answer and unpacks a compressed body to
  4 MiB, and left what came after out without a word: a policy whose `mx`
  lines came later was said to leave the mail host out. The client now
  says where it cut, and such a policy counts as one that cannot be read,
  with that reason.
- **A long text on the DNS records card ends in "…".** The table showed
  the first 120 characters of a record, such as a DKIM key, as if they were
  all of it; a longer one now ends in "…" there. The record is held against
  what was found as a whole, as before.
- **A listing names every code the list gave.** A list may answer an
  address with several codes, as Spamhaus' ZEN gives one for each of its
  lists that holds it, such as SBL and XBL; the Blocklists card named only
  the first, so a listing beside it went unnamed, and which one came first
  could change from run to run. Every code is named now, in order.
- **An MTA-STS policy is read again once its record changes.** The DNS
  check keeps a domain's policy for an hour, also where the domain's
  `_mta-sts` record changed in between: a policy mended under a new id, as
  senders take it at once, still showed as before for up to an hour. It is
  read again in the first run that finds another record.
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
- **The installer refuses `/opt/garrison` where a link puts it under `/home`,
  `/root`, `/tmp` or `/var/tmp`**, where no service could start; link it
  elsewhere or mount the disk at `/opt/garrison`.
- **An installation under a linked `/opt` keeps its rollback release.**
  Where `/opt` or `/opt/garrison` is a link to another disk, every upgrade
  removed all releases but the newest, the one to roll back to included; a
  reinstall counted as an upgrade; and `garrison upgrade` refused to run.
  All three now compare releases the same way whatever the path.
- **Notification channels are in order only once a message went out.** The
  Alerts page called the channels in order as soon as they were named.
  Their check is now Unknown until the first notification has gone out;
  `garrison notify-test` shows at once whether a message arrives.
- **The channels' check judges the channels configured now.** A
  notification that a channel did not take kept the check Failed with
  "The last notification did not go out" until another notification went
  out, which on a quiet host may be weeks later, also after that channel was
  taken out of `[notifications]`, and it came back when a channel was named
  again after all had been taken out. What a notification did is now kept
  for each channel by the name the page shows, with the notification's time,
  "The notification of … did not go out: …": a channel taken out, or named
  otherwise, such as at another server, is no longer judged by it, and a
  channel named since the last notification is Unknown, not in order, until
  one has gone out on it. `garrison notify-test` shows whether a message
  goes out now and does not change the check. What a release before this one
  kept names the channels that did not take it, without a time or its words.
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
- **Every row of a list receipt counts.** A receipt that lists results was
  read to its 200th row: a row after it that was not a success left the
  card in order, and for a list kept oldest first the newest date was the
  200th row's, so the card warned that the receipt was old while new runs
  came in, and nothing said that rows were left out. Every row is judged
  now; the table shows the last 200, and the card says how many rows the
  receipt lists where there are more. Where `rows` names a place that
  holds no list, as where a job that failed early wrote no results, the
  card was in order with no row judged; it is Unknown now and says so. A
  row that is no JSON object was dropped without a word, so a failure
  written as a text passed; the card now says how many rows were not read
  and is Partial where it would be in order.
- **A cut on a host card says what it leaves out.** A receipt's text was
  cut at 300 characters with nothing to show that the job wrote more, and
  `ok_when` and `ok_rows` compared the cut text, so a longer value never
  matched; the restart card named the first five packages that need a
  restart and no more. A cut text now ends in "…", conditions compare the
  whole text, and the restart card says how many more packages there are.
- **A receipt the card cannot read says why, and what mends it.** The
  card said "No readable receipt." whatever kept it from reading the file.
  It now tells apart a file that the job has not written at the path, a
  folder on the way that the collector's user may not search, a file it
  may not open, as a job under umask 027 or 077 writes one (mode 0644 mends
  it, as the documentation asks), a link, which is not followed, or no
  plain file, and a file larger than 1024 KiB or no JSON object or list,
  and names what mends each.
- **A receipt that another user swaps for a named pipe no longer holds up
  the collection run.**
- **A receipt whose `ok_rows` finds no row to judge is no longer in
  order.** An empty list of rows is Unknown now, as a missing one is.
- **A receipt in a place the collector's unit hides, such as `/root` or
  `/tmp`, says so instead of asking for a `chmod`.** Let the job write it
  where the collector sees it, as under `/var/lib`.
- **A list receipt read by an entry for an object is Unknown and says how
  to read it, instead of Failed.** A list is read with `rows = []` and
  `row_date`.
- **The disk forecast begins anew where `disk_path` changes, instead of
  mixing the readings of two file systems.**
- **The firewall card is Unknown where systemctl gives no state for its
  units, instead of warning that no firewall runs.**
- **The host card keeps what it read where one of its sources cannot be
  read, such as a `disk_path` that is not there, and names that source.**
- **A version card without a version says why.** It names a command that
  ended with a status or did not finish in 8 seconds, and output in which
  `pattern` finds nothing; only standard output is read.
- **The updates card and the systemd cards name a command that the
  collector ended after 8 seconds as one that did not finish in time.**
- **A count that a file system does not keep is no longer read as 0.**
  btrfs shows no share of free inodes instead of 0.0 %, and a file system
  without a size, such as /proc, is neither judged full nor forecast.
- **A receipt's time is the same instant for every viewer.** A field or
  column of a receipt with `format = "datetime"` went out as the job wrote
  it, and a time written without its offset, such as `2026-11-17T03:00:00`,
  was read in each viewer's own time zone, another instant for each, while
  the receipt's own date refuses such a time. Such a text is now read as
  the receipt's own date is, a time with its offset or a plain date as
  00:00 UTC; any other text is not shown, and the card says which field or
  column. Unix seconds stay as they were.
- **Signature files that are no longer updated are a warning.** The
  antivirus check called the signature databases in order as soon as one
  file existed, and showed the age of the daily one without judging it. A
  daily database older than 48 hours is now a warning, and files without a
  daily database among them are Unknown.
- **A webmail plugin whose bundle cannot be checked is named.** The
  webmail plugins card stayed in order where a plugin's bundle integrity
  was "unknown", as long as no other bundle mismatched: a plugin that
  Bulwark's registry does not list or lists twice, one without a recorded
  SHA-256, and one whose bundle is missing, a link, unreadable or larger
  than 2 MiB, which is what such a check is for. Each is now named with why
  its integrity is not known, and the card is Partial beside a verified
  bundle and Unknown where none could be checked; a mismatch stays a
  failure and is named first. A registry that cannot be read is named with
  why, where the card was Unknown without a word. An entry without `plugins`,
  or with an empty list, checked no bundle and was in order; it is Unknown
  now and says that no plugin is named.
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
- **An empty key file is a missing key, and setup makes one there.**
  `garrison stalwart setup` made the API keys and the webhook's signature
  key only where their file was missing. Where it was there but empty, as
  after a truncation, held a line end alone or something other than a key,
  setup kept it while Stalwart still had that key, said "secret unchanged"
  and stopped with advice about a container bridge network that did not
  apply; an empty signature key it gave Stalwart, which refused it, so that
  setup failed at the webhook every time after. Where the metrics
  credential held a line end alone or no credential, setup called the
  exporter configured, and the collector had no credential. Setup now
  makes a new key, or a new credential where the exporter is Garrison's,
  wherever the file holds none, as where it is missing, removes the key it
  replaces in Stalwart and has the receiver and the broker read the new
  one. Both called an empty key file one of "an invalid format"; they now
  say that it is empty and that `garrison stalwart setup` makes the key,
  as they do for a missing file and one that holds no key. `garrison
  doctor`, which called such a file private and in order, fails it, names
  the service it leaves without a key and the setup that makes one; the
  files that may be empty, such as `metrics-credential`, stay in order.
  The collector's journal said in every run, once a minute, that its key
  was unavailable and Stalwart's observations Unknown, which named neither
  the file nor the fix and was not so of every card. It now says once for
  each reason that the collector has no API key for Stalwart, with the
  file, why and what makes one, that each card that needs the key says
  so when its check next reads Stalwart, and once that it has the key
  again. The Blocklists and Reverse names
  cards kept a reading made without the key for an hour, and the Spam and
  ham by domain card for ten minutes, so that they said that setup was
  needed after setup had made the key; the first run with a key reads them
  again, as it does a reading made without the key of Spamhaus' Data Query
  Service. The Ansible role ran setup only where the broker's key file was
  missing; it now runs it where any of the three key files is missing or
  empty, and a run with every key in place still changes nothing.
- **Setup says that Stalwart refused the administrator.** A wrong
  password, an unknown user or an API key that Stalwart does not know made
  `garrison stalwart setup` end with "x:ApiKey/get: HTTP 401", which named
  neither the administrator nor what to check. It now says that Stalwart
  refused the administrator and to check the user name and the password,
  or the API key; where Stalwart knows the credential but does not take it
  from this host's address (HTTP 403), as for an API key whose networks
  leave this host out, it says that. Setup changes nothing in either case.
  A user without Stalwart's administrator rights got as far as the first
  API key, whose permissions Stalwart does not let it grant, and setup
  named only Stalwart's refusal; it now says to run setup as an
  administrator who holds them.
- **Setup without root stops before it changes anything.** Run without
  `sudo` on an installed host, `garrison stalwart setup` could not read the
  key files in `/etc/garrison/credentials`, which is root's, took them for
  missing, made a new API key in Stalwart and failed to write it with
  "Permission denied (os error 13)": the key stayed valid in Stalwart with
  its secret lost, one more for each such run. Setup now checks, before it
  asks for the administrator, that it can write the credentials folder;
  where it cannot, it stops, names the folder and, without root, says to
  run it as root and exits with 2. An error writing one of its files names
  the file, and a new key whose file cannot be written, as on a full disk,
  is taken out of Stalwart again.
- **Setup gives Stalwart's exporter the credential its file holds.** Where
  a run of `garrison stalwart setup` stopped after Stalwart's exporter took
  a new scrape credential and before its file did, as when the run was
  interrupted or Stalwart's answer was lost, every later run said
  "Prometheus exporter already configured" and left the two apart: Stalwart
  refused the collector's scrape until a `--rotate`. Setup now gives
  Stalwart the file's credential on every run where the exporter is
  Garrison's or off, as it gives the webhook its file's key, and says
  "updated Prometheus exporter (credential unchanged)".
- **Setup makes new keys where Stalwart no longer knows those of the
  files.** Where `/etc/garrison/credentials` was put back from a copy older
  than the last `--rotate`, as after a restore onto a new host, or
  Stalwart's data from an older backup, `garrison stalwart setup` kept the
  files' keys, said "secret unchanged" and stopped at trying them, with
  advice about a container bridge network that did not apply. Stalwart
  answers a key it does not know with HTTP 401 and a key it knows, from an
  address the key does not allow, with 403. Setup now makes a key anew
  where Stalwart answers 401, says "Stalwart did not know the API key in
  FILE; made a new one", removes the key of that description that nobody
  held and has the broker read the new one; the advice about a bridge
  network comes for 403 alone.
- **A plain setup replaces the keys that a stopped rotation left side by
  side.** A `garrison stalwart setup --rotate` interrupted after it made a
  new key, or whose removal of the old keys failed too, left two keys of
  one description in Stalwart. A plain run then updated the first one
  listed, said "secret unchanged" and kept the other valid for good, and
  where the old key was listed first, it gave a new permission or network
  to that key and not to the file's. Stalwart holds at most five API keys
  for the administrator's account, so such keys piled up until a rotation
  could make none ("You have exceeded your quota of 5 API keys."), the next
  run included. Stalwart shows no key's secret, so no run can tell which
  key a file holds: where Stalwart has more than one key of a description,
  a plain run now makes one anew and removes them all, and where the quota
  leaves the new key no room beside the old ones, these go first.
- **A failed `garrison stalwart setup` names the run that mends it.** Where
  Stalwart's limit of five API keys an account made an old key go before
  the new one could be made, it also says what goes without a key until
  then.
- **A `garrison stalwart setup` that fails no longer takes the receiver
  down.** It restarts a service only for a secret it wrote anew, and never
  onto a key file that holds no key.
- **`garrison stalwart setup` gives a key or credential whose file other
  users may read a new secret, in a file that only its owner reads.**
- **Where `garrison setup` fails to connect Stalwart, it names itself as
  the run that mends it,** which takes the steps after that one too.
- **Setup run as another administrator keeps, or with `--rotate`
  removes, the API keys the one before made.** They stayed valid, also
  after a rotation.
- **The metrics exporter's card says what makes the credential it lacks.**
  It said "No scrape credential is configured." where the file was empty,
  held no credential or could not be read, and named neither the file nor
  what fills it, though `garrison doctor` did. It now names the file, why it
  gives no credential, and what fills it, in doctor's words: setup writes it
  while the exporter is Garrison's or off, and for an exporter of another's
  its user name and password go into it as configuration.md says; with
  `collector.metrics_credential` off it says so. The collector's journal, which said in every run
  that the metrics credential was unavailable, says once for each reason why
  there is none, with the same words, and once that there is one again; and
  setup, for an exporter of another's, names the file its user name and
  password go into.
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
- **A restored access policy is the broker's to read, and never written
  through a link.** `garrison restore` and `install --rollback
  --restore-state` wrote the backup's policy through a link that
  `broker.policy` named, into whatever it pointed to, and where no policy
  was there yet they made it root's group's: the broker could not read it
  and did not start, and nobody could sign in. The policy
  now goes back as a file of its own, made new as root's and readable for
  the group `garrison-broker` alone; a link or a folder that the setting
  names stays as it is, with what it points to or holds.
- **`garrison restore` and `install --rollback --restore-state` check
  before anything stops.** Both stopped Garrison and put the state back
  before the configuration was checked: a backup whose access policy grants
  an action that `garrison.toml` no longer has, or a setting that
  `check-config` refuses and that was written since the services started,
  such as a `receipt` under `/home`, left Garrison stopped on the restored
  state, and a rollback's way back failed on the same policy. The release
  that will start now runs its own `check-config` on today's configuration
  with the policy that comes back, before anything stops, and a refusal
  changes nothing.
- **A rollback that fails once the state went back says what went back.**
  `install --rollback --restore-state` that failed after it had put the
  state from before the upgrade back started the release that ran before on
  that state and said only that it runs again; a nearly full disk, which
  nothing checked, stopped it after the first databases. It now checks,
  before anything stops, that each copy fits beside the database it
  replaces, as `garrison restore` does now too, and where it fails all the
  same it names what went back to its copy, as a failed restore does.
- **An installation whose services ran is upgraded only with a configuration
  the new release loads and its access policy in place**, also where
  `broker.policy` lies outside `/etc/garrison`; otherwise nothing changes.
- **An upgrade that was interrupted is finished by running it again**, with
  its installer or `garrison upgrade` and the same archive; a release that
  does not start then is stopped, and the answer names `install --rollback`.
- **A rollback that was interrupted is finished by the command its first
  line names**: the installer of the release it left, with the same options.
- **A restore that was interrupted is finished by running it again**, which
  copies the state as it finds it first; the copy its first run made keeps
  the state from before it.
- **The installer changes nothing where its release runs as installed, and
  says so** with exit status 0: it stops nothing and makes no backup. It
  starts the services where `garrison.toml` changed since they started.
- **`garrison upgrade` with the archive of the release that runs hands it to
  its installer**, which finishes an installation cut short or changes
  nothing; an older archive is refused as before.
- **The installer and an uninstallation no longer stop the macro filter
  while Stalwart may still ask it**, which left Stalwart deferring all
  incoming mail; they say why the filter keeps running and that `garrison
  stalwart setup` takes it out.
- **The installer loads the SELinux module again where its last load
  failed**, where it took the module as loaded and nginx answered 502; its
  warning says how `semodule` ended where it said nothing.
- **An uninstallation's test of nginx no longer renames Garrison's
  snippets**, so a run cut short there no longer leaves nginx unable to
  start, and a dry run changes nothing.
- **The installer no longer makes a policy file of another user the one the
  broker grants by**: it refuses such a file before anything stops and names
  the command that makes it root's.
- **`garrison.toml` put back from the copy in a backup before an upgrade is
  read by the services again**, also where it was moved or copied with its
  mode: the copy keeps the file's mode.
- **A switch back after a failed upgrade that finds no room for a database's
  copy says so and puts nothing back**, where it said that the previous
  release did not start either; it also names what went back and what was
  removed.
- **An installer run right after one that was killed while it backed up no
  longer fails with "backup failed: … disk I/O error".** Each run backs up
  into a folder of its own, also two restores within one second.
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
- **A page whose database is being written says that it passes.** Where
  the event receiver or the collector held its database for longer than
  the two seconds a page waits for it, as the receiver does while it
  removes a tenth of a full event history at its size limit, the event
  history, Deliveries, Sessions, Attacks & bans, Delivery problems, the
  history's coverage, the status and the metric history answered "Internal
  error", and the web service's journal got an error for each request. They
  now say that the query waited too long for another service's write and to
  try again in a moment (503); a read of the status or of the coverage
  stopped by its own time says to try again too. The journal of the service
  whose reader waited says so once a minute at the most, naming the
  database and how many more readers waited since: "A reader of … waited 2 s
  for its writer and gave up".
- **The broker's journal says how Stalwart failed a check of a user's
  rights.** Where Stalwart could not be reached or failed a check on its
  side (a connection it did not answer, HTTP 5xx or 408, a request over its
  five seconds, the JMAP error `serverFail`), users saw "Authorization is
  temporarily unavailable" and nobody could sign in, and no journal said
  why, though the operations guide sends the operator to the broker's. The
  broker now writes "Stalwart did not complete a check of a user's rights",
  with the request that met it, UserInfo or the management API, and how, at
  once and then at most once a minute with how many more failed. A job
  whose start meets it says that Stalwart did not complete the check, where
  it said that Stalwart did not answer, also after an answer of HTTP 500,
  and its line names how. The broker's journal also names a token that
  Stalwart no longer takes, and a job that did not start because its
  rights changed or its sign-in ended.
- **An account of a tenant is refused, not taken for a broken setup.** An
  account that belongs to a tenant, a tenant's administrator's too, was
  answered as if Garrison's own setup were broken: its sign-in page said
  "Your access could not be checked just now. Try again in a few minutes.",
  which no try mends, the broker's journal got an error at every try, and a
  signed-in account moved into a tenant kept its session, with an error for
  each of its requests. Such an account, and a group, is now refused, as one
  without a profile is: its sign-in fails, a session it has ends, and the
  broker's journal names the reason. An account of a type other than a user
  or a group, as a Stalwart release Garrison does not support yet might
  answer, refuses nobody, as any answer this release does not read.
- **An account Stalwart does not have is named for what it is.** Where the
  management API had no account for a subject that UserInfo still named,
  the broker answered that Garrison is not set up to check access rights,
  with an error that named no account. Where the policy binds that subject
  under `subjects` to the account, the line now says "the policy binds
  subject … to account …, which Stalwart does not have", which is the
  setup to mend; otherwise the two answers of Stalwart's do not fit
  together, an answer this release does not read: rights cannot be
  checked, and nobody is signed out for it. An account removed while its
  user is signed in gets 403 from UserInfo first (measured on Stalwart
  1.1.0), so its session keeps that answer until its time ends.
- **A request the broker cannot read is named in both journals.** The
  broker answered such a request 400 without a line, and the web service
  passed that 400 on, also to pages that know no such answer, such as the
  status. The broker now writes "The broker could not read a request (…)"
  at once and then at most once a minute, and the web service answers it
  as an internal error with a reference, where it made the request alone;
  a submission keeps the broker's 400 for what the user typed. A job that
  gets no ID for want of random numbers has an error line too.
- **A broker that gives no answer is worded alike everywhere, and the
  journal says why.** Where the broker gave no answer (stopped, its 16
  places taken, its socket gone), pages said "Authorization is temporarily
  unavailable", but the Maintenance page's requests "The maintenance broker
  is unavailable", which the operations guide did not name, and no journal
  said why. Every page now says "Authorization is temporarily unavailable",
  and the web service's journal says "The broker gave the web service no
  answer it can use" with why and the socket, at once and then at most once
  a minute. A broker that failed inside ("Internal broker error") now shows
  a reference that the web service's journal names, and a grant the web
  service cannot read, or one of another account than the session's, gets a
  line there too, which names both causes of a grant it cannot read: the
  two services read different configurations, as after an action was added
  and only the broker restarted, or run different releases. The web
  service's line for a sign-in the rights check
  rejected names the broker's words: "Sign-in rejected by authorization
  (HTTP 503: Authorization is temporarily unavailable)".
- **A sign-in that Garrison cannot keep ends on the sign-in page.** Where
  the web service could not store a new session (a full disk, an I/O
  error, its database locked beyond five seconds) or had no random numbers
  for a sign-in, the browser was left at `/auth/callback` or `/auth/login`
  with the API's `{"detail":"Internal error"}` and the login cookie kept.
  It now goes back to the sign-in page, which says that a fault of
  Garrison's own ended the sign-in and shows the reference under which the
  web service's journal names the cause, and the login cookie goes.
- **A sign-in refused at its callback says why in the journal.** A
  callback that named another issuer than `deployment.issuer`, as where
  Stalwart names itself under another URL than garrison.toml, or none, or
  that carried no code or one too long, failed every sign-in without a line
  in any journal, though the operations guide sends the operator to the web
  service's. The journal now says "Sign-in rejected at the callback (…)"
  with which, naming the issuer the callback named and the one configured,
  never the code.
- **`garrison doctor` no longer takes an events database it cannot read for
  an empty one.** A history that is damaged, that the receiver's writer held
  for longer than doctor waits, or a folder in the database's place gave "no
  Stalwart event recorded yet" with the advice about the webhook. It now says
  that when the last event arrived is not known, with the database and why,
  as it does for the status database.
- **`garrison doctor` checks the certificate on the port `public_origin`
  names.** It probed port 443 of the name whatever the origin's port, so
  for `https://host:8443` it failed a working installation where nothing,
  or another server with a certificate of its own, answers on 443, or it
  judged that other certificate and never warned that the one on 8443 ends.
  It now probes the origin's port and names it.
- **A request to a port other than its scheme's own names that port.** The
  HTTPS client sent the host name alone in `Host`, so for `public_origin =
  "https://host:8443"` `garrison doctor` said that Garrison answered 308
  instead of its answer to a visitor, as the web service redirects a name
  that is not its own, and failed a working installation with the advice to
  include `garrison.conf`. Every request of the client names such a port
  now, the sign-in check's and the notification channels' among them.
- **`garrison doctor` no longer takes another application's answer at the
  issuer for Stalwart refusing Garrison's sign-in client.** It names what
  answered and says that the issuer's proxy must pass `/api/auth/client` and
  `/api/auth` to Stalwart.
- **`garrison doctor` fails an `issuer` that is not the name Stalwart gives
  itself**, with which every sign-in fails at Garrison's callback, and says
  what to set.
- **`garrison doctor` fails an access policy the broker may not read**, such
  as one root's alone after `chmod 600`, with which nobody can sign in, and
  gives the `chown` and `chmod` that mend it.
- **`garrison doctor` fails an access policy that binds nobody, or that names
  an action garrison.toml no longer has**, and names the `garrison access`
  command that mends it.
- **`garrison doctor` fails `metrics-credential` and `spamhaus-dqs-key` where
  a check reads them and they hold what the collector takes for none**, with
  how to fill them.
- **`garrison doctor` fails an SELinux module loaded for another port than
  `web.port`**, with which nginx answers 502, and names the installer, which
  loads it for the port.
- **`garrison stalwart setup` leaves one entry for the macro filter in
  Stalwart**, also where its note of the entry is lost, and switches that
  entry on again where it was switched off.
- **`garrison doctor` fails a macro filter entry in Stalwart that asks another
  port than `[milter]` names**, as after a change of `port` without setup, with
  which Stalwart defers all incoming mail.
- **`garrison doctor` says that nginx does not reach the web service where it
  answers 502 for Garrison**, and names the service, the include's port and the
  SELinux module instead of the include itself.
- **`garrison stalwart setup` no longer ends in success while Stalwart asks a
  milter on this host where nothing answers, and `garrison doctor` names every
  such entry**, also without setup's note of the macro filter's. Remove one
  that setup cannot tell for the filter's in the Stalwart WebUI.
- **`garrison doctor` judges the access policy exactly as the broker's own
  reading takes it**: one the broker owns is a warning, no longer a failure,
  one it does not take is named with why, and a closed `/etc/garrison` with
  the `chmod` that opens it.
- **`garrison doctor` tries the broker's and the collector's API keys with
  Stalwart**, as their services use them, and fails one Stalwart no longer
  knows, with which nobody can sign in, with the setup that makes a new one.
- **The warning of nginx's include for another port restarts `garrison-web`
  in its way without the installer**, which left nginx answering 502, and
  `garrison doctor`'s line of a 502 says whether anything listens on
  `web.port`.
- **`garrison doctor` reads the port of the SELinux module SELinux has
  loaded**, no longer that of the file the installer writes before it loads
  it, and names the `semodule -i` that repeats a load that failed.
- **`garrison doctor` judges the free space where `/var/backups` will be
  made** on a host that has none yet, as the installer does, where it was
  unknown until the first upgrade.
- **`garrison doctor` no longer calls a web page at `/metrics/prometheus`
  Stalwart's public exporter**, as a webmail answers one for any path: only
  the exporter's own text, or its 401 without a credential, counts.
- **A session that ends by its time ends its token at Stalwart too**, as a
  sign-out does, and a revocation Stalwart did not answer is asked again, so
  no token outlasts its session for the rest of Stalwart's hour.
- **A policy that names an action added to garrison.toml since the broker
  started no longer keeps everyone out**; the broker offers the action once
  the installer runs again. A policy that names one garrison.toml does not
  have is refused by `check-config` and the installer with its name and
  `garrison access update`.
- **Of two sign-ins begun in one browser, as from two tabs, the one begun
  last completes**; the other's return, or one a page made up, no longer
  ends it.
- **After the host's clock went back, the Maintenance page lists the job
  started last first**, a job recorded while it ran ahead leaves the audit
  with the jobs after it, and a session signed in meanwhile ends.
- **The polkit rule's first line names the command that writes it,
  `garrison polkit-rule`**, where it named one that does not exist, and says
  to run the installer again after `[[actions]]` changed.
- **The Ansible role shows what `garrison stalwart setup` said**, also where
  it failed; the Stalwart administrator's credential stays out of the output.
- **The Ansible role unpacks a release again where a play that stopped left
  it unpacked in part.**
- **The Ansible role runs the installer again until it has finished with the
  play's release and configuration**, so that the next play starts Garrison
  where one stopped after the first install or its installer did not finish.
- **The Ansible role runs `garrison stalwart setup` again where setup did
  not finish or `garrison.toml` changed since, and finds the access policy
  where `[broker] policy` keeps it**; where the policy binds no role and no
  account, the play stops and says how to bind one.

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
