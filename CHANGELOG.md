# Changelog

Notable changes for operators and users. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

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
- **The README's title is Garrison**, as the logo has been since 0.1.2.
  Stalwart is named where the text says what Garrison is for; the Ansible
  role's description says the same.
- **The byline shows relative23's logo.** "by relative23" under the name on
  the large logos, the byline logos and the sign-in page now reads "by" and
  relative23's own logo, the tile and the word, in its colours.

### Fixed

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
  else makes it Unknown, also a `path` that names a link.
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
  follow its changes; a theme chosen in the settings takes over as soon as
  the page has its session.
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
  and after a sign-out elsewhere the sign-in page.
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
  as it was written, and treats ASCII letters alike in either case and
  other letters as written.
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
- **An answer that arrived counts, also where the server ends TLS without
  its closing notice.** Many servers just close the connection. Garrison
  then threw away what it had read: a notification that ntfy or a webhook
  had taken counted as failed and was sent again every minute, and the
  sign-in check, the MTA-STS policy and the release list could fail without
  a reason. A complete answer is now taken; one that its own length does
  not call complete still is not.
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
