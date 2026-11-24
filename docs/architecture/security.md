# Security model

## Assets

Stalwart administration (accounts, configuration), mail metadata in the event
history (addresses, IPs, hostnames), the ability to restart host services, the
credentials Garrison holds and, where the macro filter is switched on, each
incoming message while the filter judges it.

## Boundaries and controls

| Boundary | Control |
|---|---|
| Internet → web | nginx TLS on Garrison's own host name, which serves nothing else; `/metrics/` blocked in Stalwart's server blocks; strict CSP without inline code or styles, except the build's own stylesheet in the drawn pages, allowed by its SHA-256 hash, which the web service takes from the page it sends; JSON answers go out gzipped when the browser accepts it, except `/api/session`, which carries the CSRF token (a compressed secret next to text an attacker chose leaks by its length, BREACH); `X-Frame-Options: DENY`; no access log; at most 10 sign-in code exchanges a minute per client network (an IPv4 address, also one that nginx names in IPv6's form, or an IPv6 /64 of the address nginx names; requests it names none for count as one network), for up to 4096 networks within a minute, and 10 a minute together for all networks beyond those, so at most 40 970 a minute in all; a refused callback goes back to the sign-in page, which says to wait a minute, and its code never reaches Stalwart. |
| Browser → API | Session cookie (`__Host-`: this host name only, HttpOnly, SameSite=Lax); writes need the exact Origin and the CSRF token. Every route that serves a module's data names that module, and `/api/status` holds only the observations of the user's modules; the session's own routes (session, preferences, sign-out) need no module, and `/api/switch` says only whether the switch row is on, `false` without a session. History queries run two at a time for at most two seconds each, after the caller's rights are checked; at most eight more wait up to two seconds for a turn and any other gets 429, so no user can make the readers hold off the receiver's and the collector's commits for longer, and a query whose request went away stops at its next step, also while it waits for a writer's commit. |
| Garrison ↔ Stalwart WebUI | Separate host names: `check-config` refuses an origin shared with the issuer or the Stalwart WebUI, and the web service answers another host name or port only with a redirect to its own origin, which nginx's include passes on with the port the browser asked for. Neither interface's scripts can act in the other or read its storage. |
| Web → broker | Unix socket, group `garrison`, mode 0660; the broker accepts only allowed peer UIDs (SO_PEERCRED), whatever the peer's PID, which the kernel gives as 0 for a peer in a PID namespace the broker cannot see. The web service sends the user's token, never an identity, and has Stalwart revoke it when the session ends, by its time too, within a second of the end (a revocation Stalwart does not answer is asked again a minute later): a compromised web service can act only as a user who is signed in at that moment, within that user's rights. The broker serves at most 16 requests at once and closes further connections unanswered (the web service then answers 503, and its journal says why it got no answer, at most once a minute), so a flood of connections cannot use up the tasks its unit allows (`TasksMax=32`) and a maintenance job needs. |
| Broker → host | Unprivileged user; the polkit rule generated from `[[actions]]` says yes only to those unit/verb pairs and leaves every other request of the broker's user to the host's other rules and systemd's default, which asks for an administrator, while the broker runs `systemctl --no-ask-password`. Tests hold the generated rule's text against fixtures (`polkit.rules` in `crates/broker/tests/fixtures` and `crates/garrison/tests/fixtures`), and `scripts/acceptance.sh` runs a configured action through polkit and, as the broker's user, tries another operation on that unit and another unit, both of which polkit refuses. Fixed argument vectors, no shell. |
| Garrison → Stalwart | A registered OAuth client (`stalwart setup`): only its own callback, PKCE, no service such as mail. User tokens carry only `openid`; Stalwart grants them `authenticate` and `authenticateWithAlias`, no management API and no mail, a revocation ends a token and no other, and the refresh token it gives with a sign-in, which the web service does not keep, serves no client (contract test `crates/web/tests/contract.rs`). Broker and collector use separate API keys with Replace permissions (4 and 10 read permissions), usable only from loopback. `stalwart setup` writes with an administrator's credential that it is given for the run and stores nowhere: the webhook, the keys, the exporter, the sign-in client and, where configured, the macro filter's entry among the milters. `garrison doctor`, which root runs, reads that entry with the collector's key and tries both keys from this host, the broker's with the reads of a rights check. |
| Garrison → Stalwart WebUI | Optional: an nginx include adds one script that draws the "Switch to Garrison WebUI" row. Subresource Integrity pins it (a changed file does not run); it reads no page data, tokens or storage. Its one request goes to `/api/switch`, which answers only whether the signed-in user turned the row on and is the only answer the Stalwart WebUI's origin may read; the row is shown only when that answer says so, and a missing, failed or other answer shows none. The session cookie is `SameSite=Lax`, so the browser sends it with that request only where Garrison and the Stalwart WebUI are the same site, under one registered domain such as `garrison.example.org` and `mail.example.org`; across sites Garrison sees no session there and the row stays away. It runs in the Stalwart WebUI's origin, so it stays one small, reviewed file of under a hundred lines of code. |
| Stalwart → ingest | Loopback listener; HMAC-SHA256 signature over the body; size limits; two batches are read at a time, and a batch has ten seconds to get its turn and arrive whole; event-type and field allowlist; raw protocol data, bodies and client-supplied free text are never stored. Of a failed sign-in the address, the listener and Stalwart's verdict are kept; the name that was tried is kept only where Stalwart found an account of that name, since any other name may be a password typed into the wrong field. Of a check of an incoming sender (SPF, DKIM, DMARC, ARC) only the name of the outcome is kept, not the records it looked at. |
| Stalwart → milter | Optional (`[milter]`). Loopback listener under a user of its own that can read the configuration and nothing of Garrison's state; the unit may reach loopback only and has no writable path. A message is held in memory while it is judged and then dropped; the journal gets the kind of finding, never a sender, recipient, subject or file name. Limits on frame size, message size, unpacked size, archive depth and connections at once, and one bound on what the messages of all connections hold together, keep crafted or many large messages from exhausting memory: a message that finds no room is deferred, not passed. A scan's work grows with the size of the message alone, whatever its archives' headers claim, and the filter answers within 20 seconds of a message's end. A message it could not scan completely gets what `on_incomplete` says, never the answer of a clean one. The parsers are fuzzed. Stalwart is told of the filter only once it answers, and the filter moves or stops only after Stalwart has read the change. |
| Local users → files | One system user per service; state directories 0700/0750; credentials via systemd `LoadCredential=`; under `/proc` the web service, the receiver and the macro filter see their own process and nothing else (`ProtectProc=invisible`, `ProcSubset=pid`), since that is all they read there, though its `net/` still lists the host's sockets, as they share the host's network; policy root-owned 0640 for the broker group; backups contain no sessions or credentials. `garrison.toml` is 0644, since the macro filter and the broker read it as users of their own, so it holds no secret: a notification address that is one (an ntfy topic that takes no token, a webhook with its key in the address) is kept in a credential file it names, and the status database, which the group `garrison` reads, keeps only that file's name for the watch; so is the key of Spamhaus' Data Query Service (`collector.dqs_key`), which only the question to the list carries, and the first collection run of this release clears what earlier releases kept of either in the status database, free pages included, as a later run does with an address once it is kept in a file; `garrison doctor` warns of a channel without a token whose address is written in `garrison.toml`, and check-config and doctor of a list that holds its key there. |
| Service users → root commands | `backup`, `self-check`, `restore` and `install --rollback --restore-state` follow no links in the state directories; a database holding anything but tables and indexes is not read; a restored file is created new, owned like its directory and renamed into place; the access policy is created new as root's with the broker's group, never through a link `broker.policy` names. Services read each other's databases the same way. |
| Collector → outside | Only what an operator configured, and nothing about the installation: the `releases` provider asks GitHub's public release list once a day; `[notifications]` sends the title and first finding of a check to the channels named there and to no other: an ntfy topic, a webhook, a mailbox through the named mail server (signed in, with the certificate checked for that name), each over TLS with a secret read as a systemd credential, and an error that names only the server of a channel's address, never the rest of it; the `dns` provider asks this host's resolver for the names Stalwart lists, each question with a random number from a port the system chose, and reads only an answer that carries that number and repeats the question; every length in an answer is checked (fuzz target `dns_answer`), and where a domain publishes an MTA-STS record it fetches that domain's policy file; the `reputation` provider, off in the example configuration, asks the named blocklists about the mail hosts' addresses through this host's resolver, so those lists learn the addresses; the `tls` provider connects to Stalwart's listeners on this host; the `mail-test` provider hands its test messages to the SMTP listener at the configured IP address, loopback by default, and to the one recipient named. |
| Other jobs → status | A receipt counts only when only root (or the collector itself) can change it; otherwise its observation is Unknown. |

## Authorization logic

Stalwart has no API that returns another account's effective permissions, so the
broker evaluates roles itself (inheritance, Merge/Replace, "disabled wins").
Profiles may only require `authenticate` and `sys*` permissions, and
`crates/stalwart/tests/contract.rs` compares exactly those with Stalwart's own
answer (`/api/account`) for several account shapes on every CI run. Two
differences found that way are documented in
`crates/stalwart/src/permissions.rs`.

## Failure behavior

Nothing is granted unless it could be decided, and the answer says which of
two things kept it from being granted.

A refusal (403) is what the policy and Stalwart say of a user: the subject is
on the deny list, has no binding, belongs to an account Garrison evaluates no
rights for (one of a tenant, a tenant's administrator's too, or a group),
lacks the rights its profile requires, or has
profiles that name none of the modules the installation offers. It ends that
user's session, as an invalid token does (401), and the broker's journal
names the reason of each.

Everything else grants nothing and refuses nobody, and is answered 503: a
Stalwart or a broker that is temporarily unavailable, a setup of Garrison's
own that is broken, and an answer of Stalwart's in a form this release does
not read. The setup is a policy that does not read, is not protected,
names an action the configuration does not have or binds a subject to an
account Stalwart does not have; a broker key that is
missing or that Stalwart no longer takes; and an answer about an account's
rights that cannot be used. An answer this release does not read is one
without JSON, with an object or a status it does not know (an account of a
type other than a user or a group too, or no account for a subject that
UserInfo named), larger than it
reads or without what was asked, or an error of a method other than
`forbidden`, such as `unknownMethod` for a method Stalwart does not know, as
a Stalwart release Garrison does not support yet may give, to UserInfo, where
only 401 says that a token is no longer valid, or to the management API. Signed-in users
stay signed in and see that their rights cannot be checked, nobody new can
sign in, and the broker's journal names the cause and the request that met
it: a broken setup and an answer this release does not read as an error,
Stalwart that could not be reached or failed on its side, and its rate
limit, as a warning, at once and then at most once a minute with how many
more there were. Where the broker gives no answer, the web service's
journal says why, in the same way. A typo in the policy, or an upgrade of Stalwart,
so does not sign everyone out.

A configuration with unknown keys, modules or actions keeps the services
from starting, and ambiguous broker answers count as no grant. Restarted
brokers never repeat a job; pending jobs become "uncertain".

## Known limits

- The macro filter reads documents by their structure, not by running them,
  and looks for them without reading the message's structure, so no
  boundary, nesting depth or header hides a document it would otherwise
  find. What it does not see is listed under
  [configuration](../operator/configuration.md#milter): among it an archive
  with a password, a document in zip archives nested more than three deep,
  archive formats other than zip, and base64 as some mail programs read it;
  how Outlook and Apple Mail decode is not known. Anyone who can reach its
  loopback port can ask it about a message, as with any milter.
- A message the macro filter could not scan completely, as the same section
  lists, is taken all the same unless the operator chose otherwise. By
  default (`on_incomplete = "tag"`) it arrives with the header
  `X-Garrison-Scan: unscanned`, and it is up to a Sieve rule or the mail
  program to act on that; `"defer"` and `"refuse"` keep it out.
- A flood of sign-in callbacks from more than 4096 networks within a minute
  (a single IPv6 /48 holds 65 536 of them) leaves everyone signing in from a
  network that has not tried within that minute 10 exchanges a minute,
  shared with the flood, so such a person is likely to be turned away while
  it lasts. Networks already counted keep their own budget here, signed-in
  users stay signed in, the table holds no more than 4096 networks, and a
  minute after the flood ends everyone can sign in again.
- Stalwart limits requests and blocks addresses on its own, by the client
  address it sees, which by default is the connection's (`clientIpSource`
  is `peer`; measured on Stalwart 1.1.0 with its defaults). Where it runs on
  this host, natively or in the host network, it sees Garrison and nginx at
  127.0.0.1, which it neither limits nor blocks: Garrison is never refused
  for Stalwart's limits, but neither are password guesses that nginx
  forwards to Stalwart's own sign-in page, however many. Where it sees them
  under one other address, as in a container behind a published port or
  behind a proxy on another host, everything they send shares that
  address's limits: 100 unauthenticated requests a minute
  (`rateLimitAnonymous`; code exchanges and Stalwart's sign-in page among
  them), after which nobody can sign in until the minute is over; 1000 a
  minute for each account or key (`rateLimitAuthenticated`), of which each
  check of a user's rights takes three with the broker's one key, so that
  beyond about 330 checks a minute (an open page asks once a minute, an open
  Maintenance page eight times, and about 30 times while it follows a job it
  started) users get 503 until the minute is over and
  the broker's journal names the limit; and after 100 failed password
  sign-ins within a day a block of that address, with no end by default
  (`authBanRate`, `authBanPeriod`), after which Stalwart answers neither
  nginx nor Garrison until an administrator removes it. Told to take the
  client's address from X-Forwarded-For, Stalwart counts and blocks each
  client under its own address in either case, and that address alone: an
  IPv6 client by its whole address and not by its /64, so a client with
  many addresses of one network meets each limit once for every address
  ([installation](../operator/installation.md#client-addresses-for-stalwarts-limits));
  a request without the header, such as Garrison's own or one of a client
  that nginx sees at loopback, which the documented map leaves unnamed,
  counts under the connection's address. Under one other address, such
  clients' failed passwords block it, and Stalwart then closes every
  connection from it, those nginx forwards for any client included, unless
  that address is among Stalwart's allowed IPs, which neither limits nor
  blocks it (measured). One whose header names a loopback address is
  refused (400), so Garrison names no such user.
- Profiles are server-wide; the event history of all domains is visible to
  anyone with the Event history, Deliveries, Sessions or Attacks & bans
  module.
- Rights are cached for up to five seconds in the web service.
- The collector reads the event history through the shared group (for the
  running Stalwart version, how a test message was filed, what was sent
  under each address and the mail flow's numbers), so a compromised collector
  can read mail metadata.
- Events buffered inside Stalwart are lost if Stalwart restarts while the
  receiver is unreachable; receiver downtime beyond Stalwart's one-hour buffer is
  recorded as a gap. So is the time in which the receiver ran but took
  nothing: batches it refused for longer than that hour, because the
  signature key did not match or they could not be stored, and events of a
  recorded type that it could not read or whose time cannot be their own
  (more than five minutes ahead of the receiver's clock, or older than the
  history keeps).
