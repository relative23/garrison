# Security model

## Assets

Stalwart administration (accounts, configuration), mail metadata in the event
history (addresses, IPs, hostnames), the ability to restart host services, the
credentials Garrison holds and, where the macro filter is switched on, each
incoming message while the filter judges it.

## Boundaries and controls

| Boundary | Control |
|---|---|
| Internet → web | nginx TLS on Garrison's own host name, which serves nothing else; `/metrics/` blocked in Stalwart's server blocks; strict CSP without inline code or styles, except the build's own stylesheet in the drawn pages, allowed by its SHA-256 hash, which the web service takes from the page it sends; JSON answers go out gzipped when the browser accepts it, except `/api/session`, which carries the CSRF token (a compressed secret next to text an attacker chose leaks by its length, BREACH); `X-Frame-Options: DENY`; no access log; at most 10 sign-in code exchanges a minute per client network (an IPv4 address or an IPv6 /64 of the address nginx names; requests it names none for count as one network), for up to 4096 networks within a minute, and 10 a minute together for all networks beyond those, so at most 40 970 a minute in all; a refused callback goes back to the sign-in page, which says to wait a minute, and its code never reaches Stalwart. |
| Browser → API | Session cookie (`__Host-`: this host name only, HttpOnly, SameSite=Lax); writes need the exact Origin and the CSRF token; every route names its module. |
| Garrison ↔ Stalwart WebUI | Separate host names: `check-config` refuses an origin shared with the issuer or the Stalwart WebUI, and the web service answers other host names only with a redirect to its own. Neither interface's scripts can act in the other or read its storage. |
| Web → broker | Unix socket, group `garrison`, mode 0660; the broker accepts only allowed peer UIDs (SO_PEERCRED). The web service sends the user's token, never an identity: a compromised web service can act only as a user who is signed in at that moment, within that user's rights. The broker serves at most 16 requests at once and closes further connections unanswered (the web service then answers 503), so a flood of connections cannot use up the tasks its unit allows (`TasksMax=32`) and a maintenance job needs. |
| Broker → host | Unprivileged user; polkit rule generated from `[[actions]]` allows exactly those unit/verb pairs (verified: other units and verbs are denied). Fixed argument vectors, no shell. |
| Garrison → Stalwart | A registered OAuth client (`stalwart setup`): only its own callback, PKCE, no service such as mail. User tokens carry only `openid`; Stalwart grants them `authenticate` and `authenticateWithAlias`, no management API and no mail (contract test `crates/web/tests/contract.rs`). Broker and collector use separate API keys with Replace permissions (4 and 10 read permissions), usable only from loopback. `stalwart setup` writes with an administrator's credential that it is given for the run and stores nowhere: the webhook, the keys, the exporter, the sign-in client and, where configured, the macro filter's entry among the milters. |
| Garrison → Stalwart WebUI | Optional: an nginx include adds one script that draws the "Switch to Garrison WebUI" row. Subresource Integrity pins it (a changed file does not run); it reads no page data, tokens or storage. Its one request goes to `/api/switch`, which answers only whether the signed-in user turned the row on and is the only answer the Stalwart WebUI's origin may read; the row is shown only when that answer says so, and a missing, failed or other answer shows none. The session cookie is `SameSite=Lax`, so the browser sends it with that request only where Garrison and the Stalwart WebUI are the same site, under one registered domain such as `garrison.example.org` and `mail.example.org`; across sites Garrison sees no session there and the row stays away. It runs in the Stalwart WebUI's origin, so it stays one small, reviewed file of under a hundred lines of code. |
| Stalwart → ingest | Loopback listener; HMAC-SHA256 signature over the body; size limits; two batches are read at a time, and a batch has ten seconds to get its turn and arrive whole; event-type and field allowlist; raw protocol data, bodies and client-supplied free text are never stored. Of a failed sign-in the address, the listener and Stalwart's verdict are kept; the name that was tried is kept only where Stalwart found an account of that name, since any other name may be a password typed into the wrong field. Of a check of an incoming sender (SPF, DKIM, DMARC, ARC) only the name of the outcome is kept, not the records it looked at. |
| Stalwart → milter | Optional (`[milter]`). Loopback listener under a user of its own that can read the configuration and nothing of Garrison's state; the unit may reach loopback only and has no writable path. A message is held in memory while it is judged and then dropped; the journal gets the kind of finding, never a sender, recipient, subject or file name. Limits on frame size, message size, unpacked size, archive depth and connections at once, and one bound on what the messages of all connections hold together, keep crafted or many large messages from exhausting memory: a message that finds no room is deferred, not passed. A scan's work grows with the size of the message alone, whatever its archives' headers claim, and the filter answers within 20 seconds of a message's end. A message it could not scan completely gets what `on_incomplete` says, never the answer of a clean one. The parsers are fuzzed. Stalwart is told of the filter only while it answers, and the filter stops only after Stalwart has forgotten it. |
| Local users → files | One system user per service; state directories 0700/0750; credentials via systemd `LoadCredential=`; policy root-owned 0640 for the broker group; backups contain no sessions or credentials. |
| Service users → root commands | `backup`, `self-check` and `install --rollback --restore-state` follow no links in the state directories; a database holding anything but tables and indexes is not read; a restored file is created new, owned like its directory and renamed into place. Services read each other's databases the same way. |
| Collector → outside | Only what an operator configured, and nothing about the installation: the `releases` provider asks GitHub's public release list once a day; `[notifications]` sends the title and first finding of a check to the channels named there and to no other: an ntfy topic, a webhook, a mailbox through the named mail server (signed in, with the certificate checked for that name), each over TLS with a secret read as a systemd credential; the `dns` provider asks this host's resolver for the names Stalwart lists, each question with a random number from a port the system chose, and reads only an answer that carries that number and repeats the question; every length in an answer is checked (fuzz target `dns_answer`), and where a domain publishes an MTA-STS record it fetches that domain's policy file; the `reputation` provider, off in the example configuration, asks the named blocklists about the mail hosts' addresses through this host's resolver, so those lists learn the addresses; the `tls` provider connects to Stalwart's listeners on this host; the `mail-test` provider hands its test messages to the SMTP listener at the configured IP address, loopback by default, and to the one recipient named. |
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

A refusal (403) is what the policy says of a user: the subject is on the deny
list, has no binding, belongs to an account that is not allowed, lacks the
rights its profile requires, or has profiles that name none of the modules
the installation offers. It ends that user's session, as an invalid token
does (401).

Everything else grants nothing and refuses nobody, and is answered 503: a
Stalwart or a broker that is temporarily unavailable, and a setup of
Garrison's own that is broken. That is a policy that does not read, is not
protected or names an action the configuration does not have; a broker key
that is missing or that Stalwart no longer takes; and an answer about an
account's rights that cannot be used. Signed-in users stay signed in and see
that their rights cannot be checked, nobody new can sign in, and the
broker's journal names the cause as an error. A typo in the policy so does
not sign everyone out.

A configuration with unknown keys, modules or actions keeps the services
from starting, and ambiguous broker answers count as no grant. Restarted
brokers never repeat a job; pending jobs become "uncertain".

## Known limits

- The macro filter reads documents by their structure, not by running them:
  it misses what an archive with a password hides, Excel 4.0 macro sheets in
  an old `.xls` file, the macros of an old `.ppt` file and archive formats
  other than zip. Anyone who can reach its loopback port can ask it about a
  message, as with any milter.
- A message the macro filter could not scan completely is taken all the same
  unless the operator chose otherwise: one larger than `max_message_mib`,
  one whose archives unpack to more than 16 MiB a file or 64 MiB together or
  are packed otherwise than by deflate, and one whose scan was not done
  within 20 seconds. By default (`on_incomplete = "tag"`) it arrives with the
  header `X-Garrison-Scan: unscanned`, and it is up to a Sieve rule or the
  mail program to act on that; `"defer"` and `"refuse"` keep it out.
- A flood of sign-in callbacks from more than 4096 networks within a minute
  (a single IPv6 /48 holds 65 536 of them) leaves everyone signing in from a
  network that has not tried within that minute 10 exchanges a minute,
  shared with the flood, so such a person is likely to be turned away while
  it lasts. Networks already counted keep their own budget, signed-in users
  stay signed in, the table holds no more than 4096 networks, and a minute
  after the flood ends everyone can sign in again.
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
