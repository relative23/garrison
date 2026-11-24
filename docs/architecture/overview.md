# Architecture

## Components

| Component | Process / user | Reads | Writes |
|---|---|---|---|
| **web** | `garrison web`, user `garrison` | status and events databases (group), broker socket | `web.sqlite`: sessions, preferences |
| **ingest** | `garrison ingest`, user `garrison-ingest` | signed webhook batches on 127.0.0.1:8094 | `events.sqlite` |
| **collector** | `garrison collect` (timer), user `garrison-collector` | providers: host, systemd, Stalwart API, Prometheus, files, the event history (read-only), DNS and blocklists, TLS listeners, test mail, GitHub's release list | `status.sqlite`: snapshots, metric samples and what the checks remember between runs; messages on the notification channels |
| **watch** | `garrison watch` (timer), user `garrison-collector` | when the collector last finished a run, read-only | a marker file; a message on the notification channels when the collector stops |
| **milter** | `garrison milter`, user `garrison-milter`, only where `[milter]` is configured | each incoming message, shown by Stalwart on 127.0.0.1:8096 | nothing: it answers Stalwart and logs what kind of macro it found |
| **broker** | `garrison broker` (socket-activated), user `garrison-broker` | policy, Stalwart account/role metadata | `jobs.sqlite`: audit and idempotency |

Each database has exactly one writer. Databases another user reads use
SQLite's rollback journal (a read-only WAL reader would need write access to the
shared-memory file). Readers open one snapshot per request and close it at once.

The code mirrors this split, one Rust crate each in `crates/`:

```
core/            configuration, module registry, observation contract, SQLite, JSON I/O
stalwart/        OIDC, JMAP management client, native permission evaluation
authz/           access policy, grants, Authority (token -> grant)
broker/          socket protocol, job store, systemd runner, polkit rule
ingest/          webhook app, privacy policy, event store, queries, summaries of deliveries, sessions, attacks and destinations
checks/          what every check is built from: Provider, Context, options, commands, HTTPS and DNS clients
checks-host/     checks of the host: resources, host care, systemd units, versions, receipts, endpoints, backups
checks-stalwart/ checks of Stalwart: management API, mailboxes, metrics exporter, releases
checks-mail/     checks of the mail flow: event numbers, sending addresses, test mail, antivirus
checks-network/  checks of the network: DNS records, blocklists and reverse names, TLS certificates
collector/       provider registry, status store, notifications, one collection run
milter/          the macro filter: scan of a message, milter protocol, listener
web/             axum app, sessions, security gate, routes, API models and OpenAPI document
garrison/        the one binary: services, operator commands, installer
```

`core`, `stalwart`, `authz`, `broker`, the `checks` crates, `collector` and
`milter` are synchronous and depend on no web framework or async runtime
(enforced by `cargo xtask layering`); axum and tokio run only in the web and
ingest services. Each `checks-*` crate names only the libraries its own checks
use, so one that a single check needs stays out of the others. `testing`
holds shared test fixtures and `xtask` the build and maintenance tasks; neither
is shipped.

## Request paths

**Sign-in.** Authorization Code with PKCE (S256), scope `openid` only. The
state and verifier stay in a short-lived HttpOnly cookie, so a sign-in that is
begun stores nothing on the server; a callback with its cookie's state counts
in a bounded budget of code exchanges per client network
([security](security.md#known-limits)). The callback exchanges the code,
then asks the broker for a grant. Without one, the token is revoked and no
session is created. Sessions are stored as SHA-256 digests of a random
identifier in a `__Host-` cookie of Garrison's own host name.

A session ends when its row is deleted, and its token is revoked at Stalwart
with it: at sign-out, when the policy refuses the user, when the token turns
out to be another user's, and when the same browser signs in again. A
sign-out whose row could not be deleted answers with an error and keeps the
cookie, so that it can be tried again; it never answers "ok" for a session
that is still there.

**Every API request.** Except for sign-out and the switch row's question
(`/api/switch`), which look only at the session, the web service sends the
user's token to the broker. The broker resolves the identity through
UserInfo, applies the policy (denial first), reads the account's roles with
its own read-only API key, evaluates permissions and returns modules and
actions. The web service caches this for five seconds per session. When the
broker answers 401 (the token is no longer valid) or 403 (the policy refuses
this user), the session ends; any other error keeps it, such as 503 when
Stalwart or the broker is unavailable or Garrison's own setup cannot decide
([failure behavior](security.md#failure-behavior)). A request for a module
the grant does not name gets 403 and keeps the session as well.

The interface asks for the status once a minute and reads the session again
right after each answer; the web service answers that read from the grant it
cached for the status, so a change of rights reaches the menu within a
refresh without another question to the broker, and so to Stalwart. A
refused request reads the session again at once. The tabs of one browser
share the session cookie: a tab that signs in, signs out or saves its
settings tells the others on a `BroadcastChannel`, without any data, and
they read the session again.

**Actions.** Web checks Origin, CSRF and the grant; the broker checks the grant
again, the confirmation phrase, idempotency (UUID4 request ID), concurrency and
cooldown, records the job, re-checks the grant when the job starts, and runs
`systemctl start|restart <unit>`. polkit allows exactly the configured pairs.

**Events.** Stalwart sends batches of selected events, signed with HMAC-SHA256.
The receiver verifies, filters fields, stores idempotently and answers 200 only
after commit; otherwise Stalwart retries. It reads two batches at a time and
removes what its limits no longer keep after the answer, in its maintenance
task. Queue IDs link delivery events; span
IDs link the events of one SMTP session.

**History queries.** The event lists, details and summaries and the metric
history read databases that other services write, and while a query reads,
that writer's commits wait. So the web service runs two at a time, each for
at most two seconds (a longer one is answered 503, which asks for a narrower
filter or a shorter period). A query that waits longer than two seconds for
the writer's commit, as while the receiver removes a tenth of a full
history, is answered 503 as well, which asks to try again in a moment; so
are the status and the history's coverage, which are read outside the
turns. A further query waits up to two seconds for its
turn, and at most eight wait; any other is answered 429 at once. A query
whose request goes away, as when the browser moves on to another filter,
stops at its next step, or while it waits for the writer's commit, and
gives its turn to the next.

**Status.** Every minute the collector runs all configured providers. Each
returns observations (what, when, how, scope, findings) and metric samples.
The metric history keeps every minute for eight days, which the 24-hour and
7-day views draw; older samples are thinned to one per ten minutes, each
counting for the minutes it holds, so the longer views read the same.
Both ages count from the collector's own run time, which each step of at
most ten minutes from one run to the next moves on, and a longer one, a
pause or a jump, does not. A run's own time is taken again once it is within
ten minutes of that, or once the collector has run at the new time for a
day. So a clock that jumps ahead takes no history with it, and no pattern of
pauses stops the clean-up. A clock that goes back makes the collector write
minutes a second time: such a minute then holds the increases of both times,
so that the history loses no event, and the later reading of each gauge.
The web service filters observations by the modules the user may see. Every
observation has an id that notifications and operators' scripts rely on, so
the ids are kept like an interface ([observation ids](../operator/observations.md)).

## What is deliberately not here

- No changes to Stalwart's binaries, WebUI files or license checks.
- No shell, no arbitrary command, no Docker socket, no raw mail in the
  interface or on disk. The optional macro filter reads each incoming message
  in memory to judge it and keeps nothing of it.
- No per-domain tenant isolation: profiles are server-wide.
- No reconstruction of events from before the webhook existed.

See [security.md](security.md).
