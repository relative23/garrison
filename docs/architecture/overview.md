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
checks-mail/     checks of the mail flow: event numbers, sending accounts, test mail, antivirus
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
state and verifier stay in a short-lived HttpOnly cookie, so a visitor who is
not signed in writes nothing on the server. The callback exchanges the code,
then asks the broker for a grant. Without one, the token is revoked and no
session is created. Sessions are stored as SHA-256 digests of a random
identifier in a `__Host-` cookie of Garrison's own host name.

**Every API request.** The web service sends the user's token to the broker.
The broker resolves the identity through UserInfo, applies the policy (denial
first), reads the account's roles with its own read-only API key, evaluates
permissions and returns modules and actions. The web service caches this for
five seconds per session. 401 ends the session, 403 means not authorized, 503
(Stalwart or broker unavailable) keeps it.

**Actions.** Web checks Origin, CSRF and the grant; the broker checks the grant
again, the confirmation phrase, idempotency (UUID4 request ID), concurrency and
cooldown, records the job, re-checks the grant when the job starts, and runs
`systemctl start|restart <unit>`. polkit allows exactly the configured pairs.

**Events.** Stalwart sends batches of selected events, signed with HMAC-SHA256.
The receiver verifies, filters fields, stores idempotently and answers 200 only
after commit; otherwise Stalwart retries. Queue IDs link delivery events; span
IDs link the events of one SMTP session.

**Status.** Every minute the collector runs all configured providers. Each
returns observations (what, when, how, scope, findings) and metric samples.
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
