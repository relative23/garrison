# Contributing to Garrison

Thank you for helping. Garrison adds status, history and maintenance
pages to Stalwart Mail Server and runs with access to a production mail host,
so this guide asks for more care than most: every change is tested, every claim
the interface makes is backed by evidence, and no change widens what a service
may do without a review.

- [Getting oriented](#getting-oriented)
- [Design goals](#design-goals)
- [Setting up](#setting-up)
- [Checks](#checks)
- [Tests](#tests)
- [Code rules](#code-rules)
- [Common changes](#common-changes)
- [Dependencies](#dependencies)
- [Releases](#releases)
- [Commits and pull requests](#commits-and-pull-requests)
- [Licensing](#licensing)

Security problems are not reported in public issues; see [SECURITY.md](SECURITY.md).
Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).

## Getting oriented

| Path | What it holds |
|---|---|
| `crates/core` | Configuration, SQLite access, logging, time, the module registry |
| `crates/stalwart` | Stalwart's OIDC, JMAP and management API clients |
| `crates/authz` | The access policy and the grant of a signed-in user |
| `crates/broker` | The privileged service that starts maintenance jobs |
| `crates/checks` | What every check is built from: `Provider`, options, commands, the HTTPS and DNS clients |
| `crates/checks-*` | The checks, by what they look at: `host`, `stalwart`, `mail` and `network` |
| `crates/collector` | Runs the configured checks into `status.sqlite` and sends the notifications |
| `crates/ingest` | The webhook receiver and the event history queries |
| `crates/milter` | The optional macro filter: the scan of a message and the milter protocol |
| `crates/web` | The HTTP service: sign-in, API, interface files |
| `crates/garrison` | The single binary: every service, the installer, the CLI |
| `crates/testing` | Fixtures shared by tests; never a normal dependency |
| `frontend` | The React interface, built into `static/` of a release |
| `deploy` | systemd units, sysusers, nginx and configuration examples |
| `xtask` | Build and maintenance tasks: `cargo xtask --help` |
| `e2e` | Browser checks of the interface: flows, Lighthouse and axe |
| `fuzz` | Fuzz targets, a workspace of its own |
| `scripts/acceptance.sh` | Upgrade and rollback test on a disposable host |
| `scripts/acceptance-failures.sh` | The installer's failure paths on a disposable host |

[docs/architecture/overview.md](docs/architecture/overview.md) explains how the
services work together, and [docs/architecture/security.md](docs/architecture/security.md)
explains what each one is allowed to do and why.

## Design goals

- **Garrison shows only what it adds.** Accounts, domains and every other
  Stalwart setting stay in the Stalwart WebUI. The interface follows that
  WebUI's layout and structure, so both feel like one product; its colours
  are its own.
- **Least privilege.** The web service never holds an administrative
  credential. The broker derives the user's identity from the user's token and
  runs only reviewed systemd units. A hidden menu entry never grants or revokes
  a permission.
- **Unknown is not OK.** Unknown, stale and unverified data stay visibly
  distinct from a successful check, and every value says how it was obtained.
- **The host stays the operator's.** Stalwart's files, mail data and unrelated
  services are left alone, and the interface never exposes shell commands,
  Docker sockets, secrets or mail contents. Garrison uses what Stalwart
  offers in a stable release and never works around a license check.
- **Easy to run for years.** One static binary, one configuration file, an
  idempotent installer with backup and rollback, and documentation a beginner
  can follow.

## Setting up

You need Rust (the exact release in `rust-toolchain.toml` is installed
automatically), Node.js 24 or newer for the interface, and Docker for the
contract and acceptance tests.

```sh
git clone https://github.com/relative23/garrison.git
cd garrison
rustup toolchain install                       # the release in rust-toolchain.toml
cargo install --locked cargo-deny@0.20.2       # license and advisory checks
cargo install --locked cargo-machete@0.9.2     # unused dependencies
cargo install --locked cargo-llvm-cov@0.9.1    # coverage of the Rust tests
rustup component add llvm-tools                # which cargo-llvm-cov needs
(cd frontend && npm ci --ignore-scripts)
```

`npm run dev` in `frontend/` serves the interface with live reload and forwards
the API to a web service on 127.0.0.1:8091.

TypeScript is pinned to 6.0, the last release with the compiler API that
`typescript-eslint` and `openapi-typescript` need. `openapi-typescript`
declares only TypeScript 5 as its peer, so `package.json` overrides that range.
`package.json` also gives the lint tools minimatch 11.0.1, the first release
without GHSA-g3hv-75wg-m249; the override goes once they require it themselves.
`e2e/package.json` gives the Sentry plugin inside Lighthouse glob 14.0.2 and
minimatch 11.0.1, the first releases without GHSA-3g3m-2fjr-6pw4 and
GHSA-g3hv-75wg-m249. Lighthouse loads Sentry only for error reporting, which
the measurements leave off; that override goes once the plugin requires a
fixed glob itself.

## Checks

These are the checks CI runs; run them before you push. A check is never made
green by weakening it: a lower coverage threshold, a new lint `allow` or an
exception needs the same review as the code it excuses.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo test --workspace --locked
cargo xtask check                              # layering and file sizes
cargo deny --locked check                      # licenses, advisories, sources
cargo machete                                  # no crate declares a dependency it does not use
cargo coverage                                 # the tests again, with the lines they run
shellcheck scripts/*.sh                        # when a script changed
actionlint                                     # when a workflow changed
cd frontend
npm run typecheck && npm run lint && npm run format:check
npm run knip && npm run coverage && npm run build
npm run audit                                  # known vulnerabilities, needs the registry
```

| Check | What it protects |
|---|---|
| `clippy` | Pedantic lints; `unsafe` is forbidden and `unwrap` is a warning, so an error |
| `cargo xtask layering` | `core`, `stalwart`, `authz`, `broker`, the `checks` crates, `collector` and `milter` never depend on a web framework or an async runtime |
| `cargo xtask sizes` | Handwritten files stay at or below 500 lines |
| `contract_files` test | `frontend/api/openapi.json` and `modules.json` match the code |
| `cargo coverage` | The tests run at least 90 % of the lines, counted without build tooling, test fixtures, and the installer and the Stalwart setup, which acceptance and contract tests check on a real host; `cargo coverage --html` shows the lines no test runs |
| `npm run lint` | No visible text outside the catalog, no rendered HTML |
| `npm run format:check` | Prettier formatting; `npm run format` applies it |
| `npm run knip` | No unused files, exports or dependencies |
| `npm run coverage` | Frontend coverage of at least 95 % of lines (90 % of branches) |
| `npm run audit` | No known vulnerability in what the interface ships, none rated high or critical in the build tools |
| `shellcheck`, `actionlint` | The acceptance scripts and the workflows, with the shell in their steps; CI pins ShellCheck 0.11.0 and actionlint 1.7.12 |

Changes to code that talks to Stalwart also run the contract tests, which start
a supported Stalwart release in Docker, pinned by its digest:

```sh
eval "$(cargo xtask lab start)"                # the supported release
cargo test --workspace --locked --test contract -- --ignored
cargo xtask lab stop
```

CI runs the contract tests against every supported release (`IMAGES` in
`xtask/src/lab.rs`), on every change and once a week without one, because
Stalwart serves its WebUI from outside the release and changes it without a
new version. The job `contract-newest` runs them against Stalwart's newest
release (`NEWEST`, `cargo xtask lab start newest`) while it is not a
supported one. Renovate moves `NEWEST` to each new release and to a new
image of the same release, without the 14 days' wait, so its pull request
shows whether Garrison still fits.

## Tests

Test what a user or an attacker can observe: permissions, refused input,
cancellation, concurrent requests, what survives a restart and what an upgrade
or a rollback leaves behind. A test names the behavior it proves, such as
`a_demotion_before_execution_prevents_the_run`.

- **Unit tests** sit next to the code (`mod tests`, or `tests.rs` beside a
  module that would otherwise grow past 500 lines).
- **Sequence tests** (`crates/ingest/src/store/sequence_tests.rs`) run long
  random sequences of what happens to a history over months (batches, limits,
  cleanups, restarts, time away) against a plain model and check after every
  step that no event is lost without a recorded window that says so. A new
  way to remove or keep events is added there as a step.
- **Work tests** (`crates/ingest/src/queries/work_tests.rs`) count the steps
  SQLite takes for each query in a small and in a ten times larger history. A
  page of a list must cost the same in both; a new list or detail query is
  added there.
- **Integration tests** in `crates/*/tests/` drive a whole service: the web
  routes through a fake broker and identity provider, the receiver with a
  signed batch whose rows and answers `fixtures/golden.json` records.
  `backup_check.rs` runs the command with stand-ins for restic and borg;
  with restic installed, `cargo test -p garrison --test backup_check --
  --ignored` asks the real one.
- **Contract tests** (`crates/*/tests/contract.rs`, or `tests/contract/`
  where they are several files) check every assumption about Stalwart against
  the real release. Anything Garrison expects from Stalwart needs one.
- **Frontend tests** in `frontend/tests/` render the real views against a
  stand-in API server (`tests/support/server.ts`) with typed sample answers,
  so a contract change also breaks the fixtures.
- **Acceptance** (`scripts/acceptance.sh`, see [Releases](#releases)) installs,
  upgrades and rolls back real archives on a disposable host;
  `scripts/acceptance-failures.sh` drives the installer into every failure it
  must survive.
- **Fuzz targets** (`fuzz/`, see [Fuzzing](#fuzzing)) feed arbitrary input to
  the code that reads what Garrison did not write.

Mutation testing shows which changes to the code no test notices. It is slow,
so it runs by hand, not in CI:

```sh
cargo install --locked cargo-mutants@27.1.0
cargo mutants --workspace                         # everything; takes hours
cargo mutants --workspace --in-diff <(git diff main)  # what a branch changes
```

`.cargo/mutants.toml` lists what is excluded and why. A surviving mutant
deserves a test, or a short note in the pull request why it changes nothing a
user could observe. cargo-mutants copies the tree for each job; set `TMPDIR` to
a directory on disk if `/tmp` is in memory.

Benchmarks (`crates/*/benches`, with Divan) measure the paths that grow with
the data: storing a webhook batch, listing and searching the event history,
and the metric history of each period over 90 days of samples. They run by
hand, not in CI, where the machines differ from run to run:

```sh
cargo bench -p garrison-ingest --bench history
cargo bench -p garrison-collector --bench metrics
```

The numbers belong to the machine they were measured on. Before a change to
one of these paths, run its benchmark on the commit before and on yours, and
say both in the pull request. The web service gives a history query two
seconds; a line above that is a request that fails.

The **preview** runs the production web service and the built interface with
the collector's golden observations and examples of the checks that ask the
network (`crates/web/examples/preview/extras.json`), a week of metric history
and the receiver's test batch; its sign-in approves at once and its broker
grants everything. `e2e/` drives it in a real Chrome. `npm run flows` does what a
user does: it signs in, opens every page, moves through the menu, searches
the event history, saves settings, runs a maintenance action and signs out,
and fails on an error in the console, a failed request, a finding of axe
(WCAG 2.2 AA, both themes) or a page that is wider than a phone's screen; CI
runs it. `npm run measure` measures every page
with Lighthouse (Performance, Accessibility and Best Practices, desktop and
mobile) and axe on both screen sizes, by hand. It measures over HTTP/2 with
TLS, as nginx serves Garrison, through a proxy with a certificate it makes
with `openssl` for the run; `--http1` measures the preview directly:

```sh
(cd frontend && npm run build)
cargo run -p garrison-web --example preview        # http://localhost:18091/
(cd e2e && npm ci && npm run flows)                # in a second terminal
(cd e2e && npm run measure -- --runs 3)
```

The README's screenshots come from the same preview started with `--busy`,
which shows a mail server with a lot going on: a month of sign-in attacks, a
week of sessions and deliveries and observations with large numbers, all made
up from reserved example names and addresses
(`crates/web/examples/preview/busy.rs`, `busy.json`). Take them again when a
page they show changes:

```sh
cargo run -p garrison-web --example preview -- 18091 --busy
(cd e2e && npm run screenshots)                    # writes .github/screenshots/
```

### Fuzzing

`fuzz/` is a workspace of its own with one target for each kind of input
Garrison does not write itself: the strict JSON parser (`json`), a line on the
broker's socket (`broker_request`), the text of Stalwart's metrics endpoint
(`prometheus`), a resolver's answer (`dns_answer`), a batch of events together
with every view of the stored history (`events`), any request to the web
service's routes, signed in or not, with real databases behind them
(`web_request`), a message as the macro milter scans it (`milter_scan`) and
what a mail server sends that milter on a connection (`milter_session`). A
target fails on a panic, on an answer "Internal error", and where what was
stored cannot be read again. The targets need a nightly compiler and
cargo-fuzz, so they are no part of the checks before a commit;
`.github/workflows/fuzz.yml` runs each for five minutes every week and
whenever `fuzz/` changes.

```sh
cargo install --locked cargo-fuzz@0.13.2
cd fuzz
cargo +nightly fuzz run web_request corpus/web_request seeds/web_request -- -max_total_time=300
```

`seeds/` holds the inputs to start from, such as one request for every route;
add one for a new route or a new kind of event. The fuzzer keeps what it finds
in `corpus/` and an input that breaks a target in `artifacts/`; neither is
committed. Turn such an input into a test beside the code it broke before you
fix the code, and add it to `seeds/`.

## Code rules

Source, comments, identifiers, file names and documents are in English.

### Rust

- **Don't panic.** Product code uses no `unwrap`, `expect` or `panic!`; it
  returns an error that says what failed. `unreachable!` is allowed with a
  comment that proves the case cannot happen. Tests may unwrap.
- **Don't exit.** Only `main` decides the exit code. Libraries return errors,
  so every service can report a failure in its own way.
- **No `unsafe`.** The workspace forbids it; system calls go through `rustix`.
- **Keep paths as paths.** Use `Path` and `OsStr` until a value is displayed;
  converting to `str` loses or rejects names that are valid on Linux.
- **Macros sparingly.** A function is easier to read, test and change.
- **One writer per database.** Each SQLite file has exactly one writing
  service (`config::Database`). Readers use `core::sqlite::reading()` and never
  keep a connection beyond one request.
- **No host-specific names in code.** Units, paths and hosts belong in
  `garrison.toml`, in providers and actions.
- **Small modules.** Split by responsibility, not at an arbitrary line;
  authentication, authorization, collection, storage, HTTP and rendering stay
  apart.
- **Errors for people.** A message names the setting, file or unit and what to
  do; it never contains a secret, a token or mail content.
- **Types across boundaries.** What one component stores or sends and another
  reads is a type both use (`broker::protocol`, `collector::snapshot`,
  `core::observations`, `ingest::answers`), not JSON put together by hand. The
  API's own types (`web/src/models.rs`) are made from those in conversions
  that name every field, so a changed field fails to compile instead of
  failing a request.

### Interface

- Strict TypeScript; no `any`.
- Every visible text is in `frontend/src/i18n/en.json` and rendered with
  `t()`; values from the server are shown as sent, as text, never as HTML.
- The Content-Security-Policy allows no injected styles or scripts, so the
  interface uses native elements such as `<dialog>` and `<select>`. The one
  exception is the stylesheet `prerender.mjs` writes into the drawn pages;
  the web service allows it by its hash.
- Follow the Stalwart WebUI's layout and structure (`frontend/src/styles/index.css`,
  `components/ui`), not its colours: Garrison keeps its own palette, which is
  measured for contrast. Never copy its code.
- The only thing Garrison adds to the Stalwart WebUI is the opt-in switch row
  (`frontend/public/stalwart-switch.js`, `crates/web/src/switch.rs`). It runs
  in the Stalwart WebUI's origin; keep it that small.
- A missing value is shown as Unknown, never as zero, empty or success.

### Comments

Comments explain why, not what: a security boundary, an unusual decision, a
limit someone would otherwise raise. Keep them short; if a comment has to
describe what the code does, a better name usually helps more. A doc comment
says something the name and signature do not. Update comments with the code:
an outdated comment is worse than none.

## Common changes

### Changing the API

1. Change the response types in `crates/web/src/models.rs` and the routes
   with their `#[utoipa::path]`.
2. `cargo xtask api` writes `frontend/api/openapi.json` and `modules.json`.
3. `npm run api` in `frontend/` regenerates `src/api/schema.gen.ts`; never edit
   it by hand.
4. Fix the TypeScript errors and the fixtures in `frontend/tests/support/`.

### Interface texts

Use plural keys (`_one`, `_other`) for counts and `<Trans>` for inline markup
such as `<code>`. `npm run lint` rejects text written directly in JSX, and
`npm run typecheck` rejects keys that `en.json` lacks. To add a language, add
`src/i18n/<language>.json` with the same keys and register it in `CATALOGS` in
`src/i18n/index.ts`; `tests/i18n.test.tsx` checks keys and placeholders.

### Adding a module

1. Add a `ModuleId` and its `Module` to `crates/core/src/modules.rs`.
2. Add a view with its own icon to `frontend/src/modules/registry.tsx` and the
   module's name, description and intro to `frontend/src/i18n/en.json`.
3. Export the API contract (above). `tests/registry.test.ts` fails until both
   registries and the English texts match.

### Adding a provider

1. Implement `Provider` (`name`, `collect`) in `src/providers/` of the
   `crates/checks-*` crate for what it looks at, and validate its options with
   `Options`. A dependency it needs goes into that crate only.
2. Register its `type` in `TYPES` in `crates/collector/src/providers/mod.rs`.
3. Report an unreadable source as an Unknown observation, not as an error.
4. Add tests with fixture files and document the options in
   [docs/operator/checks.md](docs/operator/checks.md).
5. List the new observation ids in
   [docs/operator/observations.md](docs/operator/observations.md) and give the
   type an entry in `crates/collector/tests/observation_ids.rs`, which holds
   every id the checks report to that list.

Status pages render observations generically, so no interface change is needed.

Observation ids are an interface: notifications remember them, and
operators' scripts read them. Renaming one is a change to announce. Put old
and new into `RENAMED` (`crates/core/src/observations.rs`) and under Renamed
in the list, and name it in the changelog. For that release the observation
carries its old id in `value.aliases` and notifications keep what they
remembered. The release after takes the entry out again.

### Supporting a new Stalwart release

1. Add the image and its digest to `IMAGES` in `xtask/src/lab.rs` (Renovate's
   pull request has them in `NEWEST`) and the release to the contract job in
   `.github/workflows/ci.yml`, then run the contract tests against it. A
   release stays in both for as long as it is supported.
2. Regenerate the event labels from the new schema while the lab runs:
   `curl -sL -u "$GARRISON_LAB_ADMIN" "$GARRISON_LAB_URL/api/schema" | gunzip > schema.json`,
   then `cargo xtask event-types schema.json`.
3. Review webhook fields and permission names, then update the supported
   releases in `README.md`.

## Dependencies

Every dependency is code that runs on a mail host, so the bar is high.

1. Prefer the standard library and crates or packages already in use. A new one
   needs a reason in the commit message: what it replaces and who maintains it.
2. Use releases that are at least 14 days old, including everything they add to
   `Cargo.lock` or `package-lock.json`: `cargo update -p <crate> --precise
   <version>`, `npm install --before=<date>`. The exception is a fix for an
   advisory; take the oldest release that fixes it and name the advisory.
3. Rust dependencies are declared once in `[workspace.dependencies]` and must
   pass `cargo deny --locked check`. A license not listed in `deny.toml` needs a
   review before it is added there.
4. Install npm packages with `--ignore-scripts`; a package that needs an
   install script needs a review.

Renovate (`renovate.json`) proposes updates once a release is 14 days old,
keeps npm packages at exact versions, moves Rust crates through `Cargo.lock`
and keeps the GitHub Actions pinned to commit digests; review its pull
requests like any other change.

## Releases

One archive per architecture; building it publishes nothing:

```sh
rustup target add aarch64-unknown-linux-musl x86_64-unknown-linux-musl
cargo install --locked cargo-zigbuild@0.23.4   # cross-linking through Zig
# Zig 0.17.0 on PATH: https://ziglang.org/download/ (check the sha256 there)
cargo xtask release                            # dist/garrison-<version>-<arch>.tar.gz
cargo xtask release aarch64                    # one architecture only
```

The binaries are static (musl), so they run on any Linux of their architecture.
Each archive holds `bin/garrison`, the interface in `static/`, `deploy/`,
`docs/`, the notices of exactly the crates and packages it contains, the
notices of the Rust standard library and musl libc in `licenses/`, a CycloneDX
SBOM in `sbom.cdx.json` (also written next to the archive) and `SHA256SUMS`.
`cargo xtask sbom` prints the SBOM without a build. The same commit yields
the same archive; `cargo xtask release` refuses other Zig or cargo-zigbuild
versions, because they are part of the build like the compiler.

### Signing releases

Releases are signed with minisign. The secret key stays with the maintainer,
best on a machine or medium that is offline, and never enters the repository:

```sh
minisign -G -s ~/.minisign/garrison.key -p garrison.pub   # once; asks for a password
tail -n 1 garrison.pub >> deploy/signing/keys.txt           # commit the public key
GARRISON_SIGNING_KEY=~/.minisign/garrison.key cargo xtask release
```

The release task then writes a `.minisig` next to the archive and the SBOM.
Their trusted comment names the release (`garrison <version> <arch>`), and
`garrison upgrade` refuses a signature that names another one. Releases built
with a key in `deploy/signing/keys.txt` accept upgrades signed by that key
only. To replace a key, add the new one in a release signed with the old one,
and remove the old key in a later release. Publish the public key in the README
as well, so that operators can check a first installation.

`.github/workflows/release.yml` builds the archives of a `v*` tag twice,
requires both builds to be identical, attests where they came from and keeps
them as a workflow artifact; it publishes and signs nothing. To release, build
the same tag locally, compare the two sets of checksums (`sha256sum` must
match, since the build is reproducible; `gh attestation verify <archive>`
shows the attested commit), sign your local archives and publish each archive
with its `.minisig`, `.sha256` and `.cdx.json`. GitHub keeps attestations for
public repositories only: while the repository is private the workflow skips
that step, and the checksums in its log and artifact are what to compare.

### Acceptance on disposable hosts

A release is accepted on hosts that are made for the run and removed after
it. Each script takes release archives, prints one line for every check and
stops at the first `FAIL`.

| Script | Archives | What it proves |
|---|---|---|
| `acceptance.sh` | previous, new | Install, upgrade, rollback with and without the pre-upgrade state, and upgrade again, with every service checked each time; what `detect` reports |
| `acceptance-failures.sh` | previous, new | Refusals change nothing (no root, no polkit, a changed file, a configuration the release refuses, a failed backup). A release that does not start, or keeps restarting, is switched back. A second installer is refused. An installer killed at any point leaves a state the next run finishes. A rollback without the pre-upgrade state stops first |
| `acceptance-upgrade.sh` | `OUT` | `garrison upgrade` refuses an archive changed after signing, a signature naming another release, a foreign key, a missing signature, another architecture, the running version, a user other than root and a binary outside the installed releases, each without changing anything; then it upgrades |
| `acceptance-uninstall.sh` | previous, new | A dry run changes nothing, an uninstallation keeps configuration and data for the next installation, and a purge leaves nothing of Garrison but the operator's own backups |
| `acceptance-host.sh` | previous, new | In a virtual machine, what a container cannot show: Garrison under the distribution's own SELinux or AppArmor, behind nginx with TLS, after a reboot and after an upgrade there |
| `acceptance-ansible.sh` | `OUT` | In a virtual machine, the Ansible role in `deploy/ansible`: a first installation, a second run that changes nothing and an upgrade by version. Needs `ansible-playbook` (`ANSIBLE` names another one) and `minisign` |
| `acceptance-quickstart.sh` | new | In a virtual machine, the quick start against a real Stalwart (the image `xtask/src/lab.rs` pins, run with Podman in the host network): the install at a terminal, `garrison setup` answered as an operator would, nginx with the server block setup printed, the sign-in redirect to Stalwart, a mail session that arrives as events, `garrison doctor` without a problem but the reserved test names, and the macro filter switched on and off again |
| `soak.sh` | previous, new | `SOAK_MINUTES` (120) under `SOAK_RATE` (40) events a second: no service restarts, logs an error or grows by more than 64 MiB after warm-up; the event store stays within its limit and stops growing once the limit applies; every accepted event is stored or lies in the window the receiver recorded for what the limit removed |

`scripts/signed-releases.sh OUT` builds what they take: two archives of the
current commit, the second with the higher version, that trust a throwaway
key and are signed with it. Never publish those archives: the secret half of
their key lies next to them.

| Setting | Effect |
|---|---|
| `DISTRO` | `almalinux-10` (the default) or `debian-13` in a container. In a virtual machine also `debian-12`, `ubuntu-22.04`, `ubuntu-24.04`, `ubuntu-26.04`, `almalinux-9`, `rocky-9`, `rocky-10`, `centos-stream-10`, `fedora-44`, `amazonlinux-2023` and `opensuse-leap-16.0` |
| `HOST=vm` | A virtual machine instead of a container (`scripts/vm-lib.sh`): the distribution's official cloud image, checked against its checksum list and cached in `~/.cache/garrison-vm`, a disk that is deleted afterwards, and root over SSH with a key made for the run |
| `ARCH=aarch64` | With `HOST=vm`, an emulated ARM machine (`apt install qemu-system-arm qemu-efi-aarch64`): slow, but with a real aarch64 kernel |
| `CLAMAV=1` | Installs ClamAV first, for `detect` to find |
| `UPDATE=1` | First installs every update the distribution has and restarts a virtual machine into them, so that the host is one that is kept up to date |
| `KEEP=1` | Leaves the host running afterwards and says how to reach it |

A release runs `acceptance.sh` with and without ClamAV on both container
distributions, `acceptance-failures.sh` on both, and the virtual machines of
every distribution the installation guide names. The containers need Docker,
about 2 GiB of memory and a host of the archive's architecture. On an x86_64
host the aarch64 build is also checked by running the tests through qemu
(`apt install qemu-user qemu-user-binfmt`):

```sh
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER=qemu-aarch64 \
    cargo-zigbuild test --workspace --locked --target aarch64-unknown-linux-musl
```

### Changing the configuration format

`garrison.toml` carries `schema = 1`. A new setting gets a default, so that a
file written for an earlier release keeps loading; that covers almost every
change. A change that cannot keep old files working raises `schema`, and the
same release brings a `garrison migrate-config` that rewrites the file with a
`.previous` copy, which the installer runs before its configuration check. No
such command exists before the first such change. Until then the installer
already refuses an upgrade whose configuration the new release cannot load,
before anything stops, and `check-config` names the setting.

### Upgrade notes

Whatever an operator must do when upgrading, such as a new nginx include or a
removed setting, gets a line under "Upgrade notes" in `CHANGELOG.md` in the
change that requires it.

## Commits and pull requests

- **Small, atomic commits.** One change per commit; it builds and passes the
  checks on its own. Moving code is its own commit, so the change stays
  reviewable.
- **Messages for the reader of the history.** The summary line is an
  imperative sentence of at most 72 characters that says what changes, such
  as `Show who asked for each maintenance job by address`. The body says why,
  and what a reviewer should know: a schema change, a new permission, a risk.
- **Focused pull requests.** Describe what changed and how you tested it.
  Behavior changes come with tests, interface changes with a screenshot, and
  operator-visible changes with updated documentation and a line in
  `CHANGELOG.md`.
- **Security-relevant changes** (authentication, the broker, the access policy,
  systemd units, the installer) explain their effect on the threat model in
  [docs/architecture/security.md](docs/architecture/security.md).

If you are unsure whether an idea fits, open an issue before writing code.

## Licensing

Garrison is published under the [MIT license](LICENSE), and so is every
contribution. Stalwart and its WebUI are licensed under the AGPL, and their
Enterprise features under a commercial license, so Garrison cannot accept code
taken from them, translated from them or written while reading their source.
Use Stalwart's documentation and its observable behavior instead, and check it
with a contract test. Code from other projects must be compatible with MIT and
keep its notice, as `frontend/src/components/ui/LICENSE` does for shadcn/ui.
