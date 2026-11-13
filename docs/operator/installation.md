# Installation

Requirements: Linux on x86_64 or aarch64 with systemd 247 or newer and polkit
0.106 or newer (JavaScript rules), nginx (or another TLS reverse proxy), and
Stalwart 1.1.0 reachable on a loopback address of
the same host, natively or in a container in the host network. The release is
one static binary without runtime dependencies on the host.

Tested on 2026-11-11 in virtual machines from the distributions' own cloud
images, each with its access control as shipped: Debian 12 and 13, Ubuntu
24.04 and 26.04 (AppArmor); AlmaLinux 9 and 10, Rocky Linux 9 and 10, CentOS
Stream 10, Fedora 44 and openSUSE Leap 16.0 (SELinux enforcing); Amazon Linux
2023 (SELinux permissive), all on x86_64, and AlmaLinux 10 on aarch64. Ubuntu
22.04 is refused before anything changes: its polkit 0.105 has no JavaScript
rules. Debian 11 (polkit 0.105) and the RHEL 8 family (systemd 239) do not
meet the requirements either.

Garrison needs little of the host. Measured on 2026-11-13 in an AlmaLinux 10
container (x86_64) under 37 events a second for 30 minutes, the event
receiver held 16 MiB of memory, the broker 6 MiB and the web service 7 MiB,
which answered only health checks there; none of them grew. A collection run
takes about 4 MiB for a moment each minute. When host care asks the package
manager for pending updates, every six hours and after packages change, dnf
takes about 95 MiB for that moment. On disk, the event history stays within
`ingest.max_database_mib` (256 MiB by default). The metric history keeps
every minute of the last eight days, about 21 MiB with every check, and
ten-minute values before them: some 48 MiB at its 90 days
(`collector.history_days`, see [configuration](configuration.md)).

There are two ways to install. `garrison setup`, the way of the
[quick start](quickstart.md), asks for what steps 2 to 5 need and carries them
out. This page takes the same steps by hand and explains each one. By hand the
installer runs twice: step 1 installs the release and starts nothing, step 5
starts the services once Garrison is configured.

Step 1 also links Garrison's command into the search path, as
`/usr/bin/garrison`, so from then on `sudo garrison ...` works. The link points
to `/opt/garrison/current/bin/garrison` and follows every upgrade and
rollback. If another program of that name is there already, the installer
leaves it alone and says so; use the full path in that case.

## 1. Check and install the release

Take the archive of your architecture (`uname -m`) and its `.minisig`
signature. Check the signature with [minisign](https://jedisct1.github.io/minisign/)
(`apt install minisign`, `dnf install minisign` from EPEL on the RHEL family)
and the release signing key from the README:

```sh
minisign -Vm garrison-<version>-<arch>.tar.gz -P <release signing key>
```

It must end with `Trusted comment: garrison <version> <arch>`, naming the
release you downloaded. An archive that is not signed has only a checksum,
which tells a complete download from a broken one but not an archive someone
replaced:

```sh
sha256sum -c garrison-<version>-<arch>.tar.gz.sha256
```

Then unpack the archive and run the installer for the first time:

```sh
tar xzf garrison-<version>-<arch>.tar.gz
cd garrison-<version>-<arch>
sudo ./bin/garrison install
```

This first run creates five system users, installs the release into
`/opt/garrison/releases/<version>` without network access and copies an example
configuration to `/etc/garrison/garrison.toml`. It does not start anything yet,
because Garrison is not configured. The installer checks every file against
`SHA256SUMS` and refuses a release that holds anything else, such as an extra
file or a link.

`sbom.cdx.json` in the archive lists every component the release contains, with
versions, licenses and checksums, in the CycloneDX format that vulnerability
scanners read.

## 2. Configure

Edit `/etc/garrison/garrison.toml`. Start from the example; the file
explains every setting. See the [configuration reference](configuration.md)
and the [checks](checks.md) it can run.

At minimum set `public_origin`, `issuer` and `stalwart_url`. Then check it:

```sh
sudo garrison check-config
```

To see what the host already runs (Stalwart, ClamAV, reverse proxy,
certificate renewal, resolver, backups) and where its files are, run `detect`.
It only reads and changes nothing. With `--format toml` it prints provider
entries with the paths it found, to review and copy into the configuration:

```sh
sudo garrison detect
sudo garrison detect --format toml
```

Run it as root: without root, `ss` does not name the processes behind the
ports and some configuration files cannot be read.

Choose the modules this installation offers. The installer asks at a terminal
the first time, with what `detect` found switched on; later run:

```sh
sudo garrison modules
sudo garrison modules --set antivirus,backups --yes
```

It writes `modules = [...]` into the configuration, keeps the previous file as
`garrison.toml.previous` and restarts the broker and the web service. It
also offers the provider entries `detect` found for the chosen modules that the
configuration lacks (with `--set`, add `--adopt` for them); what is configured
already is not added twice.

## 3. Connect Stalwart

```sh
sudo garrison stalwart setup
```

It asks for a Stalwart administrator, a user name and password or an API key,
uses it for this run and stores it nowhere. From a script, pass the
administrator as JSON, `{"username": "...", "secret": "..."}` or
`{"apiKey": "..."}`: on standard input with `--admin-credential -`, or in a
root-only file with `--admin-credential FILE`, which it offers to delete
afterwards when it runs at a terminal.

This creates, and on repeated runs updates:

- a signed webhook that sends selected events to Garrison,
- two read-only API keys (broker, collector) usable only from loopback,
- the Prometheus exporter with its own scrape credential,
- Garrison as a registered OAuth client: sign-in only, no access to mail,
  and only back to its own callback. Stalwart's "client metadata documents"
  setting can stay disabled,
- where the configuration has a `[milter]` section, the macro filter's entry
  among Stalwart's milters (step 10).

All secrets go to `/etc/garrison/credentials/` (mode 0600).

At the end it tries both keys from this host. Stalwart in Docker or Podman
must use the host network (`--network host`, or `network_mode: host` with
Compose): in a bridge network Stalwart sees this host under the bridge's
gateway, refuses keys meant for loopback, and cannot reach Garrison's event
receiver, which accepts loopback only. `stalwart setup` then stops and says so.

## 4. Grant access

```sh
sudo garrison access init
```

This binds Stalwart's System Administrator role to Garrison's
`administrator` profile. Other roles get nothing until you bind them; see
[access.md](access.md).

## 5. Start

Run the installer a second time, in the unpacked release directory:

```sh
sudo ./bin/garrison install
```

This run installs the systemd units and the polkit rule, checks the
configuration and starts the services.

## 6. Publish through nginx

Garrison needs a host name of its own, such as `garrison.example.org`,
never the one of the Stalwart WebUI: a browser lets the scripts of one origin
act in everything else under that origin, including a signed-in Stalwart
administration. `check-config` refuses a shared origin.

Create the DNS record and a certificate for that name, then give it a server
block that serves nothing else. `garrison nginx` prints one for your names,
written for the nginx installed on this host, with the lines that belong in
Stalwart's server blocks:

```sh
sudo garrison nginx
```

For nginx 1.25.1 or newer it looks like this; older releases (Debian 12,
Ubuntu 24.04, the RHEL 9 family) need `listen 443 ssl http2;` instead of
`http2 on;`, which they refuse:

```nginx
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name garrison.example.org;
    ssl_certificate     /etc/letsencrypt/live/garrison.example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/garrison.example.org/privkey.pem;
    include /etc/nginx/snippets/garrison.conf;
}
```

```sh
sudo nginx -t && sudo systemctl reload nginx
```

On SELinux systems, such as the RHEL family, nginx may not connect to an
unlabelled port. The installer loads a small policy module, `garrison`, that
lets nginx reach Garrison's web port and nothing else (`semodule -l` lists it).

Garrison serves that whole host, laid out like Stalwart's: the interface under
`/admin/` (the root leads there), the API under `/api/` and the sign-in under
`/auth/`. A request that reaches it under another host name is redirected to
the same path on `public_origin`.

`stalwart setup` enables Stalwart's Prometheus exporter at `/metrics/`, with a
password; Garrison reads it on loopback. Keep it off the internet: add

```nginx
include /etc/nginx/snippets/garrison-stalwart-server*.conf;
```

at the server level of every server block that proxies to Stalwart, its mail
host and the Stalwart WebUI's host. The installer writes that file; it answers
`/metrics/` with 404.

Open `https://<public_origin>/admin/` and sign in with your Stalwart
account. Its menu ends with "Switch to Stalwart WebUI".

For the way back, add a "Switch to Garrison WebUI" row to the Stalwart WebUI:
include the generated file inside the location that serves it, in Stalwart's
server block, for example

```nginx
location ^~ /admin/ {
    proxy_pass http://127.0.0.1:8080;   # as in your existing Stalwart location
    include /etc/nginx/snippets/garrison-stalwart-switch*.conf;
}
```

Each user can turn both switch rows off in Garrison's settings; the row in
the Stalwart WebUI follows while that user is signed in to Garrison.

The installer writes that file with a hash of the script and reloads nginx when
it changes. The `*` keeps nginx valid when Garrison is not installed; the
row then simply does not appear. Nothing else in the Stalwart WebUI changes, and
if a Stalwart release changes its menu layout, the row is not shown.

## 7. Check the installation

```sh
sudo garrison doctor
```

It names every problem it finds, from a stopped service to a missing nginx
include, and what to do about it.

## 8. Include Garrison in backups

Run this before your backup job takes its snapshot, and back up the target
directory together with `/etc/garrison`:

```sh
sudo garrison backup --to /var/backups/garrison/latest
```

It copies all databases consistently while the services keep running. See
[operations.md](operations.md#backup-and-restore).

## 9. Notifications (optional)

Garrison can send a message when one of its checks fails or warns, when it is
in order again, and when the collector that makes the checks stops running:
to an [ntfy](https://ntfy.sh) topic, to a webhook, by mail, or to several of
them. For ntfy, add the topic to `/etc/garrison/garrison.toml`:

```toml
[notifications]
ntfy_url = "https://ntfy.example.org/mailserver"
```

ntfy does not have to run on this host: any topic you can publish to will do,
on a server of your own or on ntfy.sh. On ntfy.sh anyone who knows a topic's
name can read it, so choose a name nobody can guess. Then send a test
message; it says how each channel took it:

```sh
sudo garrison notify-test
```

A topic that needs an access token, the webhook, mail and what is sent when:
[configuration](configuration.md#notifications).

## 10. Macro filter (optional)

Garrison watches and reports; it changes nothing in the mail flow. The one
exception is a filter that has Stalwart refuse or mark mail with Office
documents that carry macros. It is off until you add a `[milter]` section to
`/etc/garrison/garrison.toml` and run:

```sh
sudo garrison stalwart setup
```

Setup starts the filter, makes sure it answers and only then tells Stalwart
of it. Then send the server a mail from outside and see that it arrives. To
switch it off again, remove the section and run the same command; keep to
that order. What the filter finds, what it does not, and its settings:
[configuration](configuration.md#milter).

## Unattended installation

Nothing asks a question unless standard input and standard output are both a
terminal, so the same steps run from cloud-init, Ansible or a shell script.
Every command exits with 0 on success and 1 on failure, with the reason on
standard error; 2 means it was called wrongly or found no usable
configuration.

```sh
tar xzf garrison-<version>-<arch>.tar.gz
./garrison-<version>-<arch>/bin/garrison install < /dev/null    # installs, starts nothing
install -m 644 garrison.toml /etc/garrison/garrison.toml        # your configuration
garrison modules --set antivirus,backups --yes                  # instead of the question
printf '%s' "$STALWART_ADMIN_JSON" |                            # {"username": "...", "secret": "..."}
    garrison stalwart setup --admin-credential -
garrison access init
./garrison-<version>-<arch>/bin/garrison install < /dev/null    # starts the services
garrison doctor
```

Keep the administrator's secret out of command lines and files: it goes in on
standard input and is used for this one call.

For Ansible, every release carries the role `garrison` in
`deploy/ansible/` ([its README](../../deploy/ansible/README.md)): it checks the
signature on the control node, installs, configures, connects Stalwart and
upgrades when you change the version.
