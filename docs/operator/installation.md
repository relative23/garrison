# Installation

Requirements: Linux on x86_64 or aarch64 with systemd 247 or newer and polkit
0.106 or newer (JavaScript rules), nginx (or another TLS reverse proxy), and
Stalwart 1.1.0 reachable on a loopback address of
the same host, natively or in a container in the host network. The release is
one static binary without runtime dependencies on the host. It goes to
`/opt/garrison`, which may be a link to another disk, but not one under
`/home`, `/root`, `/tmp` or `/var/tmp`, which Garrison's services do not see.

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
`/opt/garrison/releases/<version>` without network access, together with its
systemd units, and copies an example configuration to
`/etc/garrison/garrison.toml`. It does not start anything yet, because
Garrison is not configured; the polkit rule for the maintenance actions and
the nginx includes made from the configuration follow in step 5. The
installer checks every file against `SHA256SUMS` and refuses a release that
holds anything else, such as an extra file or a link.

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

This creates, and on repeated runs updates where it differs from what was
asked:

- a signed webhook that sends selected events to Garrison, with a header
  (`X-Garrison-Key`) that names its signature key by a hash, since Stalwart
  shows no key,
- two read-only API keys (broker, collector) usable only from loopback,
- the Prometheus exporter with its own scrape credential,
- Garrison as a registered OAuth client: sign-in only, no access to mail,
  and only back to its own callback. Stalwart's "client metadata documents"
  setting can stay disabled,
- where the configuration has a `[milter]` section, the macro filter's entry
  among Stalwart's milters (step 10).

A run that finds all of it as asked changes nothing and says "Stalwart is set
up as asked; nothing was changed."

All secrets go to `/etc/garrison/credentials/` (mode 0600), which is root's:
run setup as root. A file there that other users may read gets a new
secret, since its old one may have been seen. Where it cannot write there,
it stops before it asks for the administrator, and nothing is changed.

It tries each key from this host as soon as it has made or updated it.
Stalwart in Docker or Podman must use the host network (`--network host`, or
`network_mode: host` with Compose): in a bridge network Stalwart sees this
host under the bridge's gateway, refuses keys meant for loopback, and cannot
reach Garrison's event receiver, which accepts loopback only. `stalwart setup`
then stops and says so.

## 4. Grant access

```sh
sudo garrison access init
```

This binds Stalwart's System Administrator role to Garrison's
`administrator` profile. Other roles get nothing until you bind them; see
[access.md](access.md). Where it finds no role with all of an
administrator's rights, it names the rights each of Stalwart's
administrator roles lacks: give them to the role in Stalwart, then bind it
as it says.

## 5. Start

Run the installer a second time, in the unpacked release directory:

```sh
sudo ./bin/garrison install
```

This run checks the configuration, writes the polkit rule for its
`[[actions]]`, the nginx include for its `web.port` and the include for the
switch row (step 6), and starts the services. Where the configuration does
not load, the installer says which of these files it could not write and
why, as `garrison check-config` would.

## 6. Publish through nginx

Garrison needs a host name of its own, such as `garrison.example.org`,
never the one of the Stalwart WebUI: a browser lets the scripts of one origin
act in everything else under that origin, including a signed-in Stalwart
administration. `check-config` refuses a shared origin.

Create the DNS record and a certificate for that name, then give it a server
block that serves nothing else. `garrison nginx` prints one for your names,
on the port `public_origin` names (443 where it names none), written for the
nginx installed on this host, with the lines that belong in
Stalwart's server blocks and, as optional ones, those of
[client addresses for Stalwart's limits](#client-addresses-for-stalwarts-limits):

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

The installer writes that include for the configured `web.port`;
`garrison nginx --snippet` prints it.

On SELinux systems, such as the RHEL family, nginx may not connect to an
unlabelled port. The installer loads a small policy module, `garrison`, that
lets nginx reach Garrison's web port and nothing else (`semodule -l` lists it).

Garrison serves that whole host, laid out like Stalwart's: the interface under
`/admin/` (the root leads there), the API under `/api/` and the sign-in under
`/auth/`. A request that reaches it under another host name or port is
redirected to the same path on `public_origin`.

`stalwart setup` enables Stalwart's Prometheus exporter at `/metrics/`, with a
password; Garrison reads it on loopback. Keep it off the internet: add

```nginx
include /etc/nginx/snippets/garrison-stalwart-server*.conf;
```

at the server level of every server block that proxies to Stalwart, its mail
host and the Stalwart WebUI's host. The installer writes that file; it answers
`/metrics/` with 404.

Open `https://<public_origin>/admin/` and sign in with your Stalwart
account. Its menu ends with "Switch to Stalwart WebUI" once you turn the
switch rows on in Settings.

For the way back, add a "Switch to Garrison WebUI" row to the Stalwart WebUI:
include the generated file inside the location that serves it, in Stalwart's
server block, for example

```nginx
location ^~ /admin/ {
    proxy_pass http://127.0.0.1:8080;   # as in your existing Stalwart location
    include /etc/nginx/snippets/garrison-stalwart-switch*.conf;
}
```

Both switch rows stay hidden until a user turns them on in Garrison's
settings; the row in the Stalwart WebUI then shows while that user is signed
in to Garrison. It needs both host names under one registered domain, such
as `garrison.example.org` and `mail.example.org`: only then does the browser
send Garrison's session cookie with the row's question to Garrison. With two
different domains the row does not appear.

The installer writes that file with a hash of the script and reloads nginx when
it changes. The `*` keeps nginx valid when Garrison is not installed; the
row then simply does not appear. Nothing else in the Stalwart WebUI changes, and
if a Stalwart release changes its menu layout, the row is not shown.

### Client addresses for Stalwart's limits

Stalwart answers no more than 100 unauthenticated requests a minute from
one address, failed sign-ins among them, and blocks an address after 100
failed passwords in a day, both by the address a request comes from.
Behind nginx that is nginx's: where nginx and Stalwart share this host,
127.0.0.1, which Stalwart neither limits nor blocks, so password guesses
at its sign-in page go unlimited; where Stalwart sees nginx under another
address, as with nginx on another host or Stalwart in a container behind
a published port, one address that every client shares, so one client's
guesses lock out everyone. A failed sign-in at Stalwart's page shows in
Garrison's event history with the address Stalwart counted it under.

To have Stalwart count and block each client under its own address:

1. In nginx's `http` block, for example as
   `/etc/nginx/conf.d/stalwart-forwarded-for.conf`:

   ```nginx
   # Stalwart refuses (400) a request that names a loopback address,
   # so a client on this host itself is not named.
   map $remote_addr $stalwart_forwarded_for {
       ~^(127\.|::1$|::ffff:127\.)  "";
       default                     $proxy_add_x_forwarded_for;
   }
   ```

   and in every location that proxies to Stalwart:

   ```nginx
   proxy_set_header X-Forwarded-For $stalwart_forwarded_for;
   ```

   nginx passes a `proxy_set_header` of the server level only into a
   location that sets none of its own, and Stalwart's locations set `Host`,
   so the line belongs in each of them; Garrison's include does not set it.
2. In the Stalwart WebUI, open Settings (the sliders at the foot of the
   menu), then Network → HTTP → General. Under Proxy, set "Client IP
   source" to "X-Forwarded-For header", keep "Trusted proxy hops" at 1 and
   save. Stalwart takes the change once you run Management → Actions →
   Server settings (under Reload).
3. Let nothing but nginx and Garrison reach Stalwart's HTTP listeners (keep
   them on 127.0.0.1, or behind a firewall): a client that reaches one
   directly names any address it likes and so meets no limit at all.
4. Give a block an end: Settings → Security → Settings, "Authentication
   failure ban", "Duration", and save. As with the client IP source,
   Stalwart takes it once you run Management → Actions → Server settings;
   until then, and for a block made before, a block has no end. Without
   one, a blocked address stays blocked until it is removed under
   Settings → Security → Blocked IPs, followed by Management → Actions →
   Blocked IPs list.

Stalwart then counts and blocks each client under its own address, an
IPv6 client too, and that address alone: the other addresses of its
network, also those of its IPv6 /64, are neither limited nor blocked with
it. A blocked client gets 403 for everything of Stalwart's that nginx
forwards, its sign-in page and the WebUI included, which a browser shows
as `{"detail":"Forbidden",...}`, and Stalwart closes the connections that
address opens to its mail listeners too, SMTP, submission, IMAP, POP3 and
ManageSieve, with TLS and without, so a mail program there is turned away
as well. Garrison's own pages, and a Garrison session begun before the
block, go on working. Once the duration is over, Stalwart answers the
address again by itself; its list of blocked IPs goes on showing the
block, with its end.

Garrison's event history then names each client's own address, for every
failed sign-in at Stalwart's page and for every block Stalwart makes, in
the Event history and on Attacks & bans. It records no successful
sign-in; Stalwart's own log names one under the address of the
connection, nginx's, also with forwarding.

Garrison names the user's address when it exchanges a sign-in code. Its
other requests carry a token or its key and count under its own address,
which Stalwart on this host neither limits nor blocks.

Where Stalwart sees nginx under another address than 127.0.0.1, as in a
container behind a published port, nginx's map still names no client that
nginx sees at loopback, such as one through an SSH tunnel to this host:
Stalwart counts it under nginx's address, as it counts everything that
reaches it through the published port without a forwarded address. 100
failed passwords from such clients in a day block nginx's address, and
Stalwart then closes every connection from it: nginx answers every client
502, whatever address it forwards, and nothing reaches Stalwart through
the published port, until the block ends or is removed. Add that address,
which Stalwart's log names as the `remoteIp` of such requests, under
Settings → Security → Allowed IPs, then run Management → Actions →
Blocked IPs list and Server settings: Stalwart then neither limits nor
blocks it, as it does 127.0.0.1, and still counts each client that nginx
names under its own address.

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
name can read it, so choose a name nobody can guess. Every user of this host
may read `garrison.toml`, so keep the address of such a topic out of it:
write the address into `/etc/garrison/credentials/ntfy-url` and set
`ntfy_url = "credential:ntfy-url"` instead
([configuration](configuration.md#an-address-that-is-a-secret)). A topic
that takes an access token needs neither. Then send a test message; it says
how each channel took it:

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
configuration. `doctor` and `self-check` write their whole report on
standard output, failures among it, and end with 1 where it holds one. Run
without root, `doctor`, `notify-test`, `setup` and `stalwart setup` exit
with 2, and `install`, `upgrade`, `restore` and `uninstall` with 1.

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
upgrades when you change the version, and the next play finishes one that
stopped on the way.
