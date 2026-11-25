# State names

What a command of Garrison refuses, the outcomes a script acts on and every
line of `garrison doctor` end with a name in brackets, such as
`[install-no-room]`: the name of that state. The name stays from release to
release while the sentence before it may change, so a script looks for the
name, never for the sentence. A release that no longer has one of these
states says so in the changelog.

This page lists every state with an example of its line, as the release
writes it. What an example names (paths, units, numbers, versions, accounts)
stands for what the command finds on your host, and `…` for words left out
here. An indented last line is what mends the state. A line may carry the
line of another state inside it, with that state's name: the state's own name
is the last one.

## The installer

`garrison install`, also with `--rollback` and `--restore-state`,
`garrison restore` and `garrison uninstall`.
Names begin with `install-…`.

```text
/opt/garrison: Permission denied (os error 13) [install-io]
```
```text
Another garrison install is already running; try again when it has finished. [install-busy]
```
```text
Run as root. [install-not-root]
```
```text
/usr/bin/systemd-sysusers is required. [install-tool-missing]
```
```text
systemd 239 is too old: Garrison's units need systemd 247 or newer. [install-old-systemd]
```
```text
`systemctl --version` names no systemd version. [install-systemd-unknown]
```
```text
polkit 0.105 has no JavaScript rules: Garrison needs polkit 0.106 or newer. [install-old-polkit]
```
```text
polkit is required for service actions, with JavaScript rules (polkit 0.106 or newer, /etc/polkit-1/rules.d). [install-no-polkit]
```
```text
/opt/garrison leads to /home/garrison, which lies under /home; nothing was changed. [install-base-hidden]
```
```text
/opt has 29 MiB free and the installation needs 512 MiB; nothing was changed. [install-no-room]
```
```text
/var/lib/garrison/collector has 3 MiB free and the copies from before the upgrade need 5 MiB there; free space there [install-copies-no-room]
```
```text
SHA256SUMS is missing; this is not a complete release. [install-sums-missing]
```
```text
SHA256SUMS is malformed. [install-sums-malformed]
```
```text
SHA256SUMS lists "../VERSION", which is no file of a release; nothing was installed. [install-sums-outside]
```
```text
SHA256SUMS lists VERSION twice; nothing was installed. [install-sums-twice]
```
```text
static/etc is not a regular file; nothing was installed. [install-not-a-file]
```
```text
Checksum mismatch for static/index.html; nothing was installed. [install-checksum-mismatch]
```
```text
static/extra.js is not listed in SHA256SUMS; nothing was installed. [install-unlisted]
```
```text
VERSION "../../etc" is not a release version; nothing was installed. [install-bad-version]
```
```text
Garrison 0.2.0 is running. [install-running]
      Roll back with: garrison install --rollback
```
```text
Garrison 0.2.0 is running as installed; nothing was changed. [install-as-installed]
```
```text
The release is installed, but Garrison is not configured yet.

  1. Edit /etc/garrison/garrison.toml (origins, providers, actions).
     `garrison detect` shows what this host runs, and
     `garrison modules` chooses the modules this installation offers.
  2. Create the Stalwart objects (webhook, API keys, metrics):
       garrison stalwart setup        (asks for a Stalwart administrator)
  3. Create the access policy:   garrison access init
  4. Check everything:           garrison check-config
  5. Run the installer again to start the services.
  6. Give Garrison a host name of its own (never Stalwart's):
     `garrison nginx` prints its server block and the lines for Stalwart's.
     Add
       include /etc/nginx/snippets/garrison-stalwart-server*.conf;
     to every server block that proxies to Stalwart: it keeps the metrics
     exporter that step 2 turns on off the internet.

The command is available as garrison. [install-not-configured]
```
```text
check-config failed; the running release was not touched [install-config-refused]
```
```text
backup failed: /var/backups/garrison: Not a directory (os error 20) [install-backup-failed]
```
```text
backup failed: Cannot load /etc/garrison/garrison.toml: unknown field `modules`; 0.1.1, the release that runs, makes the backup before the upgrade and cannot load /etc/garrison/garrison.toml: take out the settings it does not know, upgrade, then put them back [install-backup-unloadable]
```
```text
garrison-web.service restarted 3 times within 8 s of starting [install-restarting]
```
```text
garrison-web.service is unknown within 8 s of starting [install-not-active]
```
```text
Start failed; switching back to the previous release. [install-switching-back]
```
```text
The new release had changed what the release that ran cannot read. These went back to their copies in /var/backups/garrison/pre-upgrade-20261124T080000: collector. [install-went-back] The other databases keep their data. [install-migrated-back]
```
```text
0.1.2 cannot read the current state, as its self-check says of collector (schema 3, integrity ok) [install-unreadable-state]
```
```text
Garrison 0.2.0 did not start (garrison-web.service restarted 3 times within 8 s of starting [install-restarting]); the previous release is running. See the journal. [install-switched-back]
```
```text
Garrison 0.2.0 did not start (garrison-web.service restarted 3 times within 8 s of starting [install-restarting]); switching back to 0.1.2 failed (/var/lib/garrison/collector has 3 MiB free and the copies from before the upgrade need 5 MiB there; free space there [install-copies-no-room]). `garrison install --rollback --restore-state` returns to it with the state from before the upgrade. See the journal. [install-switch-back-failed]
```
```text
Garrison 0.2.0 did not start (garrison-web.service restarted 3 times within 8 s of starting [install-restarting]); the previous release did not start either (garrison-web.service restarted 3 times within 8 s of starting [install-restarting]), and the links could not be set back (/opt/garrison/current: Read-only file system (os error 30) [install-io]). These went back to their copies in /var/backups/garrison/pre-upgrade-20261124T080000: collector. [install-went-back] See the journal. [install-previous-failed]
```
```text
Garrison 0.2.0 did not start (garrison-web.service restarted 3 times within 8 s of starting [install-restarting]); 0.1.2 did not run when this run began, so it was not started again; `garrison install --rollback` returns to it. See the journal. [install-not-restarted]
```
```text
Garrison 0.2.0 did not start (garrison-web.service restarted 3 times within 8 s of starting [install-restarting]); it was stopped; `garrison install --rollback` returns to 0.1.2. See the journal. [install-stopped]
```
```text
nginx -t failed; snippets updated but nginx was not reloaded:
nginx: [emerg] unknown directive "x" [install-nginx-not-reloaded]
```
```text
/etc/polkit-1/rules.d/50-garrison.rules was not written, since `garrison polkit-rule` failed: Cannot load /etc/garrison/garrison.toml: unknown key [install-unwritten]
```
```text
/srv/access.json, the access policy that broker.policy names, belongs to the user with ID 65534, not to root: the installer makes no other user's file the policy, and the broker takes none. Where it is the policy you mean, `chown root /srv/access.json` and run this again. Nothing was changed. [install-policy-foreign]
```
```text
/usr/bin/garrison is something else and was left alone; Garrison's command is /opt/garrison/current/bin/garrison. [install-link-taken]
```
```text
/usr/bin/garrison could not be made (Read-only file system (os error 30)); Garrison's command is /opt/garrison/current/bin/garrison. [install-link-failed]
```
```text
The SELinux module did not load, so nginx may not reach Garrison: libsemanage: conflict. `setsebool -P httpd_can_network_connect 1` allows it more broadly. [install-selinux-failed]
```
```text
The macro filter stays on the port it listens on, which garrison.toml no longer names: Stalwart asks its milter entry m1 at 127.0.0.1:8096 [install-milter-asked]. `garrison stalwart setup` moves it to port 8097. [install-milter-held]
```
```text
Stalwart asks its milter entry m1 at 127.0.0.1:8096 [install-milter-asked]
```
```text
Stalwart's milters could not be asked (Stalwart: connection refused [install-io]) [install-milter-unasked]
```
```text
where garrison-milter.service listens cannot be seen [install-milter-unseen]
```
```text
/etc/garrison/garrison.toml does not load, so Stalwart's milters cannot be asked [install-milter-unloaded]
```
```text
The macro milter, which the configuration no longer has, keeps running: Stalwart asks its milter entry m1 at 127.0.0.1:8096 [install-milter-asked]. Run `garrison stalwart setup`: it takes the filter out of Stalwart and stops it. [install-milter-kept]
```
```text
Stalwart still asks Garrison's macro milter about every message, as far as this host can tell, and would defer mail without it: Stalwart asks its milter entry m1 at 127.0.0.1:8096 [install-milter-asked]; nothing was changed. Remove the [milter] section from /etc/garrison/garrison.toml, run `garrison stalwart setup` and uninstall then. [install-milter-still-asked]
```
```text
There is no previous release to return to. [install-no-previous]
```
```text
There is no other release to return to: /opt/garrison/previous names the release /opt/garrison/current names. A rollback cut short is finished by the installer its first line named. [install-no-other-release]
```
```text
There is no state from before an upgrade to restore (/var/backups/garrison/last-pre-upgrade); nothing was changed. [install-no-state]
```
```text
The state in /var/backups/garrison/pre-upgrade-20261124T080000 was written by Garrison 0.2.0, which is newer than 0.1.2; 0.1.2 cannot read it. Nothing was changed. [install-state-newer]
```
```text
The group garrison-broker, which reads the access policy, does not exist; the installer makes it. Nothing was changed. [install-no-broker-group]
```
```text
0.1.2 cannot load /etc/garrison/garrison.toml:
Configuration not usable: unknown field `modules`
Remove the settings 0.1.2 does not know, or put back the file from before the upgrade (/var/backups/garrison/last-pre-upgrade/etc/garrison.toml), then roll back. [install-rollback-unloadable]
```
```text
0.1.2 cannot read the current data, as its self-check says of collector (schema 3, integrity ok). Roll back with --restore-state to return to the data from before the upgrade. [install-rollback-unreadable]
```
```text
The access policy from before the upgrade, in /var/backups/garrison/pre-upgrade-20261124T080000, does not suit /etc/garrison/garrison.toml, as 0.1.2's check-config says:
Access policy not usable: unknown actions
Nothing was changed. [install-rollback-policy]
```
```text
Rolling back to 0.1.2. [install-rolling-back]
      If this is interrupted, run it again: /opt/garrison/releases/0.2.0/bin/garrison install --rollback
```
```text
The rollback failed (garrison-web.service restarted 3 times within 8 s of starting [install-restarting]); 0.1.2 is stopped. See the journal. [install-rollback-stopped]
```
```text
The rollback failed (garrison-web.service restarted 3 times within 8 s of starting [install-restarting]); the release that ran before is running again. These went back to their copies in /var/backups/garrison/pre-upgrade-20261124T080000: web, the access policy. Removed, as they did not exist then: broker. [install-went-back] See the journal. [install-rollback-returned]
```
```text
The rollback failed (garrison-web.service restarted 3 times within 8 s of starting [install-restarting]); the release that ran before did not start either. See the journal. [install-rollback-neither]
```
```text
Rolled back to 0.1.2. [install-rolled-back]
```
```text
These went back to their copies in /var/backups/garrison/pre-upgrade-20261124T080000: web, the access policy. Removed, as they did not exist then: broker. [install-went-back]
```
```text
/root/kept is no backup that `garrison backup` wrote (no backup.json there); nothing was changed. [install-not-a-backup]
```
```text
The copies in /root/kept did not pass `garrison self-check --state`; nothing was changed.
{"result": "failed"} [install-copies-refused]
```
```text
Garrison 0.2.0's check-config refuses /etc/garrison/garrison.toml; nothing was changed:
Configuration not usable: [x] [install-restore-config-refused]
```
```text
The access policy in /root/kept does not suit /etc/garrison/garrison.toml, as Garrison 0.2.0's check-config says; nothing was changed:
Access policy not usable: unknown actions [install-restore-policy]
```
```text
The state as it is could not be backed up (/var/backups/garrison: File exists (os error 17)); nothing was changed. [install-keep-failed]
```
```text
Restored the state from /root/kept; Garrison 0.2.0 is running. Users sign in again: a backup holds no sessions. The state from before is in /var/backups/garrison/pre-restore-20261124T080000. [install-restored]
```
```text
The restore failed (The group garrison-broker, which reads the access policy, does not exist; the installer makes it. Nothing was changed. [install-no-broker-group]); Garrison is running with what could be put back. The state from before is in /var/backups/garrison/pre-restore-20261124T080000. [install-restore-failed]
```
```text
The restore failed (garrison-web.service restarted 3 times within 8 s of starting [install-restarting]); Garrison did not start either. The state from before is in /var/backups/garrison/pre-restore-20261124T080000. [install-restore-neither]
```
```text
The state was put back, but Garrison did not start (garrison-web.service restarted 3 times within 8 s of starting [install-restarting]). The state from before is in /var/backups/garrison/pre-restore-20261124T080000; see the journal. [install-restore-unstarted]
```
```text
broker.policy names /etc/garrison-link/access.json, which is not a file of its own; it was left as it is [install-policy-left]
```
```text
broker.policy names /, which is no file's name [install-policy-nameless]
```
```text
broker.policy names /etc/garrison-link/access.json, which is not a file of its own: the access policy goes back only as a file, never through a link or into a folder. Nothing was changed. [install-policy-place]
```
```text
The folder of broker.policy, /srv/absent, does not exist. Nothing was changed. [install-policy-folder]
```
```text
Access policy not usable: broker.policy is /home/admin/access.json, under /home. Move it. Nothing was changed. [install-policy-hidden]
```
```text
/etc/garrison/garrison.toml does not load, so an access policy it names outside /etc/garrison is not removed (unknown field `nonsense`); remove it yourself if there is one. [install-policy-unknown]
```
```text
/usr/bin/unshare (util-linux) is needed to test nginx without Garrison's snippets; nothing was changed [install-needs-unshare]
```
```text
nginx would not start without Garrison's snippets; nothing was changed. Remove the `include /etc/nginx/snippets/garrison…` lines from your server blocks first:
nginx: [emerg] open() "/etc/nginx/snippets/garrison.conf" failed [install-nginx-invalid]
```

## Upgrade

`garrison upgrade`, before it hands over to the new release's installer.
Names begin with `upgrade-…`.

```text
/root/garrison-0.2.0-x86_64.tar.gz.minisig: No such file or directory (os error 2). Nothing was installed. [upgrade-io]
```
```text
Run as root. Nothing was installed. [upgrade-not-root]
```
```text
/root/release.tgz is not named like a release archive, garrison-<version>-<arch>.tar.gz. Nothing was installed. [upgrade-not-an-archive]
```
```text
garrison-0.2.0-aarch64.tar.gz is built for aarch64, this host is x86_64. Nothing was installed. [upgrade-other-architecture]
```
```text
0.1.2 is older than the running 0.2.0; go back with `garrison install --rollback` instead. Nothing was installed. [upgrade-older-archive]
```
```text
latest or 0.2.0 is no semantic version. Nothing was installed. [upgrade-no-version]
```
```text
Run the installed release: /opt/garrison/current/bin/garrison upgrade <archive>. Nothing was installed. [upgrade-not-installed]
```
```text
This release trusts no signing key yet, so it cannot check an archive. Check the archive by hand (docs/operator/installation.md) and run its own installer. Nothing was installed. [upgrade-no-keys]
```
```text
"not a key" is not a minisign public key. Nothing was installed. [upgrade-bad-key]
```
```text
The signature file is not a minisign signature. Nothing was installed. [upgrade-not-a-signature]
```
```text
The archive does not match its signature, or no key this release trusts made it. Nothing was installed. [upgrade-signature-mismatch]
```
```text
The signature is for "garrison 0.1.0 x86_64", not for "garrison 0.2.0 x86_64". Nothing was installed. [upgrade-other-release]
```
```text
tar is required. Nothing was installed. [upgrade-no-tar]
```
```text
The archive cannot be unpacked: gzip: stdin: not in gzip format. Nothing was installed. [upgrade-unpack-failed]
```

## Setup of Stalwart

`garrison stalwart setup`, also with `--rotate`.
Names begin with `setup-…`.

```text
Name the Stalwart administrator: run this at a terminal to be asked, or pass --admin-credential - with the JSON on standard input, or --admin-credential FILE. [setup-no-administrator]
```
```text
Protected file is unavailable: /root/admin.json. Run `garrison stalwart setup` again once this is mended. [setup-file-unread]
```
```text
standard input: Input/output error (os error 5) [setup-input-unread]
```
```text
The administrator on standard input is too long. [setup-administrator-too-long]
```
```text
invalid JSON: expected value at line 1 column 1 [setup-administrator-not-json]
```
```text
The administrator needs {"username","secret"} or {"apiKey"} [setup-administrator-unusable]
```
```text
/usr/bin/systemd-ask-password: No such file or directory (os error 2) [setup-ask-failed]
```
```text
No secret was entered; nothing was changed. [setup-no-secret]
```
```text
Setup cannot write the credentials folder /etc/garrison/credentials: Permission denied (os error 13). Run it as root, as `sudo garrison stalwart setup`; nothing was changed. [setup-not-root]
```
```text
Setup cannot write the credentials folder /etc/garrison/credentials: Read-only file system (os error 30). Nothing was changed; run `garrison setup` again once this is mended. [setup-folder-unwritable]
```
```text
invalid network nonsense [setup-network-invalid]
```
```text
172.17.0.1/16 has host bits set [setup-network-host-bits]
```
```text
x:ApiKey/get: Stalwart is unavailable [setup-call-failed]
```
```text
x:ApiKey/get: Stalwart refused the request for its limit of requests (HTTP 429), whose window is a minute unless it was set otherwise [setup-limited]
```
```text
Stalwart refused the administrator (HTTP 401): check the user name and the password, or the API key. Run `garrison stalwart setup` again once this is mended. [setup-administrator-refused]
```
```text
Stalwart refused the administrator from this host's address (HTTP 403): its API key may not allow that address. [setup-administrator-refused-here]
```
```text
x:WebHook/get: malformed answer, which this release of Garrison does not read; see the supported Stalwart releases in the README [setup-unreadable]
```
```text
x:MtaMilter/get: forbidden Forbidden [setup-stalwart-error]
```
```text
x:WebHook/set: {"new":{"type":"invalidProperties","properties":["url"]}}; the receiver may refuse Stalwart's batches until setup runs again, and Stalwart sends them again for an hour [setup-signature-pending]. Run `garrison stalwart setup --rotate` again once this is mended. [setup-stalwart-refused]
```
```text
This build of Garrison would ask Stalwart for the event smtp.raw-input, which Garrison must never record, so the webhook was not changed. Install Garrison again from its release archive. [setup-event-forbidden]
```
```text
Could not write /etc/garrison/credentials/broker-native-key: Permission denied (os error 13); the new API key was taken out of Stalwart again [setup-unwritten]
```
```text
getrandom: this target is not supported [setup-no-random]
```
```text
Asking Stalwart whose API key /etc/garrison/credentials/broker-native-key holds: Stalwart refused the request for its limit of requests (HTTP 429), whose window is a minute unless it was set otherwise [setup-key-owner-unknown]
```
```text
Stalwart does not show the administrator the account that the API key in /etc/garrison/credentials/broker-native-key belongs to: run setup as an administrator who holds the keys' permissions, as one with Stalwart's administrator role (x:ApiKey/get: accountNotFound The accountId does not correspond to a valid account [setup-stalwart-error]) [setup-account-unseen]
```
```text
Stalwart takes no more API keys in the administrator's account, which holds 'garrison broker', 'backup': setup makes a new key before it removes the one it replaces. Remove a key the account no longer needs in the Stalwart WebUI; setup made no new key 'garrison broker' and removed none [setup-account-full]
```
```text
Stalwart refused the administrator the API key 'garrison broker', since it may not grant the key's permissions: run setup as an administrator who holds them, as one with Stalwart's administrator role (x:ApiKey/set: {"new":{"description":"You are not authorized to grant permissions: sysRoleGet","type":"forbidden"}} [setup-stalwart-refused]) [setup-key-not-granted]
```
```text
Stalwart did not return the new API key secret [setup-key-secret-missing]
```
```text
Trying broker-native-key: The endpoint did not answer [setup-key-untried]
```
```text
Stalwart does not take the API key in broker-native-key (HTTP 401) [setup-key-untaken]
```
```text
Stalwart refuses the API key in broker-native-key from this host (HTTP 403): it sees this host at an address the key does not allow. That happens when Stalwart runs in a Docker or Podman bridge network; run it in the host network instead (docker run --network host, or network_mode: host with Compose). Run `garrison stalwart setup --rotate` again once this is mended. [setup-key-refused-here]
```
```text
Restart garrison-broker so it reads the new secret. [setup-restart-asked] Until then it holds the API key the new one replaces, which stays in Stalwart [setup-old-key-kept]
```
```text
garrison-milter.service runs, but setup cannot see where it listens, so it cannot tell which of Stalwart's entries ask it. Nothing was changed [setup-milter-unseen]
```
```text
The macro milter cannot move to 127.0.0.1:8097 (Address already in use (os error 98)). Nothing was changed: free that port, or give the filter another [setup-milter-port-taken]
```
```text
The macro milter does not answer on 127.0.0.1:8096 (Connection refused (os error 111)): while Stalwart asks it there, it defers all incoming mail. `journalctl -u garrison-milter.service -n 20` shows why it does not run. [setup-milter-silent]
```
```text
Stalwart asks a milter at 127.0.0.1:11332 (entry o), where nothing answers: Stalwart defers all incoming mail [doctor-milter-stranded]
      If nothing is to answer there, remove that entry in the Stalwart WebUI (Settings ▸ MTA ▸ Milters) and reload its settings.
Setup changed nothing. Run `garrison stalwart setup` again once this is mended. [setup-milter-stranded]
```
```text
Stalwart does not let the administrator read its milter entries: run setup as an administrator who holds the keys' permissions, as one with Stalwart's administrator role (x:MtaMilter/get: forbidden Forbidden [setup-stalwart-error]) [setup-milters-unreadable]
```
```text
Stalwart is set up as asked; nothing was changed. [setup-as-asked]
```
```text
Settings reloaded. garrison-ingest restarted with the new secret. [setup-restarted] [setup-reloaded]
```
```text
Restart garrison-ingest and garrison-broker so they read the new secrets. [setup-restart-asked]
```
```text
garrison-broker reads the new secret when it starts. [setup-read-at-start]
```
```text
garrison-ingest restarted with the new secret. [setup-restarted]
```
```text
the receiver may refuse Stalwart's batches until setup runs again, and Stalwart sends them again for an hour [setup-signature-pending]
```
```text
the exporter may refuse the collector's scrape until setup runs again [setup-scrape-pending]
```

## Setup at a terminal

`garrison setup`, which asks step by step.
Names begin with `wizard-…`.

```text
standard input: Input/output error (os error 5) [wizard-io]
```
```text
The setup was ended; run `garrison setup` again to continue. [wizard-ended]
```
```text
The addresses cannot be written into /etc/garrison/garrison.toml: its deployment table is not one [deployment] section with a line for each, as dotted keys write it. Write public_origin = "https://garrison.example.org", issuer = "https://mail.example.org", stalwart_url = "http://127.0.0.1:8080" and admin_url = "https://mail.example.org/admin/" under [deployment] there, then run `garrison setup` again. [wizard-addresses-unwritable]
```
```text
Creating the access policy did not succeed; fix the cause above and run `garrison setup` again. [wizard-step-failed]
```
```text
Connecting Stalwart did not succeed. [wizard-stalwart-unconnected]
```
```text
Starting Garrison failed: Another install runs. [install-busy]; run `garrison setup` again. [wizard-start-failed]
```
```text
Run as root. [wizard-not-root]
```
```text
garrison setup asks questions at a terminal; without one, follow "Unattended installation" in docs/operator/installation.md. [wizard-no-terminal]
```
```text
Install the release first: ./bin/garrison install in the unpacked archive. [wizard-not-installed]
```

## Doctor

`garrison doctor` puts its level before each line: `ok`, `warn` or `FAIL`.
It exits with 1 when a line fails.
Names begin with `doctor-…`.

```text
Run as root: the checks read files only root may read. [doctor-not-root]
```
```text
All 30 checks are in order. [doctor-summary-in-order]
```
```text
0 problems, 1 warning, 1 unknown, of 30 checks. [doctor-summary-no-problem]
```
```text
2 problems, 0 warnings, 0 unknown, of 30 checks. [doctor-summary-problems]
```
```text
issuer is still the placeholder https://mail.example.org [doctor-origin-placeholder]
      Set the real address in /etc/garrison/garrison.toml.
```
```text
broker.socket is /run/broker.sock, but garrison-broker.socket listens on /run/garrison/broker.sock [doctor-setting-unfollowed]
      Remove the setting.
```
```text
broker.native_key is credential:key, but garrison-broker.service loads this secret only as credential:broker-native-key [doctor-secret-unloaded]
      Write broker.native_key = "credential:broker-native-key".
```
```text
providers[1].lists names zen.dq.spamhaus.net [doctor-dqs-list-unasked]
      Set collector.dqs_key.
```
```text
providers[1].lists names ….sbl.dq.spamhaus.net with the key [doctor-dqs-key-in-config]
      Write the zone without the key.
```
```text
release 0.2.0, previous 0.1.2 [doctor-release-installed]
```
```text
no installed release in /opt/garrison/current [doctor-release-missing]
      Run the installer from the release archive.
```
```text
garrison-web.service is active [doctor-service-active]
```
```text
garrison-web.service is failed [doctor-service-inactive]
      journalctl -u garrison-web.service -n 50 shows why.
```
```text
garrison-web.service: systemctl gave no answer [doctor-service-unknown]
```
```text
when the collector last finished a run: the status database cannot be read (file is not a database) [doctor-collection-unreadable]
```
```text
no collection run has finished yet [doctor-collection-none]
      The collector runs every minute; if this stays, `systemctl status garrison-collect.service garrison-collect.timer` and `garrison check-config` say why.
```
```text
when the collector last finished a run: the newest status snapshot is dated 9223372036854775807, which is no time [doctor-collection-undated]
```
```text
no collection run has finished since 2026-11-06T21:09:59+00:00, 10 minutes ago [doctor-collection-stopped]
      Until one does, Garrison checks nothing and reports nothing: `systemctl status garrison-collect.service garrison-collect.timer` and `garrison check-config` say why.
```
```text
the newest status snapshot is dated 60 minutes ahead of this host's clock, so its age is not known [doctor-collection-ahead]
      The clock went back after it was written; `timedatectl` shows whether it is synchronized.
```
```text
the last collection run finished 1 minute ago [doctor-collection-recent]
```
```text
the last collection run ended with exit-code [doctor-collection-run-failed]
      journalctl -u garrison-collect.service -n 50 shows why.
```
```text
garrison-collect.service: systemctl gave no answer about its last run [doctor-collection-run-unknown]
```
```text
the clock is synchronized [doctor-clock-synchronized]
```
```text
the clock is not synchronized [doctor-clock-unsynchronized]
      Sign-in tokens and certificates depend on the time: enable a time service (timedatectl set-ntp true).
```
```text
clock synchronization: timedatectl gave no answer [doctor-clock-unknown]
```
```text
free space of /proc/self/status/garrison: Not a directory (os error 20) [doctor-space-unknown]
```
```text
/var/backups does not exist yet; /var, where it will be made, has 2048 MiB free [doctor-space-enough]
```
```text
/var/lib/garrison has only 512 MiB free [doctor-space-low]
      Databases and backups grow; make room before the next upgrade.
```
```text
when the last Stalwart event arrived: the events database /var/lib/garrison/ingest/events.sqlite cannot be read (file is not a database) [doctor-events-unreadable]
```
```text
when the last Stalwart event arrived: the newest event is recorded at -9223372036854775808, which is no time [doctor-events-undated]
```
```text
the last Stalwart event is recorded 60 minutes ahead of this host's clock, so when it arrived is not known [doctor-events-ahead]
      The clock went back after it arrived; `timedatectl` shows whether it is synchronized.
```
```text
the last Stalwart event arrived 10 minutes ago [doctor-events-recent]
```
```text
no Stalwart event for 30 hours [doctor-events-quiet]
      Check the webhook in the Stalwart WebUI, or run `garrison stalwart setup` again.
```
```text
no Stalwart event recorded yet [doctor-events-none]
      Stalwart sends events through the webhook that `garrison stalwart setup` creates.
```
```text
providers[receipt].path is /home/jobs/nightly.json, under /home, which garrison-collect.service hides from the collector (ProtectHome=true): the check cannot read it there [doctor-path-hidden]
      Keep it where the collector sees it.
```
```text
broker-native-key is missing: /etc/garrison/credentials/broker-native-key [doctor-credential-missing]
      Run `garrison stalwart setup`, which makes it.
```
```text
metrics-credential is a link or a folder, not a file: /etc/garrison/credentials/metrics-credential [doctor-credential-not-a-file]
      Remove it; then `install -m 600 /dev/null /etc/garrison/credentials/metrics-credential` makes the file itself there.
```
```text
webhook-signature-key is private (600) [doctor-credential-private]
```
```text
/etc/garrison/credentials/broker-native-key is not root-owned with mode 600 or less (mode 644) [doctor-credential-open]
      Make it root's with mode 600: chown root /etc/garrison/credentials/broker-native-key && chmod 600 /etc/garrison/credentials/broker-native-key
```
```text
webhook-signature-key is empty, so garrison-ingest.service has no key: /etc/garrison/credentials/webhook-signature-key [doctor-credential-no-key]
      Run `garrison stalwart setup`, which makes it.
```
```text
ntfy-token is missing: /etc/garrison/credentials/ntfy-token; systemd starts garrison-collect.service and garrison-watch.service only with it [doctor-credential-missing-empty]
      Make it, empty, which means none: install -m 600 /dev/null /etc/garrison/credentials/ntfy-token
```
```text
spamhaus-dqs-key is missing: /etc/garrison/credentials/spamhaus-dqs-key; systemd starts garrison-collect.service only with it [doctor-credential-missing-read]
      Write the key into it (zen.dq.spamhaus.net is asked with it): install -m 600 /dev/null /etc/garrison/credentials/spamhaus-dqs-key && sh -c 'cat > /etc/garrison/credentials/spamhaus-dqs-key', then paste the key and press Enter and Ctrl-D.
```
```text
metrics-credential is empty, which means none (600) [doctor-credential-empty]
```
```text
metrics-credential holds no credential, but the prometheus check reads Stalwart's exporter with it [doctor-credential-unusable]
      Run `garrison stalwart setup`, which writes it while Stalwart's exporter is Garrison's or off; for an exporter of another's, write its user name and password into it as configuration.md says (collector.metrics_credential).
```
```text
Stalwart takes the broker's API key (broker-native-key) from this host [doctor-key-taken]
```
```text
Stalwart does not know the collector's API key in collector-native-key, so every card that reads Stalwart stays unknown [doctor-key-not-known]
      Run `garrison stalwart setup`, which makes a new one.
```
```text
Stalwart refuses the broker's API key in broker-native-key from this host's address (HTTP 403), so nobody can sign in [doctor-key-other-address]
      The key may be used only from this host: run Stalwart in the host network.
```
```text
whether Stalwart takes the broker's API key in broker-native-key: it answered HTTP 500 for the key's JMAP session [doctor-key-untried]
```
```text
Stalwart takes the collector's API key (collector-native-key) but refuses what the collector reads with it (forbidden), so the cards that read Stalwart's domains and accounts stay unknown [doctor-key-narrowed]
      Run `garrison stalwart setup`, which gives the key the permissions it needs.
```
```text
whether Stalwart lets the broker's API key (broker-native-key) read what the broker reads: Stalwart did not answer at http://127.0.0.1:8080/jmap/ (timed out) [doctor-key-reads-unknown]
```
```text
the macro milter answers on 127.0.0.1:8096 [doctor-milter-answers]
```
```text
the macro milter does not answer on 127.0.0.1:8096: Connection refused (os error 111) [doctor-milter-silent]
      journalctl -u garrison-milter.service -n 50 shows why.
```
```text
Stalwart asks a milter at 127.0.0.1:11332 (entry o), where nothing answers: Stalwart decides by conditions of its own what to do with all incoming mail [doctor-milter-stranded]
      If nothing is to answer there, remove that entry in the Stalwart WebUI (Settings ▸ MTA ▸ Milters) and reload its settings.
```
```text
Stalwart asks a milter at 127.0.0.1:9000 (entry x), where nothing answers: Stalwart takes all incoming mail unscanned [doctor-milter-stranded-unscanned]
      If nothing is to answer there, remove that entry in the Stalwart WebUI (Settings ▸ MTA ▸ Milters) and reload its settings.
```
```text
Stalwart asks the macro milter at 127.0.0.1:8096, but the configuration has it on 127.0.0.1:8097 [doctor-milter-entry-moved]
      Run `garrison stalwart setup`.
```
```text
Stalwart asks the macro milter at 127.0.0.1:8096, but the configuration has it on 127.0.0.1:8097, where nothing answers: Stalwart defers all incoming mail [doctor-milter-entry-unanswered]
      Run `garrison stalwart setup` once the milters named above are out of Stalwart.
```
```text
Stalwart has no entry for the macro milter on 127.0.0.1:8096 and asks it nothing [doctor-milter-entry-missing]
      Run `garrison stalwart setup`.
```
```text
Stalwart has 2 entries for the macro milter on 127.0.0.1:8096 [doctor-milter-entries-several]
      Run `garrison stalwart setup`.
```
```text
Stalwart's entry for the macro milter on 127.0.0.1:8096 is switched off [doctor-milter-entry-off]
      Run `garrison stalwart setup`.
```
```text
Stalwart's entry for the macro milter on 127.0.0.1:8096 is switched on only under conditions of its own [doctor-milter-entry-conditional]
      Run `garrison stalwart setup`.
```
```text
Stalwart does not ask the macro milter on 127.0.0.1:8096 once a message's data has arrived, so it sees no attachment [doctor-milter-entry-before-data]
      Run `garrison stalwart setup`.
```
```text
Stalwart defers mail while the macro milter does not answer, though when_unreachable is "accept" [doctor-milter-when-unreachable]
      Run `garrison stalwart setup`.
```
```text
Stalwart asks the macro milter on 127.0.0.1:8096 about every message and defers mail while it does not answer [doctor-milter-entry-asked]
```
```text
Stalwart still asks the macro milter at 127.0.0.1:8096, which the configuration no longer has [doctor-milter-entry-dropped]
      Run `garrison stalwart setup`. It takes the filter out of Stalwart; until then mail may be deferred.
```
```text
whether Stalwart asks the macro milter on 127.0.0.1:8096: Stalwart did not answer at http://127.0.0.1:8080 (connection refused) [doctor-milter-entry-unknown]
```
```text
whether Stalwart asks a milter where nothing answers: Stalwart refused the collector's API key [doctor-milter-stranded-unknown]
```
```text
notifications: ntfy: notifications.ntfy_url cannot be used: ntfy-url is empty [doctor-notify-unusable]
      Correct the file it names (configuration.md, Notifications), then send a test message: garrison notify-test
```
```text
the webhook takes no token, and garrison.toml, which every user of this host may read, holds its address: whoever reads it can post to it where its key is part of the address [doctor-notify-open]
      Write the address into /etc/garrison/credentials/notify-webhook-url (root, mode 0600) and set webhook_url = "credential:notify-webhook-url", or give it a token (configuration.md, Notifications).
```
```text
notifications: ntfy at ntfy.example.org, mail [doctor-notify-channels]
```
```text
the access policy is missing: /etc/garrison/access-policy.json [doctor-policy-missing]
      Run `garrison access init`, which makes it.
```
```text
the access policy is a link or a folder, not a file: /etc/garrison/access-policy.json [doctor-policy-not-a-file]
      Remove it; then `garrison access init` makes the file itself there.
```
```text
the broker does not take the access policy (root:garrison-broker, mode 664): its group may change it, and others may read it, so nobody can sign in: /etc/garrison/access-policy.json [doctor-policy-refused]
      Run `chown root:garrison-broker /etc/garrison/access-policy.json && chmod 640 /etc/garrison/access-policy.json`.
```
```text
whether the broker can read the access policy: this host has no user garrison-broker [doctor-policy-no-broker]
```
```text
garrison-broker may not enter /etc/garrison (root:root, mode 700), so it cannot read the access policy and nobody can sign in [doctor-policy-folder-closed]
      Run `chmod 755 /etc/garrison`.
```
```text
garrison-broker may not enter /srv/private (root:root, mode 700), so it cannot read the access policy and nobody can sign in [doctor-policy-folder-closed-elsewhere]
      Move the policy to /etc/garrison/access-policy.json and set broker.policy to it.
```
```text
garrison-broker may not read the access policy (root:root, mode 600), so nobody can sign in: /etc/garrison/access-policy.json [doctor-policy-unreadable]
      Run `chown root:garrison-broker /etc/garrison/access-policy.json && chmod 640 /etc/garrison/access-policy.json`.
```
```text
garrison-broker owns the access policy (garrison-broker:garrison-broker, mode 600), which the installer keeps root's, so that only root may change what it grants [doctor-policy-broker-owner]
      Run `chown root:garrison-broker /etc/garrison/access-policy.json && chmod 640 /etc/garrison/access-policy.json`.
```
```text
the broker may read the access policy, which only root may change (root:garrison-broker, mode 640) [doctor-policy-readable]
```
```text
the access policy is larger than the broker reads (64 KiB), so nobody can sign in: /etc/garrison/access-policy.json [doctor-policy-too-large]
      Move it away and run `garrison access init`, or copy back the newest backup beside it (/etc/garrison/access-policy.json.<time>.bak) with sudo cp where there is one.
```
```text
the access policy names actions garrison.toml does not have (run_reports), so nobody can sign in [doctor-policy-actions-dropped]
      Run `garrison access update`, which mends it.
```
```text
the access policy does not read (schemaVersion must be 1), so nobody can sign in [doctor-policy-invalid]
      Correct it as docs/operator/access.md shows.
```
```text
the access policy binds no role and no account, so nobody can sign in [doctor-policy-unbound]
      Bind the role of your administrators: garrison access bind-role <role-id> --profile administrator
```
```text
the access policy binds 1 role and 0 accounts [doctor-policy-bound]
```
```text
broker.policy is /home/admin/access-policy.json, under /home, which garrison-broker.service hides from the broker (ProtectHome=true): the broker cannot read it there, and nobody can sign in [doctor-policy-hidden]
      Keep the policy where the broker sees it.
```
```text
the certificate of admin.example.org expired on 2026-11-01 [doctor-certificate-expired]
      Renew it (certbot renew) and reload nginx.
```
```text
the certificate of admin.example.org:8443 expires in 5 days [doctor-certificate-expiring]
      Check that certificate renewal runs.
```
```text
admin.example.org presents a trusted certificate for 61 more days (TLSv1_3) [doctor-certificate-valid]
```
```text
TLS to [::1]:1: connection refused [doctor-certificate-tls-failed]
      Check DNS, the certificate and the nginx server block for this name.
```
```text
Garrison answers at https://admin.example.org [doctor-interface-answers]
```
```text
https://admin.example.org/api/session answers 502: nginx does not reach Garrison's web service on 127.0.0.1:8091 [doctor-interface-unreached]
      Something listens on 127.0.0.1:8091: the lines above name an include or an SELinux module for another port.
```
```text
https://admin.example.org/api/session answers 502: nginx does not reach Garrison's web service on 127.0.0.1:8091 [doctor-interface-web-down]
      Nothing listens on 127.0.0.1:8091: `systemctl restart garrison-web.service` starts the web service on web.port, and `systemctl status garrison-web.service` says why it does not run.
```
```text
https://admin.example.org/api/session answers 404 instead of Garrison's answer to a visitor [doctor-interface-other-answer]
      The server block for this name must include /etc/nginx/snippets/garrison.conf.
```
```text
https://admin.example.org/api/session: connection refused [doctor-interface-unanswered]
      Check DNS, the certificate and the nginx server block for this name.
```
```text
nginx sends Strict-Transport-Security [doctor-hsts-sent]
```
```text
no Strict-Transport-Security header [doctor-hsts-missing]
      Include /etc/nginx/snippets/garrison.conf in the server block; it sets the header.
```
```text
https://mail.example.org does not serve Stalwart's metrics [doctor-metrics-private]
```
```text
https://mail.example.org/metrics/prometheus answers 200: Stalwart's metrics exporter is public [doctor-metrics-public]
      Add `include /etc/nginx/snippets/garrison-stalwart-server*.conf;` to that server block.
```
```text
https://mail.example.org/metrics/prometheus answers 500 [doctor-metrics-unread]
```
```text
https://mail.example.org/metrics/prometheus: timed out [doctor-metrics-unanswered]
```
```text
Stalwart knows Garrison's sign-in client as registered [doctor-client-registered]
```
```text
Stalwart refuses Garrison's sign-in client https://admin.example.org/client.json: Client metadata documents are disabled [doctor-client-refused]
      Run `garrison stalwart setup` again.
```
```text
https://mail.example.org/api/auth/client: timed out [doctor-client-unanswered]
      Check that the issuer is reachable from this host.
```
```text
whether Stalwart knows Garrison's sign-in client: https://mail.example.org answered 429 (Stalwart's rate limit); ask again in a minute [doctor-client-limited]
```
```text
https://mail.example.org answers 502 for Garrison's sign-in client: its proxy does not reach Stalwart [doctor-client-unreached]
      See that Stalwart runs and that the proxy for https://mail.example.org reaches it.
```
```text
https://mail.example.org answers 404 (no content type) for Garrison's sign-in client, not Stalwart's JSON [doctor-client-not-stalwart]
      The proxy for https://mail.example.org must pass /api/auth/client and /api/auth to Stalwart.
```
```text
which issuer Stalwart names itself: http://127.0.0.1:8080/.well-known/openid-configuration answered 404 without an issuer this release of Garrison reads; see the supported Stalwart releases in the README [doctor-issuer-unknown]
```
```text
Stalwart names itself https://mail.example.org, as deployment.issuer does [doctor-issuer-same]
```
```text
Stalwart names itself https://other.example.org, but deployment.issuer is https://mail.example.org, so every sign-in fails at Garrison's callback [doctor-issuer-other]
      Set issuer = "https://other.example.org" under [deployment] and restart garrison-web, or make mail.example.org Stalwart's Default Hostname and reload its settings.
```
```text
Stalwart names itself https://other.example.org/, but deployment.issuer is https://mail.example.org, so every sign-in fails at Garrison's callback [doctor-issuer-other-hostname]
      Make mail.example.org Stalwart's Default Hostname and reload its settings.
```
```text
https://mail.example.org/sign-in shows Stalwart's sign-in page, which gets the 3 files it loads [doctor-sign-in-page-shown]
```
```text
Stalwart's sign-in page https://mail.example.org/sign-in cannot load /assets/app.js [doctor-sign-in-page-failed]
      Whatever answers for mail.example.org must pass these paths.
```
```text
https://mail.example.org/sign-in differs from the sign-in page Stalwart serves at http://127.0.0.1:8080 [doctor-sign-in-page-unknown]
```
```text
SELinux lets nginx connect to every port (httpd_can_network_connect) [doctor-selinux-everywhere]
```
```text
SELinux is enforcing and the module garrison is not loaded, so nginx cannot reach Garrison [doctor-selinux-unloaded]
      Run the installer again; it loads the module.
```
```text
SELinux is permissive and the module garrison is not loaded [doctor-selinux-unloaded-permissive]
      Run the installer again.
```
```text
the SELinux module garrison is loaded and lets nginx reach the web service on port 8091 [doctor-selinux-port-reached]
```
```text
the SELinux module garrison lets nginx reach port 8091, not 9443 (web.port), so nginx answers 502 [doctor-selinux-other-port]
      Run the installer again; it loads the module for web.port.
```
```text
the SELinux module garrison lets nginx reach port 8091, not 9443 (web.port); SELinux is permissive and only logs the denial [doctor-selinux-other-port-permissive]
      Run the installer again; it loads the module for web.port.
```
```text
the SELinux module garrison lets nginx reach port 8091, not 9443 (web.port), so nginx answers 502 [doctor-selinux-load-failed]
      Load the module the installer wrote for web.port: semodule -i /opt/garrison/selinux/garrison.cil
```
```text
the SELinux module garrison lets nginx reach port 8091, not 9443 (web.port); SELinux is permissive and only logs the denial [doctor-selinux-load-failed-permissive]
      Load the module the installer wrote for web.port: semodule -i /opt/garrison/selinux/garrison.cil
```
```text
which port the SELinux module garrison lets nginx reach: `semodule -c -E garrison` extracted no module (libsemanage.semanage_direct_get_module_info: error) [doctor-selinux-port-unknown]
```

## The configuration

What every command says of a configuration it cannot use, the lines of
`garrison check-config`, and the one of `garrison stalwart-switch`.
Names begin with `config-…`, `check-config-…` and `switch-…`.

```text
Cannot load /etc/garrison/garrison.toml: unknown field `nonsense` [config-unloadable]
```
```text
garrison detect reads no configuration, so it takes no --config (/root/garrison.toml). [config-not-followed]
```
```text
Configuration not usable: providers[2]: unknown type `nonsense` [check-config-providers]
```
```text
Configuration not usable: collector.native_key is credential:my-key, but … loads it as … [check-config-unloaded]
```
```text
Configuration not usable: providers[1].lists names zen.dq.spamhaus.net. Set collector.dqs_key [check-config-dqs-refused]
```
```text
Configuration not usable: providers[receipt].path is /home/jobs/nightly.json. Keep it. [check-config-hidden-check]
```
```text
Configuration valid: 3 providers, 1 actions. [check-config-valid]
```
```text
Warning: deployment.public_origin https://admin.example.test is a placeholder; set the real name. [check-config-placeholder]
```
```text
Warning: credentials_directory is /etc/garrison/elsewhere. Remove it [check-config-unfollowed]
```
```text
Warning: providers[1].lists names ….sbl.dq.spamhaus.net. Move the key [check-config-dqs-warned]
```
```text
Warning: providers[receipt].path is /home/jobs/nightly.json. [check-config-hidden-check-warned]
```
```text
Access policy not usable: garrison-broker may not enter /etc/garrison [check-config-policy-refused]
```
```text
Warning: garrison-broker owns the access policy [check-config-policy-warned]
```
```text
Access policy valid: /etc/garrison/access-policy.json [check-config-policy-valid]
```
```text
/opt/garrison/current/static/stalwart-switch.js is missing; build the interface first. [switch-script-missing]
```

## Access

`garrison access` with `init`, `list`, `bind-role`, `unbind-role`, `deny`,
`check` and `update`.
Names begin with `access-…`.

```text
invalid profile name 'Admin' [access-invalid-profile]
```
```text
/etc/garrison/access-policy.json is a link or a folder, not a file: remove it; then `garrison access init` makes the file itself there. [access-not-a-file]
```
```text
The access policy /etc/garrison/access-policy.json is missing: `garrison access init` makes it. [access-missing]
```
```text
The access policy /etc/garrison/access-policy.json is larger than the broker reads (64 KiB), so it is no policy: move it away and run `garrison access init`, or copy back the newest backup beside it (/etc/garrison/access-policy.json.<time>.bak) with sudo cp where there is one. [access-too-large]
```
```text
Stalwart answered in a form this release of Garrison does not read (x:Role/get did not return the objects asked for); see the supported Stalwart releases in the README [access-unread-answer]
```
```text
The access policy /etc/garrison/access-policy.json names run_other, which garrison.toml no longer has: run `garrison access update`, which takes it out of the profiles. [access-actions-gone]
```
```text
/etc/garrison/access-policy.json: No such file or directory (os error 2) [access-io]
```
```text
unknown actions: run_other [access-invalid-policy]
```
```text
Garrison access policy: not JSON [access-unread-policy]
```
```text
The policy would be larger than the broker reads (64 KiB): the change is not saved, and /etc/garrison/access-policy.json stays as it is. [access-save-too-large]
```
```text
Note: the broker cannot read /etc/garrison/access-policy.json: this host has no group garrison-broker. Run the installer, which makes the group and gives it the policy. [access-no-group]
```
```text
Note: the broker cannot read /etc/garrison/access-policy.json: it could not be made root's with the group garrison-broker (Operation not permitted (os error 1)). Run the command as root, or the installer again, which does. [access-not-chowned]
```
```text
Saved /etc/garrison/access-policy.json; the previous file is kept as /etc/garrison/access-policy.json.20261124T080000.bak. [access-saved]
```
```text
The profiles have the actions garrison.toml names; nothing to change. [access-actions-held]
```
```text
Profile administrator: run_other added, run_check taken out. [access-profile-changed]
```
```text
Run the installer again now: it writes the polkit rule for these actions and restarts the broker and the web service, which read them only when they start; until then an added action is offered to nobody. [access-run-installer]
```
```text
Stalwart returned no object [access-no-object]
```
```text
Stalwart did not answer [access-unavailable]
```
```text
Stalwart limits the requests [access-limited]
```
```text
The token has ended [access-invalid-token]
```
```text
This identity's profiles grant no module this installation offers [access-denied]
```
```text
Garrison has no API key for Stalwart [access-misconfigured]
```
```text
/etc/garrison/access-policy.json exists; use --force to replace it (a backup is kept). [access-exists]
```
```text
No native administrator role with full administrative rights was found, so the policy binds no role and nobody can sign in yet. The administrator profile requires authenticate, sysAccountUpdate, sysActionCreate, sysDomainUpdate and sysRoleUpdate.
Stalwart's default administrator role 1 (Administrators) lacks sysRoleUpdate: give the role that right in the native administration (Roles), then run garrison access bind-role 1 --profile administrator. As it is, it meets the profile viewer.
Stalwart's default administrator role 2 is left out: it is every user's default role too, and binding it would make every user an administrator [access-every-users-role]. [access-unbound]
```
```text
No native administrator role with full administrative rights was found, and a new default policy would bind no role and sign everyone out: /etc/garrison/access-policy.json is kept as it is.
The access policy /etc/garrison/access-policy.json names run_other, which garrison.toml no longer has: run `garrison access update`, which takes it out of the profiles. [access-actions-gone]
It binds no role or account either, so nobody can sign in yet. The administrator profile requires authenticate, sysAccountUpdate, sysActionCreate, sysDomainUpdate and sysRoleUpdate.
Stalwart names no default administrator role: once the role of your administrators holds these rights, bind it with garrison access bind-role <role-id> --profile administrator. [access-kept]
```
```text
Bound native role 1 (Administrators) to profile administrator. [access-bound]
```
```text
Unknown profile auditor; known: administrator, operator, viewer [access-unknown-profile]
```
```text
Stalwart has no role 17: bind one of the roles the native administration shows (Roles). [access-no-role]
```
```text
Note: the rights of role 5 cannot be evaluated (it belongs to a tenant [access-tenant-role]), so whether its users get the profile operator is not known; `garrison access check <subject>` shows what a user gets. [access-role-unjudged]
```
```text
Note: role e lacks sysAccountUpdate and sysDomainUpdate, which the profile administrator requires, so its users get nothing of it until Stalwart's administrator gives the role those rights in the native administration (Roles). As it is, it meets none of the profiles. [access-role-lacks]
```
```text
"a b" is no subject: a subject is 1 to 128 letters, digits and _ . : @ -, and that of a local Stalwart account its numeric account ID. [access-no-subject]
```
```text
broker.policy names no file: / [access-no-file-name]
```
```text
/srv/shared/access.json.lock is a link, not the lock of `garrison access`: remove it, then run the command again. [access-lock-link]
```
```text
/srv/shared/access.json.lock is not a file, so not the lock of `garrison access`: remove it, then run the command again. [access-lock-not-a-file]
```
```text
/srv/shared/access.json.lock is another user's file, not the lock of `garrison access`: remove it, then run the command again. [access-lock-foreign]
```
```text
/srv/shared/access.json.lock has another name too (a hard link), so it is not the lock of `garrison access`: remove it, then run the command again. [access-lock-linked]
```
```text
/srv/shared/access.json.lock is held by another process, as another `garrison access` command: try again once it has ended. Where none runs, remove the file and run the command again. [access-lock-held]
```
```text
No backup of /etc/garrison/access-policy.json could be kept: every name for one of this second is taken. [access-no-backup-name]
```
```text
/etc/garrison/.access-policy.json.pending is a folder, not the file `garrison access` writes the policy to first: remove it, then run the command again. [access-pending-folder]
```
```text
it inherits from more than 64 roles, more than Garrison evaluates [access-too-many-roles]
```
```text
it inherits from role 9, which Stalwart does not have [access-inherits-missing]
```
```text
this release cannot read role 9 [access-role-unreadable]
```
```text
role 9, from which it inherits, belongs to a tenant [access-tenant-role]
```
```text
a cycle of roles [access-unevaluable]
```
```text
it is every user's default role too, and binding it would make every user an administrator [access-every-users-role]
```
```text
Stalwart has no role of that ID [access-no-such-role]
```
```text
its rights cannot be evaluated (a cycle of roles [access-unevaluable]) [access-rights-unevaluated]
```

## Modules

`garrison modules`.
Names begin with `modules-…`.

```text
backup is not a module ID; known: dashboard, backups [modules-unknown]
```
```text
/etc/garrison/garrison.toml: unknown field `x` [modules-io]
```
```text
/etc/garrison/garrison.toml: the edited file does not offer the chosen modules [modules-not-offered]
```
```text
garrison modules asks before it writes, and no terminal is here to answer: add --yes to write it. [modules-unasked]
```
```text
Nothing was changed. [modules-unchanged]
```
```text
The configuration offers these modules already; nothing was changed. [modules-held]
```
```text
Written; the previous file is /etc/garrison/garrison.toml.previous. [modules-written]
```
```text
Restart garrison-broker.service and garrison-web.service to apply it. [modules-unapplied]
```
```text
The broker and the web service were restarted where they ran. [modules-restarted]
```

## Backup and self-check

`garrison backup` and `garrison self-check`.
Names begin with `backup-…` and `self-check-…`.

```text
ingest: database disk image is malformed [backup-io]
```
```text
Cannot write /srv/receipt.json: Permission denied (os error 13) [self-check-receipt-unwritten]
```

## The check of a backup repository

`garrison backup-check`.
Names begin with `backup-check-…`.

```text
The backup tool is restic or borg. [backup-check-unknown-tool]
```
```text
The report's lock /var/lib/garrison/backup-check/restic.json.lock cannot be taken: No such file or directory (os error 2). [backup-check-io]
```
```text
/var/lib/garrison/backup-check/restic.json.lock is no lock of `garrison backup-check`'s, but a link, another user's file or no file: remove it, then run the command again. [backup-check-lock-other]
```
```text
Another `garrison backup-check` writes /var/lib/garrison/backup-check/restic.json; this run waits until it has ended. [backup-check-waits]
```
```text
restic: 2 snapshots, the newest of 2026-11-16T02:00:04+00:00. [backup-check-listed]
```
```text
borg did not list its snapshots: Repository /srv/repo does not exist. [backup-check-unlisted]
```
```text
Integrity check: passed (no errors were found) [backup-check-verified]
```
```text
Integrity check: FAILED (pack 5e1f0c3a: not referenced) [backup-check-verify-failed]
```
```text
Restore test: passed (/etc/hosts: 1 files, 220 bytes) [backup-check-restored]
```
```text
Restore test: FAILED (/etc/hosts was not in the newest snapshot: nothing was restored) [backup-check-restore-failed]
```
```text
/var/tmp/garrison-restore-00000000000000c1 could not be removed (Device or resource busy (os error 16)); it holds a copy of what the backup holds: remove it as root with rm -r /var/tmp/garrison-restore-00000000000000c1 [backup-check-not-removed]
```
```text
Removed /var/tmp/garrison-restore-00000000000000c1, a copy of restored data that an interrupted test restore left. [backup-check-leftover-removed]
```
```text
A copy that an interrupted test restore left: /var/tmp/garrison-restore-00000000000000c1 could not be removed (Device or resource busy (os error 16)); it holds a copy of what the backup holds: remove it as root with rm -r /var/tmp/garrison-restore-00000000000000c1 [backup-check-not-removed] [backup-check-leftover-kept]
```
```text
This test restore's copy: /var/tmp/garrison-restore-00000000000000c1 could not be removed (Device or resource busy (os error 16)); it holds a copy of what the backup holds: remove it as root with rm -r /var/tmp/garrison-restore-00000000000000c1 [backup-check-not-removed] [backup-check-copy-kept]
```
```text
The last report, /srv/reports/restic.json, can be changed by users other than root: its last integrity check and test restore are not kept. [backup-check-report-foreign]
```
```text
The last report, /var/lib/garrison/backup-check/restic.json, cannot be read: it must be a file, not a link, of at most 64 KiB of valid JSON. Its last integrity check and test restore are not kept. [backup-check-report-unread]
```
```text
The last report, /var/lib/garrison/backup-check/restic.json, is not known to be of this repository, since the command is not told where this one is: its last integrity check and test restore are not kept. [backup-check-report-unplaced]
```
```text
The last report, /var/lib/garrison/backup-check/restic.json, is not known to be of this repository, since restic could not list it: its last integrity check and test restore are not kept. [backup-check-report-unlisted]
```
```text
The last report, /var/lib/garrison/backup-check/restic.json, is not known to be of this repository, since restic gave no ID for it: its last integrity check and test restore are not kept. [backup-check-report-unidentified]
```
```text
The last report, /var/lib/garrison/backup-check/restic.json, holds no repository ID: its last integrity check and test restore are not kept. [backup-check-report-anonymous]
```
```text
The last report, /var/lib/garrison/backup-check/restic.json, is of the restic repository /srv/repo (ID 5e1f), and this run asks the borg repository /srv/borg (ID 77aa): its last integrity check and test restore are not kept. [backup-check-report-other]
```
```text
The last report, /var/lib/garrison/backup-check/restic.json, is of the restic repository /srv/repo (ID 5e1f), and this run asks the restic repository /srv/copy (ID 5e1f): its last integrity check and test restore are not kept. The same ID at another place is a copy, which needs a --report of its own; name one repository alike in every run. [backup-check-report-copy]
```
```text
The report could not be written to /var/lib/garrison/backup-check/restic.json: Read-only file system (os error 30) [backup-check-unwritten]
```
```text
Report written to /var/lib/garrison/backup-check/restic.json. [backup-check-written]
```

## Test notifications

`garrison notify-test`.
Names begin with `notify-test-…`.

```text
Not tested: notifications.token is credential:t, but … [notify-test-unloaded]
```
```text
Run as root: the channels' secrets are files only root may read. [notify-test-not-root]
```
```text
No channel is configured: set ntfy_url, webhook_url or the mail settings under [notifications] in garrison.toml. [notify-test-no-channel]
```
```text
ntfy: the test message is out. [notify-test-sent]
```
```text
ntfy: the test message did not go out: HTTP 403. Check its address and its secret in /etc/garrison/credentials. [notify-test-failed]
```

## The services, in the journal

What a service writes when it stops, a collection run that collects
nothing, and the watch over the collector each time it has looked
(`journalctl -u garrison-watch.service`).
Names begin with `service-…`, `collect-…` and `watch-…`.

```text
The ingest service stopped: Address already in use (os error 98) [service-stopped]
```
```text
Another collection run is under way; this one ends without collecting [collect-busy]
```
```text
/etc/garrison/garrison.toml does not load (unknown field `nonsense`); watching with what the last collection run left [watch-unloaded]
```
```text
Whether the collector runs is not known: the newest snapshot in /var/lib/garrison/collector/status.sqlite is dated at a time that is none [watch-not-known]
```
```text
No collection run has finished yet [watch-never-ran]
```
```text
The collector runs [watch-running]
```
```text
The collector has stopped [watch-stopped]
```
```text
The collector has stopped; the channels were told [watch-told-stopped]
```
```text
The collector runs again; the channels were told [watch-told-running]
```
```text
The watch over the collector did not finish: database is locked [watch-unfinished]
```
