# Ansible role `garrison`

Installs, configures and upgrades Garrison on hosts that already run Stalwart
and nginx, the way the unattended installation in
[docs/operator/installation.md](../../docs/operator/installation.md) does it.
The signature is checked on the control node with `minisign` before anything
reaches a host.

```yaml
- hosts: mail
  become: true
  roles:
    - role: garrison
      vars:
        garrison_version: "0.1.1"
        garrison_signing_key: "RW..."            # from the README
        garrison_public_origin: "https://garrison.example.org"
        garrison_issuer: "https://mail.example.org"
        garrison_modules: [antivirus, backups]
        garrison_stalwart_admin: "{{ vault_stalwart_admin }}"   # {username, secret}
        garrison_extra_config: "{{ lookup('file', 'garrison-providers.toml') }}"
```

Put `garrison-<version>-<arch>.tar.gz` and its `.minisig` in `archives/` next
to the playbook. Changing `garrison_version` upgrades; the installer backs up
and switches back on failure as always. The role prints `garrison doctor`'s
report at the end and fails only when doctor cannot run. The nginx server
block stays yours: `garrison nginx` prints one for your names.
