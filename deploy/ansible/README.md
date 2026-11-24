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
        garrison_version: "0.1.2"
        garrison_signing_key: "RW..."            # from the README
        garrison_public_origin: "https://garrison.example.org"
        garrison_issuer: "https://mail.example.org"
        garrison_modules: [antivirus, backups]
        garrison_stalwart_admin: "{{ vault_stalwart_admin }}"   # {username, secret}
        garrison_extra_config: "{{ lookup('file', 'garrison-providers.toml') }}"
```

Put `garrison-<version>-<arch>.tar.gz` and its `.minisig` in `archives/` next
to the playbook. Changing `garrison_version` upgrades; the installer backs up
and switches back on failure as always. Every play runs the installer, which
changes nothing where the release runs as installed with this configuration:
a second play changes nothing, and a play that stopped on the way is finished
by the next one. With this role, a release before this one restarts Garrison
in every play, as its installer always did. `garrison stalwart setup` runs,
where `garrison_stalwart_admin` is set, until it has finished with this
configuration, which the role notes in `/opt/garrison/ansible-setup`. So setup
also runs after a change of the configuration, and Stalwart must answer then.
The first play of this role runs setup also on a host that the role of an
earlier release set up, so the administrator in `garrison_stalwart_admin` must
still work then.
Where the access policy binds no role and no account, the play stops and
says how to bind one. On a host the role has set up, a dry run (`--check`)
checks the signature and says whether `garrison.toml` would change; it runs
neither the installer nor setup. The role prints `garrison doctor`'s report
at the end; what doctor finds does not fail the play. The nginx server block
stays yours: `garrison nginx` prints one for your names.

Every user of the host may read `/etc/garrison/garrison.toml`. A
notification address that is a secret itself, such as an ntfy topic that
takes no token, goes into a credential file instead, and
`garrison_extra_config` names that file (`ntfy_url = "credential:ntfy-url"`
under `[notifications]`, see
[configuration](../../docs/operator/configuration.md#an-address-that-is-a-secret)):

```yaml
  post_tasks:
    - name: The ntfy topic's address, kept out of garrison.toml
      ansible.builtin.copy:
        content: "{{ vault_ntfy_url }}\n"
        dest: /etc/garrison/credentials/ntfy-url
        owner: root
        group: root
        mode: "0600"
      no_log: true
```
