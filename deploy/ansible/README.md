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
        garrison_version: "0.2.0"
        garrison_signing_key: "RW..."            # from the README
        garrison_public_origin: "https://garrison.example.org"
        garrison_issuer: "https://mail.example.org"
        garrison_modules: [antivirus, backups]
        garrison_stalwart_admin: "{{ vault_stalwart_admin }}"   # {username, secret}
        garrison_extra_config: "{{ lookup('file', 'garrison-providers.toml') }}"
```

The role's variables, with what each is where the play does not set it:

| Variable | Default | Meaning |
|---|---|---|
| `garrison_version` | none, required | The release to install, as published. |
| `garrison_signing_key` | none | The release signing key from the README. Without it the role installs nothing, unless `garrison_unsigned` is set. |
| `garrison_unsigned` | `false` | `true` skips the signature check, for an archive that has no signature, such as one you built yourself. Check its checksum yourself. |
| `garrison_archives` | `archives/` next to the playbook | The folder on the control node that holds the archive and its `.minisig`. |
| `garrison_arch` | the host's architecture | `x86_64` or `aarch64`, as in the archive's name. |
| `garrison_public_origin` | none, required | `deployment.public_origin`. |
| `garrison_issuer` | none, required | `deployment.issuer`. |
| `garrison_stalwart_url` | `http://127.0.0.1:8080` | `deployment.stalwart_url`. |
| `garrison_admin_url` | `<issuer>/admin/` | `deployment.admin_url`. |
| `garrison_modules` | all modules | The modules besides the dashboard and services. |
| `garrison_extra_config` | none | Further configuration, appended as TOML: providers, actions, `[web]` and the like. |
| `garrison_stalwart_admin` | none | The Stalwart administrator for `garrison stalwart setup`: `{username, secret}` or `{apiKey}`. Keep it in Ansible Vault. Without it the role does not run setup. |

Put `garrison-<version>-<arch>.tar.gz` and its `.minisig` in `archives/` next
to the playbook. Changing `garrison_version` upgrades; the installer backs up
and switches back on failure as always. Every play has the release check the
configuration, runs `garrison stalwart setup` where `garrison_stalwart_admin`
is set, and then the installer; setup changes nothing where Stalwart is as
asked, and the installer nothing where the release runs as installed with
this configuration. So a second play changes nothing, and a play that
stopped on the way is finished by the next one; every play needs Stalwart to
answer and that administrator to work. With this role, a release before this
one restarts Garrison and sets up Stalwart again in every play, as its
installer and setup always did.
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
