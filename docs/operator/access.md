# Access

Users sign in with their Stalwart account. What they may see and do follows
from two things together:

1. **Garrison access policy** (`/etc/garrison/access-policy.json`)
   binds Stalwart roles, or individual accounts, to Garrison **profiles**. A
   profile lists modules and actions.
2. **Their current Stalwart permissions.** Each profile names the Stalwart
   permissions it requires. If a user lacks one, the profile does not apply.

Both are checked again on every request, so removing a role or permission in
Stalwart takes effect within seconds. Hiding a module in Preferences only
changes the menu; it grants and revokes nothing.

Only the modules the installation offers (`modules` in the
[configuration](configuration.md#top-level)) are granted, whatever a profile
names. A user whose profiles name none of them is refused, as one without a
profile is.

## Default profiles

`garrison access init` creates:

| Profile | Modules | Actions | Requires (Stalwart) |
|---|---|---|---|
| `viewer` | all except Maintenance | none | authenticate, sysAccountGet, sysDomainGet |
| `operator` | all | actions marked `operator = true` | viewer rights + sysActionCreate |
| `administrator` | all | all | authenticate, sysAccountUpdate, sysDomainUpdate, sysRoleUpdate, sysActionCreate |

and binds Stalwart's System Administrator role to `administrator`. Users,
groups and tenant administrators get nothing by default. It writes the
policy where `broker.policy` names it, and makes a folder there that is
missing, root's with mode 755 as `/etc/garrison`.

`init --force` starts over: the new policy holds the default profiles and
the administrator roles alone, so the old one's denials, account bindings,
other role bindings and profiles of its own are gone; its backup keeps them.
To give the profiles new actions, use `update` (below) instead.

Where no role of Stalwart's has all five rights, as where its administrator
role was changed or your administrators have a role of their own, `init`
writes the profiles without a binding, says so and ends with 1. It names,
for each of Stalwart's default administrator roles, the rights it lacks and
the profiles it meets as it is. Nobody can sign in until a role is bound to
a profile whose rights it holds: give the role what it lacks in the native
administration (Roles), then bind it with
`garrison access bind-role <role-id> --profile administrator`, or bind it to
a profile it meets. `bind-role` says so where it binds a role that lacks a
right its profile requires. Where a policy that reads is there already,
`init --force` keeps it then, since a new one would bind nobody and sign
everyone out.

Profiles can only require `authenticate` and `sys*` permissions: those are the
ones whose evaluation Garrison verifies against Stalwart in its contract tests.

## Commands (as root)

```sh
garrison access list                         # show the policy
garrison access bind-role <role-id> --profile viewer
garrison access unbind-role <role-id>
garrison access deny <subject>               # wins over everything
garrison access deny <subject> --undo
garrison access check <subject>              # what would this user get now?
garrison access update                       # the profiles follow [[actions]]
```

Role IDs are shown in the native administration (Roles). The subject of a local
Stalwart account is its numeric account ID; `access check` shows the mapping.
It shows what the broker grants: the modules of the user's profiles that this
installation offers (`modules` in `garrison.toml`), their actions only with
the maintenance module, and the refusal the user gets where none of those
modules is offered.

Every change keeps the previous file as `access-policy.json.<timestamp>.bak`,
with `-1`, `-2` and so on after the time where that name is taken, readable
by root alone, and says which; to undo a change, copy it back with `sudo cp`,
which keeps the policy's owner and mode. The commands follow no link in the
policy's folder and write over nothing there: a lock at
`access-policy.json.lock` that is a link or no file is refused and left as it
is, and so is a policy that is one. There is deliberately no web page that
edits the policy.

## When the actions change

The profiles hold the actions as a list. `init` gives `administrator` every
action of `[[actions]]` and `operator` those marked `operator = true`, as
`garrison.toml` has them then: an action added later is in no profile, so
nobody is offered it, and one taken out that a profile still names makes the
policy invalid, so that nobody can use Garrison and the other commands say
so. After adding, changing or removing an action:

```sh
sudo garrison access update
```

It gives `administrator` and `operator` the actions `init` would give them
now, where the profile holds the Maintenance module and requires
`sysActionCreate`, and takes from every profile the actions `garrison.toml`
no longer has; role bindings, accounts and denials stay, and the previous
file is kept. Then run the installer again, or write the polkit rule and
restart the broker ([configuration](configuration.md#actions)): the broker
reads `[[actions]]` only when it starts, and until it has, it lets nobody use
Garrison where the policy names an action it does not know. Run the two
one after the other.

## The policy file

Change it with the commands above where they do what you need. The file is
JSON with these five keys, all of them required:

```json
{
  "schemaVersion": 1,
  "profiles": {
    "viewer": {
      "modules": ["dashboard", "services", "logs"],
      "actions": [],
      "requiredNativePermissions": ["authenticate", "sysAccountGet", "sysDomainGet"]
    }
  },
  "roleBindings": {"<role-id>": "viewer"},
  "subjects": {"<subject>": {"accountId": "<account-id>", "profile": "viewer"}},
  "deniedSubjects": ["<subject>"]
}
```

`modules` are [module IDs](configuration.md#module-ids) and `actions` the
`id`s of `[[actions]]`; a profile with actions also needs the module
`actions` and the rights `authenticate` and `sysActionCreate`. After editing
it, `garrison check-config` says whether it reads, and the installer run
again makes it root's and readable for the broker's group.

## Accounts with permissions of their own

A Stalwart account can have permissions of its own beside its roles (its
Permissions setting). Garrison counts them as Stalwart does:

| Setting | Permissions | Roles bind profiles |
|---|---|---|
| Inherit | the roles' | yes |
| Merge | the roles' and the account's own; one that a role disables stays disabled, even where the account enables it | yes |
| Replace | the account's own alone: its roles grant and take away nothing | no |

So an account switched to Replace loses the profiles its roles gave it, even
where the policy binds one of its roles: within seconds its user is signed
out, and signing in again is refused. To give the access back, switch the
account to Merge or Inherit, or bind the account itself under `subjects` in
the policy, with the subject and account ID that `access check` shows:

```json
"subjects": {"1": {"accountId": "b", "profile": "viewer"}}
```

That binding, too, applies only where the account's own permissions hold
what the profile requires. `garrison access check <subject>` shows what the
user gets now.

## Not a tenant boundary

Profiles are server-wide. A user with the Event history module (`logs`) sees
the recorded events of all domains, and one with the Attacks & bans module
(`attacks`) sees which accounts of all domains someone tried to sign in to.
Do not give Garrison access to customers and expect it to be limited to
their domain.
