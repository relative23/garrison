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

## Default profiles

`garrison access init` creates:

| Profile | Modules | Actions | Requires (Stalwart) |
|---|---|---|---|
| `viewer` | all except Maintenance | none | authenticate, sysAccountGet, sysDomainGet |
| `operator` | all | actions marked `operator = true` | viewer rights + sysActionCreate |
| `administrator` | all | all | authenticate, sysAccountUpdate, sysDomainUpdate, sysRoleUpdate, sysActionCreate |

and binds Stalwart's System Administrator role to `administrator`. Users,
groups and tenant administrators get nothing by default.

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
```

Role IDs are shown in the native administration (Roles). The subject of a local
Stalwart account is its numeric account ID; `access check` shows the mapping.

Every change keeps the previous file as `access-policy.json.<timestamp>.bak`.
There is deliberately no web page that edits the policy.

## Not a tenant boundary

Profiles are server-wide. A user with the Event history module (`logs`) sees
the recorded events of all domains, and one with the Attacks & bans module
(`attacks`) sees which accounts of all domains someone tried to sign in to.
Do not give Garrison access to customers and expect it to be limited to
their domain.
