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
