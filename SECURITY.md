# Security policy

## Supported versions

Security fixes go into the latest release; older releases get none.

## Reporting a vulnerability

Please report vulnerabilities privately, not in a public issue:

- Preferred: [GitHub private vulnerability reporting](https://github.com/relative23/garrison/security/advisories/new).
- Alternatively: email garrison@relative23.com.

Include the version or commit, the steps to reproduce it and the impact as you
understand it. Leave out real mail data, tokens and passwords; a test host or
made-up values show the problem just as well.

## What to expect

Garrison is maintained by one person. You can expect an acknowledgement
within a few days and a fix or mitigation as soon as practical. Please allow a
reasonable time before you publish details; you are credited in the advisory
unless you prefer otherwise.

## Scope

Garrison runs on a mail host next to Stalwart, so these are security
boundaries and in scope:

- Sign-in and sessions: the OIDC flow, the session cookie, CSRF and Origin checks.
- Authorization: the access policy, module and action grants, and the broker
  deriving the identity from the user's token.
- The broker: starting anything other than the configured unit and verb pairs,
  or acting for a user who is not signed in.
- The webhook receiver: accepting an unsigned or altered batch, storing data the
  field allowlist excludes, or exceeding the configured limits.
- The macro filter, where it is switched on: a message that stops it, makes
  it use memory without bound or leaves it with anything of the message kept
  or sent elsewhere. That a document with macros in a form it does not read
  gets past it is a limit the documentation names, not a vulnerability.
- The interface: script execution, server data rendered as HTML, a bypass of
  the Content-Security-Policy, or the "Switch to Garrison WebUI" script.
- The installer and the shipped units: file modes, credentials, polkit rules
  and anything that weakens the service sandboxing.
- Leaks of secrets, tokens, mail metadata of other users or mail contents.

Out of scope: vulnerabilities in Stalwart itself (report them to
[Stalwart](https://github.com/stalwartlabs/stalwart/security)), in nginx,
systemd or the operating system, and in dependencies (report them upstream, and
tell us if Garrison is affected). Attacks that need root on the host are out of
scope as well.

## Threat model

The adversaries are anyone on the internet who can reach nginx, a signed-in
user who tries to exceed their grants, and a compromised web service. The web
service never holds an administrative credential, so a compromised one can act
only as a user who is signed in at that moment and within that user's rights.
Each service runs as its own system user, and only the broker may start the
units an operator configured. The full model is in
[docs/architecture/security.md](docs/architecture/security.md).
