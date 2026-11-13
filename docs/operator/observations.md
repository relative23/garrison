# Observation ids

Every value Garrison shows comes from an observation, and every observation
has an id, such as `host.updates` or `systemd.stalwart.service`. The
notifications remember a check by its id, and a script that reads Garrison's
status finds an observation by it. The ids therefore stay as they are. A
release that renames one lists it under [Renamed](#renamed) and in the
changelog, and for one more release the observation carries its old id in
`value.aliases`.

`<…>` stands for a name from the configuration or from what the check finds.

| Id | Check (`type`) | Reports |
|---|---|---|
| `backup-check.<tool>` | `backup-check` | What `restic` or `borg` reported of its repository |
| `bulwark.plugins` | `bulwark` | Webmail plugin versions and bundle integrity |
| `clamav.configuration` | `clamav` | The scanner's policy |
| `clamav.signatures` | `clamav` | The signature files |
| `collector.<type>` | any | A check that failed as a whole; the collector's journal says why |
| `dns.records` | `dns` | Stands in while the domains or the resolver are not known |
| `dns.<domain>` | `dns` | The records of one domain |
| `flow.spam` | `mail-flow` | Spam and ham of the last seven days |
| `flow.spam-domains` | `mail-flow` | The same by domain, once mailboxes have received mail |
| `flow.milter` | `mail-flow` | The milters' verdicts |
| `flow.authentication` | `mail-flow` | SPF, DKIM, DMARC and ARC of incoming senders |
| `flow.failing-senders` | `mail-flow` | Sender domains that fail those checks, where there are any |
| `flow.tls` | `mail-flow` | TLS in transit |
| `host.resources` | `host` | Memory, load, disk and uptime |
| `host.updates` | `host-care` | Pending updates |
| `host.restart` | `host-care` | A restart of the host that is due |
| `host.clock` | `host-care` | Clock synchronisation |
| `host.disk-forecast` | `host-care` | When the disk will be full |
| `host.firewall` | `host-care` | The firewall service or units |
| `http.<id>` | `http` | One endpoint |
| `mailtest.results` | `mail-test` | Test messages through the mail server |
| `notifications.channels` | `[notifications]` | Whether the channels took the last message |
| `prometheus.exporter` | `prometheus` | Stalwart's metrics exporter |
| `receipt.<id>` | `receipt` | One job's receipt |
| `release.garrison` | `releases` | Newer releases of Garrison |
| `release.stalwart` | `releases` | Newer releases of Stalwart |
| `reputation.blocklists` | `reputation` | Blocklists of the addresses the server sends from |
| `reputation.reverse` | `reputation` | Their reverse names |
| `senders.accounts` | `senders` | Accounts that send unusually much |
| `signin.page` | `sign-in` | Stalwart's sign-in page and the files it loads |
| `stalwart.api` | `stalwart` | Stands in while Stalwart's API does not answer |
| `stalwart.spam` | `stalwart` | Spam filter settings and the classifier |
| `stalwart.milter` | `stalwart` | The milters Stalwart calls |
| `stalwart.queue` | `stalwart` | The delivery queue |
| `stalwart.mailboxes` | `stalwart` | Mailbox storage |
| `systemd.<unit>` | `systemd` | One unit, such as `systemd.stalwart.service` |
| `tls.endpoints` | `tls` | The certificates of every endpoint |
| `version.stalwart` | `stalwart` | The Stalwart version that runs |
| `version.<component>` | `version-command` | An installed version |

## Renamed

None at present. A release that renames an id lists it here as a table row,
`` | `old` | `new` | release | ``, for one release; then the old id is gone.
