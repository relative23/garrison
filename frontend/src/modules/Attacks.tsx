// Attacks & bans: failed sign-ins, Stalwart's bans and TLS handshake errors
// from the recorded events, by address, network and account.
import { useState } from "react";

import { api, type Attacks as Summary } from "../api/client";
import { CoverageBanner, useCoverage } from "../components/Events";
import { ObservationCard } from "../components/ObservationCard";
import { ErrorState, Loading, Meta, Notice } from "../components/Status";
import { COUNT, Figures, PeriodTabs, Section, type Period } from "../components/Summary";
import { Table, TableBody, TableCell, TableEmpty, TableHead, TableHeader, TableHeadRow, TableRow } from "../components/ui/table";
import { useTranslation } from "../i18n";
import { useApp } from "../lib/context";
import { dateTime, number } from "../lib/format";
import { useResource } from "../lib/useResource";

function Sources({ sources }: { sources: Summary["sources"] }) {
  const { t } = useTranslation();
  return (
    <Table aria-labelledby="attacks-sources">
      <TableHeader>
        <TableHeadRow>
          <TableHead>{t("attacks.column.address")}</TableHead>
          <TableHead className={COUNT}>{t("attacks.column.failedSignIns")}</TableHead>
          <TableHead className={COUNT}>{t("attacks.column.accounts")}</TableHead>
          <TableHead className={COUNT}>{t("attacks.column.tlsErrors")}</TableHead>
          <TableHead className={COUNT}>{t("attacks.column.bans")}</TableHead>
          <TableHead>{t("attacks.column.lastSeen")}</TableHead>
        </TableHeadRow>
      </TableHeader>
      <TableBody>
        {sources.length === 0 && <TableEmpty columns={6}>{t("attacks.empty.sources")}</TableEmpty>}
        {sources.map((source) => (
          <TableRow key={source.address}>
            <TableCell>
              <span className="wrap-anywhere">{source.address}</span>
              {source.listeners.length > 0 && <span className="block text-xs text-muted-foreground">{source.listeners.join(", ")}</span>}
            </TableCell>
            <TableCell className={COUNT}>{number(source.failedSignIns)}</TableCell>
            <TableCell className={COUNT}>{number(source.accounts)}</TableCell>
            <TableCell className={COUNT}>{number(source.tlsErrors)}</TableCell>
            <TableCell className={COUNT}>{number(source.bans)}</TableCell>
            <TableCell className="whitespace-nowrap">{dateTime(source.lastSeen)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function Networks({ networks }: { networks: Summary["networks"] }) {
  const { t } = useTranslation();
  return (
    <Table aria-labelledby="attacks-networks">
      <TableHeader>
        <TableHeadRow>
          <TableHead>{t("attacks.column.network")}</TableHead>
          <TableHead className={COUNT}>{t("attacks.column.addresses")}</TableHead>
          <TableHead className={COUNT}>{t("attacks.column.failedSignIns")}</TableHead>
          <TableHead className={COUNT}>{t("attacks.column.tlsErrors")}</TableHead>
          <TableHead className={COUNT}>{t("attacks.column.bans")}</TableHead>
          <TableHead>{t("attacks.column.lastSeen")}</TableHead>
        </TableHeadRow>
      </TableHeader>
      <TableBody>
        {networks.length === 0 && <TableEmpty columns={6}>{t("attacks.empty.networks")}</TableEmpty>}
        {networks.map((network) => (
          <TableRow key={network.network}>
            <TableCell className="wrap-anywhere">{network.network}</TableCell>
            <TableCell className={COUNT}>{number(network.sources)}</TableCell>
            <TableCell className={COUNT}>{number(network.failedSignIns)}</TableCell>
            <TableCell className={COUNT}>{number(network.tlsErrors)}</TableCell>
            <TableCell className={COUNT}>{number(network.bans)}</TableCell>
            <TableCell className="whitespace-nowrap">{dateTime(network.lastSeen)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function Accounts({ accounts }: { accounts: Summary["accounts"] }) {
  const { t } = useTranslation();
  return (
    <Table aria-labelledby="attacks-accounts">
      <TableHeader>
        <TableHeadRow>
          <TableHead>{t("attacks.column.account")}</TableHead>
          <TableHead className={COUNT}>{t("attacks.column.failedSignIns")}</TableHead>
          <TableHead className={COUNT}>{t("attacks.column.addresses")}</TableHead>
          <TableHead>{t("attacks.column.lastAttempt")}</TableHead>
        </TableHeadRow>
      </TableHeader>
      <TableBody>
        {accounts.length === 0 && <TableEmpty columns={4}>{t("attacks.empty.accounts")}</TableEmpty>}
        {accounts.map((account) => (
          <TableRow key={account.name}>
            <TableCell className="wrap-anywhere">{account.name}</TableCell>
            <TableCell className={COUNT}>{number(account.failedSignIns)}</TableCell>
            <TableCell className={COUNT}>{number(account.sources)}</TableCell>
            <TableCell className="whitespace-nowrap">{dateTime(account.lastSeen)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function Bans({ bans }: { bans: Summary["bans"] }) {
  const { t } = useTranslation();
  return (
    <Table aria-labelledby="attacks-bans">
      <TableHeader>
        <TableHeadRow>
          <TableHead>{t("attacks.column.banned")}</TableHead>
          <TableHead>{t("attacks.column.address")}</TableHead>
          <TableHead>{t("attacks.column.reason")}</TableHead>
        </TableHeadRow>
      </TableHeader>
      <TableBody>
        {bans.length === 0 && <TableEmpty columns={3}>{t("attacks.empty.bans")}</TableEmpty>}
        {bans.map((ban) => (
          <TableRow key={`${ban.at}-${ban.address}-${ban.reason}`}>
            <TableCell className="whitespace-nowrap">{dateTime(ban.at)}</TableCell>
            <TableCell className="wrap-anywhere">{ban.address}</TableCell>
            <TableCell>{t(`attacks.reason.${ban.reason}`)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

export function Attacks() {
  const { t } = useTranslation();
  const [period, setPeriod] = useState<Period>("24h");
  const summary = useResource((signal) => api.attacks(period, signal), [period], 60);
  const coverage = useCoverage();
  const { status } = useApp();
  if (!coverage.data && !coverage.error) return <Loading />;
  const data = summary.data;
  const checks = (status.data?.observations ?? []).filter((item) => item.modules.includes("attacks"));
  return (
    <>
      <CoverageBanner data={coverage.data} />
      <PeriodTabs period={period} onChange={setPeriod}>
        {summary.error && <ErrorState error={summary.error} retry={summary.reload} />}
        {!data && !summary.error && <Loading />}
        {data && (
          <>
            {data.truncated && <Notice tone="warning">{t("attacks.truncated")}</Notice>}
            <Figures
              items={[
                [t("attacks.figure.failedSignIns"), data.totals.failedSignIns],
                [t("attacks.figure.unknownAccounts"), data.totals.unknownAccounts],
                [t("attacks.figure.bans"), data.totals.bans],
                [t("attacks.figure.tlsErrors"), data.totals.tlsErrors],
                [t("attacks.figure.sources"), data.totals.sources],
              ]}
            />
            <Section id="attacks-sources" title={t("attacks.sources")}>
              <Sources sources={data.sources} />
            </Section>
            <Section id="attacks-networks" title={t("attacks.networks")}>
              <Networks networks={data.networks} />
            </Section>
            <Section id="attacks-accounts" title={t("attacks.accounts")}>
              <Accounts accounts={data.accounts} />
              <Meta>{t("attacks.accountsNote")}</Meta>
            </Section>
            <Section id="attacks-bans" title={t("attacks.bans")}>
              <Bans bans={data.bans} />
            </Section>
            <Meta>{t("attacks.footer", { from: dateTime(data.since), to: dateTime(data.until) })}</Meta>
          </>
        )}
      </PeriodTabs>
      {/* What the collector's checks say of this module, such as the accounts that send unusually much.
          They come with the summary above them, not before it: nothing on the page moves down later. */}
      {(data || summary.error) && checks.map((item) => <ObservationCard key={item.id} observation={item} />)}
    </>
  );
}
