// Delivery problems: delays and bounces of outgoing mail by destination and
// cause, and the messages that still wait.
import { useState } from "react";

import { api, type Destinations } from "../api/client";
import { InternalLink } from "../components/Events";
import { ErrorState, Loading, Meta, Notice } from "../components/Status";
import { COUNT, Figures, PeriodTabs, Section, type Period } from "../components/Summary";
import { Table, TableBody, TableCell, TableEmpty, TableHead, TableHeader, TableHeadRow, TableRow } from "../components/ui/table";
import { useTranslation } from "../i18n";
import { dateTime, duration, number } from "../lib/format";
import { useResource } from "../lib/useResource";

function ByDestination({ destinations }: { destinations: Destinations["destinations"] }) {
  const { t } = useTranslation();
  return (
    <Table aria-labelledby="problems-destinations">
      <TableHeader>
        <TableHeadRow>
          <TableHead>{t("problems.column.domain")}</TableHead>
          <TableHead className={COUNT}>{t("problems.column.bounces")}</TableHead>
          <TableHead className={COUNT}>{t("problems.column.delays")}</TableHead>
          <TableHead className={COUNT}>{t("problems.column.delivered")}</TableHead>
          <TableHead>{t("problems.column.cause")}</TableHead>
          <TableHead>{t("problems.column.lastProblem")}</TableHead>
        </TableHeadRow>
      </TableHeader>
      <TableBody>
        {destinations.length === 0 && <TableEmpty columns={6}>{t("problems.empty.destinations")}</TableEmpty>}
        {destinations.map((destination) => (
          <TableRow key={destination.domain}>
            <TableCell>
              <span className="wrap-anywhere">{destination.domain}</span>
              {destination.hosts.length > 0 && (
                <span className="block text-xs text-muted-foreground wrap-anywhere">{destination.hosts.join(", ")}</span>
              )}
            </TableCell>
            <TableCell className={COUNT}>{number(destination.bounces)}</TableCell>
            <TableCell className={COUNT}>{number(destination.delays)}</TableCell>
            <TableCell className={COUNT}>{number(destination.delivered)}</TableCell>
            <TableCell>
              <span className="block min-w-48 wrap-anywhere">{destination.cause}</span>
            </TableCell>
            <TableCell className="whitespace-nowrap">{dateTime(destination.lastProblem)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function ByCause({ causes }: { causes: Destinations["causes"] }) {
  const { t } = useTranslation();
  return (
    <Table aria-labelledby="problems-causes">
      <TableHeader>
        <TableHeadRow>
          <TableHead>{t("problems.column.cause")}</TableHead>
          <TableHead className={COUNT}>{t("problems.column.bounces")}</TableHead>
          <TableHead className={COUNT}>{t("problems.column.delays")}</TableHead>
          <TableHead className={COUNT}>{t("problems.column.domains")}</TableHead>
          <TableHead>{t("problems.column.lastSeen")}</TableHead>
        </TableHeadRow>
      </TableHeader>
      <TableBody>
        {causes.length === 0 && <TableEmpty columns={5}>{t("problems.empty.causes")}</TableEmpty>}
        {causes.map((cause) => (
          <TableRow key={cause.cause}>
            <TableCell>
              <span className="block min-w-48 wrap-anywhere">{cause.cause}</span>
            </TableCell>
            <TableCell className={COUNT}>{number(cause.bounces)}</TableCell>
            <TableCell className={COUNT}>{number(cause.delays)}</TableCell>
            <TableCell className={COUNT}>{number(cause.domains)}</TableCell>
            <TableCell className="whitespace-nowrap">{dateTime(cause.lastSeen)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function Waiting({ waiting, until }: { waiting: Destinations["waiting"]; until: number }) {
  const { t } = useTranslation();
  return (
    <Table aria-labelledby="problems-waiting">
      <TableHeader>
        <TableHeadRow>
          <TableHead>{t("problems.column.queue")}</TableHead>
          <TableHead>{t("problems.column.queued")}</TableHead>
          <TableHead>{t("problems.column.waiting")}</TableHead>
          <TableHead>{t("problems.column.lastEvent")}</TableHead>
        </TableHeadRow>
      </TableHeader>
      <TableBody>
        {waiting.length === 0 && <TableEmpty columns={4}>{t("problems.empty.waiting")}</TableEmpty>}
        {waiting.map((message) => (
          <TableRow key={message.queueId}>
            <TableCell>
              <InternalLink view="deliveries" detail={message.queueId}>
                {message.queueId.slice(-8)}
              </InternalLink>
            </TableCell>
            <TableCell className="whitespace-nowrap">{dateTime(message.queuedAt)}</TableCell>
            <TableCell className="whitespace-nowrap">{duration(until - message.queuedAt)}</TableCell>
            <TableCell className="whitespace-nowrap">{dateTime(message.lastEvent)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

export function DeliveryProblems() {
  const { t } = useTranslation();
  const [period, setPeriod] = useState<Period>("24h");
  const summary = useResource((signal) => api.destinations(period, signal), [period], 60);
  const data = summary.data;
  return (
    <PeriodTabs period={period} onChange={setPeriod}>
      {summary.error && <ErrorState error={summary.error} retry={summary.reload} />}
      {!data && !summary.error && <Loading />}
      {data && (
        <>
          {data.truncated && <Notice tone="warning">{t("problems.truncated")}</Notice>}
          <Figures
            items={[
              [t("problems.figure.bounces"), data.totals.bounces],
              [t("problems.figure.delays"), data.totals.delays],
              [t("problems.figure.delivered"), data.totals.delivered],
              [t("problems.figure.destinations"), data.totals.destinations],
              [t("problems.figure.waiting"), data.totals.waiting],
            ]}
          />
          <Section id="problems-destinations" title={t("problems.destinations")}>
            <ByDestination destinations={data.destinations} />
          </Section>
          <Section id="problems-causes" title={t("problems.causes")}>
            <ByCause causes={data.causes} />
          </Section>
          <Section id="problems-waiting" title={t("problems.waiting")}>
            <Waiting waiting={data.waiting} until={data.until} />
            <Meta>{t("problems.waitingNote")}</Meta>
          </Section>
          <Meta>{t("problems.footer", { from: dateTime(data.since), to: dateTime(data.until) })}</Meta>
        </>
      )}
    </PeriodTabs>
  );
}
