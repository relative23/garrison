// Sessions: SMTP sessions reconstructed from recorded events.
import { useState } from "react";

import { api, type SessionSummary } from "../api/client";
import {
  BackLink,
  CoverageBanner,
  EventTimeline,
  InternalLink,
  Pager,
  SearchForm,
  Toolbar,
  useCoverage,
  useCursors,
} from "../components/Events";
import { Fields } from "../components/ObservationCard";
import { ErrorState, Loading, Notice } from "../components/Status";
import { Badge } from "../components/ui/badge";
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from "../components/ui/card";
import { Table, TableBody, TableCell, TableEmpty, TableHead, TableHeader, TableHeadRow, TableRow } from "../components/ui/table";
import { useTranslation } from "../i18n";
import { dateTime, duration, text } from "../lib/format";
import { useResource } from "../lib/useResource";
import type { ViewProps } from "./registry";

const CHECKS = ["spf-ehlo", "spf-from", "dkim", "arc", "dmarc", "iprev"] as const;

function isCheck(check: string): check is (typeof CHECKS)[number] {
  return (CHECKS as readonly string[]).includes(check);
}

function Checks({ session }: { session: SessionSummary }) {
  const { t } = useTranslation();
  const entries = Object.entries(session.authentication);
  if (entries.length === 0) return <span className="text-muted-foreground">{t("sessions.noneRecorded")}</span>;
  return (
    <span className="flex flex-wrap gap-1">
      {entries.map(([check, result]) => (
        <Badge key={check} tone={result === "pass" ? "ok" : "failed"}>
          {isCheck(check) ? t(`sessions.check.${check}`) : check} {result}
        </Badge>
      ))}
    </span>
  );
}

function Detail({ spanId }: { spanId: string }) {
  const { t } = useTranslation();
  const detail = useResource((signal) => api.sessionDetail(spanId, signal), [spanId]);
  if (detail.error) return <ErrorState error={detail.error} retry={detail.reload} />;
  if (!detail.data) return <Loading />;
  const { summary, events, truncated } = detail.data;
  return (
    <>
      <BackLink view="sessions" label={t("sessions.all")} />
      <Card>
        <CardHeader className="flex-row items-start justify-between gap-4 space-y-0">
          <CardTitle className="pt-1">{t("sessions.title", { ip: text(summary.remoteIp) })}</CardTitle>
          {!summary.complete && <Badge tone="warning">{t("sessions.incomplete")}</Badge>}
        </CardHeader>
        <CardContent className="space-y-4">
          <Fields
            items={[
              { label: t("sessions.field.listener"), value: text(summary.listener) },
              { label: t("sessions.field.ehlo"), value: text(summary.ehlo) },
              { label: t("sessions.field.sender"), value: text(summary.from) },
              { label: t("sessions.field.recipients"), value: summary.to.length ? text(summary.to) : t("sessions.noneAccepted") },
              { label: t("sessions.field.started"), value: dateTime(summary.firstSeen) },
              { label: t("sessions.field.duration"), value: duration(summary.lastSeen - summary.firstSeen) },
              { label: t("sessions.field.recordedEvents"), value: summary.eventCount },
              { label: t("sessions.field.authentication"), value: <Checks session={summary} /> },
              {
                label: t("sessions.field.rejections"),
                value: summary.rejections.length ? summary.rejections.join(", ") : t("sessions.field.none"),
              },
            ]}
          />
          {summary.queueIds.length > 0 && (
            <p className="flex flex-wrap gap-2 text-sm">
              {t("sessions.queuedAs")}
              {summary.queueIds.map((id) => (
                <InternalLink key={id} view="deliveries" detail={id}>
                  {id}
                </InternalLink>
              ))}
            </p>
          )}
        </CardContent>
        <CardFooter className="text-xs text-muted-foreground">{t("sessions.footer")}</CardFooter>
      </Card>
      {truncated && <Notice tone="warning">{t("sessions.truncated")}</Notice>}
      <EventTimeline events={events} />
    </>
  );
}

export function Sessions({ detail }: ViewProps) {
  return detail ? <Detail spanId={detail} /> : <List />;
}

function List() {
  const { t } = useTranslation();
  const [search, setSearch] = useState("");
  const cursors = useCursors();
  const before = cursors.before;
  const page = useResource((signal) => api.sessions({ search, before, limit: 25 }, signal), [search, before], 30);
  const coverage = useCoverage();
  if (!coverage.data && !coverage.error) return <Loading />;
  return (
    <>
      <CoverageBanner data={coverage.data} />
      <Toolbar>
        <SearchForm
          value={search}
          placeholder={t("sessions.search")}
          onSearch={(value) => {
            setSearch(value);
            cursors.newest();
          }}
        />
      </Toolbar>
      {page.error && <ErrorState error={page.error} retry={page.reload} />}
      {!page.data && !page.error && <Loading />}
      {page.data && (
        <Table>
          <TableHeader>
            <TableHeadRow>
              <TableHead>{t("sessions.column.started")}</TableHead>
              <TableHead>{t("sessions.column.client")}</TableHead>
              <TableHead>{t("sessions.column.route")}</TableHead>
              <TableHead>{t("sessions.column.checks")}</TableHead>
              <TableHead>{t("sessions.column.rejections")}</TableHead>
            </TableHeadRow>
          </TableHeader>
          <TableBody>
            {page.data.items.length === 0 && <TableEmpty columns={5}>{t("sessions.empty")}</TableEmpty>}
            {page.data.items.map((item) => (
              <TableRow key={item.spanId}>
                <TableCell className="whitespace-nowrap">
                  <InternalLink view="sessions" detail={item.spanId}>
                    {dateTime(item.firstSeen)}
                  </InternalLink>
                </TableCell>
                <TableCell>
                  {text(item.remoteIp)}
                  <span className="block text-xs text-muted-foreground">{text(item.ehlo)}</span>
                </TableCell>
                <TableCell>
                  {text(item.from)} → {item.to.length ? text(item.to) : t("sessions.noRecipients")}
                </TableCell>
                <TableCell>
                  <Checks session={item} />
                </TableCell>
                <TableCell>{item.rejections.join(", ") || "—"}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
      <Pager cursors={cursors} page={page.data} />
    </>
  );
}
