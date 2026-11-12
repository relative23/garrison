// Deliveries: queue lifecycles correlated from recorded events.
import { useState } from "react";

import { api, type DeliveriesPage, type DeliverySummary } from "../api/client";
import {
  BackLink,
  CoverageBanner,
  EventTimeline,
  InternalLink,
  Pager,
  SearchForm,
  type Cursors,
  Toolbar,
  useCoverage,
  useCursors,
} from "../components/Events";
import { Fields } from "../components/ObservationCard";
import { ErrorState, Loading, Notice } from "../components/Status";
import { Badge, type BadgeTone } from "../components/ui/badge";
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from "../components/ui/card";
import { Table, TableBody, TableCell, TableEmpty, TableHead, TableHeader, TableHeadRow, TableRow } from "../components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../components/ui/tabs";
import { useTranslation } from "../i18n";
import { dateTime, text } from "../lib/format";
import { useResource, type Resource } from "../lib/useResource";
import { DeliveryProblems } from "./DeliveryProblems";
import type { ViewProps } from "./registry";

const STATUS = ["delivered", "completed", "queued", "in-progress", "deferred", "failed", "partial", "unknown"] as const;

function isStatus(status: string): status is (typeof STATUS)[number] {
  return (STATUS as readonly string[]).includes(status);
}

function tone(status: string): BadgeTone {
  if (status === "delivered" || status === "completed") return "ok";
  if (status === "failed") return "failed";
  if (status === "deferred" || status === "partial") return "warning";
  return "unknown";
}

function useStatusLabel() {
  const { t } = useTranslation();
  // A status this build does not know is shown as the server named it.
  return (status: string) => (isStatus(status) ? t(`deliveries.status.${status}`) : status);
}

function DeliveryStatus({ summary }: { summary: DeliverySummary }) {
  const { t } = useTranslation();
  const label = useStatusLabel();
  return (
    <Badge
      tone={tone(summary.status)}
      title={summary.recipientEvidenceComplete ? t("deliveries.evidenceComplete") : t("deliveries.evidenceIncomplete")}
    >
      {label(summary.status)}
      {!summary.recipientEvidenceComplete && t("deliveries.incomplete")}
    </Badge>
  );
}

function Detail({ queueId }: { queueId: string }) {
  const { t } = useTranslation();
  const label = useStatusLabel();
  const detail = useResource((signal) => api.delivery(queueId, signal), [queueId]);
  if (detail.error) return <ErrorState error={detail.error} retry={detail.reload} />;
  if (!detail.data) return <Loading />;
  const { summary, events, truncated } = detail.data;
  return (
    <>
      <BackLink view="deliveries" label={t("deliveries.all")} />
      <Card>
        <CardHeader className="flex-row items-start justify-between gap-4 space-y-0">
          <CardTitle className="pt-1">{t("deliveries.queue", { id: summary.queueId })}</CardTitle>
          <DeliveryStatus summary={summary} />
        </CardHeader>
        <CardContent className="space-y-4">
          <Fields
            items={[
              { label: t("deliveries.field.from"), value: text(summary.from) },
              { label: t("deliveries.field.firstSeen"), value: dateTime(summary.firstSeen) },
              { label: t("deliveries.field.lastSeen"), value: dateTime(summary.lastSeen) },
              { label: t("deliveries.field.recordedEvents"), value: summary.eventCount },
            ]}
          />
          <Table>
            <TableHeader>
              <TableHeadRow>
                <TableHead>{t("deliveries.field.recipient")}</TableHead>
                <TableHead>{t("deliveries.field.outcome")}</TableHead>
              </TableHeadRow>
            </TableHeader>
            <TableBody>
              {summary.to.map((address) => (
                <TableRow key={address}>
                  <TableCell>{text(address)}</TableCell>
                  <TableCell>{label(summary.recipientOutcomes[address] ?? "unknown")}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
        <CardFooter className="text-xs text-muted-foreground">{t("deliveries.delivered")}</CardFooter>
      </Card>
      {truncated && <Notice tone="warning">{t("deliveries.truncated")}</Notice>}
      <EventTimeline events={events} />
    </>
  );
}

export function Deliveries({ detail }: ViewProps) {
  return detail ? <Detail queueId={detail} /> : <Views />;
}

/** The messages one by one, or their problems summed by destination. */
function Views() {
  const { t } = useTranslation();
  const coverage = useCoverage();
  // The list is asked for with the page, not once the coverage is known, and
  // its search stays while the other tab is open.
  const [search, setSearch] = useState("");
  const cursors = useCursors();
  const before = cursors.before;
  const page = useResource((signal) => api.deliveries({ search, before, limit: 25 }, signal), [search, before], 30);
  if (!coverage.data && !coverage.error) return <Loading />;
  return (
    <>
      <CoverageBanner data={coverage.data} />
      <Tabs defaultValue="messages" className="space-y-4">
        <TabsList aria-label={t("deliveries.views")}>
          <TabsTrigger value="messages">{t("deliveries.view.messages")}</TabsTrigger>
          <TabsTrigger value="problems">{t("deliveries.view.problems")}</TabsTrigger>
        </TabsList>
        <TabsContent value="messages" className="space-y-4">
          <List page={page} cursors={cursors} search={search} setSearch={setSearch} />
        </TabsContent>
        <TabsContent value="problems">
          <DeliveryProblems />
        </TabsContent>
      </Tabs>
    </>
  );
}

interface ListProps {
  page: Resource<DeliveriesPage>;
  cursors: Cursors;
  search: string;
  setSearch: (value: string) => void;
}

function List({ page, cursors, search, setSearch }: ListProps) {
  const { t } = useTranslation();
  return (
    <>
      <Toolbar>
        <SearchForm
          value={search}
          placeholder={t("deliveries.search")}
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
              <TableHead>{t("deliveries.column.lastActivity")}</TableHead>
              <TableHead>{t("deliveries.column.from")}</TableHead>
              <TableHead>{t("deliveries.column.to")}</TableHead>
              <TableHead>{t("deliveries.column.status")}</TableHead>
              <TableHead>{t("deliveries.column.queue")}</TableHead>
            </TableHeadRow>
          </TableHeader>
          <TableBody>
            {page.data.items.length === 0 && <TableEmpty columns={5}>{t("deliveries.empty")}</TableEmpty>}
            {page.data.items.map((item) => (
              <TableRow key={item.queueId}>
                <TableCell className="whitespace-nowrap">{dateTime(item.lastSeen)}</TableCell>
                <TableCell>{text(item.from)}</TableCell>
                <TableCell>
                  {text(item.to.slice(0, 3))}
                  {item.to.length > 3 && ` +${item.to.length - 3}`}
                </TableCell>
                <TableCell>
                  <DeliveryStatus summary={item} />
                </TableCell>
                <TableCell>
                  <InternalLink view="deliveries" detail={item.queueId}>
                    {item.queueId.slice(-8)}
                  </InternalLink>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
      <Pager cursors={cursors} page={page.data} />
    </>
  );
}
