// Dashboard: health per module, key figures, mailbox storage and recorded
// metric history.
import { lazy, Suspense, useDeferredValue, useState } from "react";

import { api, type MetricsResponse, type Observation } from "../api/client";
import { ObservationCard } from "../components/ObservationCard";
import { ErrorState, Loading, Meta, Notice, StateBadge, type StateName } from "../components/Status";
import { CARD } from "../components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../components/ui/tabs";
import { useTranslation } from "../i18n";
import { useApp } from "../lib/context";
import { dateTime, days, duration, gib, number, unknown } from "../lib/format";
import { follow, href } from "../lib/router";
import { useResource } from "../lib/useResource";
import { cn } from "../lib/utils";
import { moduleText, VIEWS } from "./registry";

// Recharts is large; load it only when the dashboard shows history.
const MetricChart = lazy(() => import("../components/Charts").then((m) => ({ default: m.MetricChart })));

const PERIODS = [
  { id: "24h", unit: "dashboard.periodHours", count: 24 },
  { id: "7d", unit: "dashboard.periodDays", count: 7 },
  { id: "30d", unit: "dashboard.periodDays", count: 30 },
  { id: "90d", unit: "dashboard.periodDays", count: 90 },
] as const;

/** Rows shown on the dashboard; the full list belongs to the observation. */
const MAILBOX_ROWS = 10;

/** The most urgent state; a stale observation no longer shows its last state. */
function worst(items: Observation[]): StateName {
  for (const state of ["failed", "warning", "partial", "unknown"] as const) {
    if (items.some((item) => (item.stale ? "unknown" : item.state) === state)) return state;
  }
  return "ok";
}

function SectionTitle({ id, children }: { id: string; children: string }) {
  return (
    <h2 id={id} className="text-lg font-semibold tracking-tight">
      {children}
    </h2>
  );
}

function HealthGrid() {
  const { t } = useTranslation();
  const { session, status } = useApp();
  const observations = status.data?.observations ?? [];
  const modules = session.modules.filter((module) => module.id !== "dashboard" && observations.some((o) => o.modules.includes(module.id)));
  if (modules.length === 0) return null;
  return (
    <section aria-labelledby="health-title" className="space-y-2">
      <SectionTitle id="health-title">{t("dashboard.health")}</SectionTitle>
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {modules.map((module) => {
          const mine = observations.filter((item) => item.modules.includes(module.id));
          const stale = mine.filter((item) => item.stale).length;
          const attention = mine.filter((item) => item.state !== "ok").length;
          const Icon = VIEWS[module.id]?.icon;
          return (
            <a
              key={module.id}
              href={href(module.id)}
              onClick={(event) => follow(event, module.id)}
              className={cn(CARD, "flex flex-col gap-3 p-4 transition-colors hover:bg-accent/50")}
            >
              <span className="flex items-center justify-between gap-2">
                <span className="flex items-center gap-2 text-sm font-medium">
                  {Icon && <Icon aria-hidden className="h-4 w-4 text-muted-foreground" />} {moduleText(module, "label")}
                </span>
                <StateBadge state={worst(mine)} />
              </span>
              <span className="text-xs text-muted-foreground">
                {t("dashboard.checks", { count: mine.length })}
                {attention > 0 && t("dashboard.attention", { count: attention })}
                {stale > 0 && t("dashboard.stale", { count: stale })}
              </span>
            </a>
          );
        })}
      </div>
    </section>
  );
}

function MailboxStorage() {
  const { status } = useApp();
  const observation = status.data?.observations.find((item) => item.id === "stalwart.mailboxes");
  if (!observation) return null;
  return (
    // The card carries its own "Mailbox storage" title.
    <ObservationCard observation={observation} limit={MAILBOX_ROWS} />
  );
}

function Figures({ history }: { history: MetricsResponse }) {
  const { t } = useTranslation();
  const latest = history.latest;
  const items: [string, string][] = [
    [t("dashboard.figure.queuedMessages"), number(latest.queue_count)],
    [t("dashboard.figure.healthyServices"), number(latest.healthy_services)],
    [t("dashboard.figure.shortestCertificate"), days(latest.tls_days)],
    [t("dashboard.figure.signatureAge"), latest.signature_age_hours == null ? unknown() : duration(latest.signature_age_hours * 3600)],
    [t("dashboard.figure.memoryUsed"), gib(latest.ram_used_gib)],
    [t("dashboard.figure.diskFree"), gib(latest.disk_free_gib)],
  ];
  return (
    <dl className="grid gap-4 sm:grid-cols-3 xl:grid-cols-6">
      {items.map(([label, value]) => (
        <div key={label} className={cn(CARD, "p-4")}>
          <dt className="text-xs text-muted-foreground">{label}</dt>
          <dd className="mt-1.5 text-2xl font-semibold tracking-tight">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

const CHARTS = [
  {
    title: "dashboard.chart.mailFlow",
    kind: "bar",
    series: [
      { key: "queue_message_queued", label: "dashboard.series.received" },
      { key: "queue_authenticated_message_queued", label: "dashboard.series.submitted" },
      { key: "delivery_completed", label: "dashboard.series.delivered" },
    ],
  },
  {
    title: "dashboard.chart.classification",
    kind: "bar",
    // Ham and spam add up to every message ingested.
    stacked: true,
    series: [
      { key: "message_ingest_ham", label: "dashboard.series.ham" },
      { key: "message_ingest_spam", label: "dashboard.series.spam" },
      { key: "milter_action_reject", label: "dashboard.series.milterRejected" },
    ],
  },
  {
    title: "dashboard.chart.security",
    kind: "bar",
    series: [
      { key: "auth_failed", label: "dashboard.series.authFailed" },
      { key: "security_authentication_ban", label: "dashboard.series.bans" },
    ],
  },
  {
    title: "dashboard.chart.connections",
    kind: "line",
    series: [
      { key: "smtp_connections", label: "dashboard.series.smtp" },
      { key: "imap_connections", label: "dashboard.series.imap" },
      { key: "http_connections", label: "dashboard.series.http" },
    ],
  },
  {
    title: "dashboard.chart.resources",
    kind: "line",
    series: [
      { key: "ram_used_gib", label: "dashboard.series.memoryUsed" },
      { key: "disk_free_gib", label: "dashboard.series.diskFree" },
      { key: "load_1m", label: "dashboard.series.load" },
    ],
  },
  { title: "dashboard.chart.queue", kind: "line", series: [{ key: "queue_count", label: "dashboard.series.queuedMessages" }] },
] as const;

function History() {
  const { t } = useTranslation();
  const [period, setPeriod] = useState("24h");
  const history = useResource((signal) => api.metrics({ period }, signal), [period], 60);
  const data = history.data;
  // The charts draw at low priority and in slices, so the page stays responsive.
  const charts = useDeferredValue(data, null);
  return (
    <section aria-labelledby="history-title">
      {/* The period tabs control the panel below, which shows the chosen period. */}
      <Tabs value={period} onValueChange={setPeriod} className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <SectionTitle id="history-title">{t("dashboard.history")}</SectionTitle>
          <TabsList aria-label={t("dashboard.period")}>
            {PERIODS.map((item) => (
              <TabsTrigger key={item.id} value={item.id}>
                {t(item.unit, { count: item.count })}
              </TabsTrigger>
            ))}
          </TabsList>
        </div>
        <TabsContent value={period} className="space-y-3">
          {history.error && <ErrorState error={history.error} retry={history.reload} />}
          {!data && !history.error && <Loading />}
          {data && (
            <>
              <Figures history={data} />
              <Meta>
                {data.sampledMinutes > 0
                  ? t("dashboard.samples", { from: dateTime(data.coverageFrom), to: dateTime(data.coverageTo) })
                  : t("dashboard.noSamples")}{" "}
                {t("dashboard.gaps")}
                {data.counterResets > 0 && t("dashboard.counterResets", { count: data.counterResets })}
              </Meta>
              {charts && (
                <Suspense fallback={<Loading label={t("dashboard.loadingCharts")} />}>
                  <div className="grid gap-4 lg:grid-cols-2 2xl:grid-cols-3">
                    {CHARTS.map((chart) => (
                      <MetricChart
                        key={chart.title}
                        title={t(chart.title)}
                        kind={chart.kind}
                        stacked={"stacked" in chart}
                        history={charts}
                        series={chart.series.map((item) => ({ key: item.key, label: t(item.label) }))}
                      />
                    ))}
                  </div>
                </Suspense>
              )}
            </>
          )}
        </TabsContent>
      </Tabs>
    </section>
  );
}

export function Dashboard() {
  const { t } = useTranslation();
  const { session, status } = useApp();
  // The sections above the history need the status: until it settles the
  // history waits too, so nothing moves down when the status arrives.
  if (!status.data && !status.error) return <Loading />;
  return (
    <>
      <HealthGrid />
      <MailboxStorage />
      <History />
      {session.modules.length === 1 && <Notice>{t("dashboard.dashboardOnly")}</Notice>}
    </>
  );
}
