// Generic page for status modules: it shows every observation that names the
// module. A new collector provider therefore appears here without new code.
import type { Observation } from "../api/client";
import { ObservationCard, ServiceTable, VersionList } from "../components/ObservationCard";
import { ErrorState, Loading, Meta, Notice } from "../components/Status";
import { useTranslation } from "../i18n";
import { useApp } from "../lib/context";
import { dateTime } from "../lib/format";
import type { ViewProps } from "./registry";

const ORDER: Record<string, number> = { failed: 0, warning: 1, partial: 2, unknown: 3, ok: 4 };

function byAttention(a: Observation, b: Observation): number {
  return (ORDER[a.state] ?? 5) - (ORDER[b.state] ?? 5) || a.title.localeCompare(b.title);
}

/** A table of this many columns needs the page's width, not half of it. */
const WIDE_TABLE = 5;

function isWide(item: Observation): boolean {
  return (item.table?.columns.length ?? 0) >= WIDE_TABLE;
}

export function StatusPage({ moduleId }: ViewProps) {
  const { t } = useTranslation();
  const { status } = useApp();
  if (status.error && !status.data) return <ErrorState error={status.error} retry={status.reload} />;
  if (!status.data) return <Loading />;
  if (!status.data.available) {
    return <Notice>{t("statusPage.noSnapshot")}</Notice>;
  }
  const mine = status.data.observations.filter((item) => item.modules.includes(moduleId));
  const services = mine.filter((item) => item.kind === "service");
  const versions = mine.filter((item) => item.kind === "version");
  const details = mine.filter((item) => item.kind === "details").sort(byAttention);
  return (
    <>
      <Meta>{t("statusPage.collected", { date: dateTime(status.data.collectedAt) })}</Meta>
      {moduleId === "services" && status.data.providerErrors.length > 0 && (
        <Notice tone="warning">
          {t("statusPage.providerErrors", { providers: status.data.providerErrors.map((item) => item.provider).join(", ") })}
        </Notice>
      )}
      {mine.length === 0 && <Notice>{t("statusPage.noObservations")}</Notice>}
      {/* One column that is as wide as the page, not as wide as its widest card. */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        {details.map((item) => (
          <ObservationCard key={item.id} observation={item} className={isWide(item) ? "xl:col-span-2" : undefined} />
        ))}
        <VersionList versions={versions} />
      </div>
      <ServiceTable services={services} />
    </>
  );
}
