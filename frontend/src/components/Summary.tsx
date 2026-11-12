// What the summaries over a period share: the period tabs, the row of
// figures and the titled sections with their tables.
import type { ReactNode } from "react";

import { useTranslation } from "../i18n";
import { number } from "../lib/format";
import { CARD } from "./ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./ui/tabs";
import { cn } from "../lib/utils";

const PERIODS = [
  { id: "24h", unit: "summary.periodHours", count: 24 },
  { id: "7d", unit: "summary.periodDays", count: 7 },
  { id: "30d", unit: "summary.periodDays", count: 30 },
] as const;

export type Period = (typeof PERIODS)[number]["id"];

function isPeriod(value: string): value is Period {
  return PERIODS.some((period) => period.id === value);
}

/** The period tabs with the summary of the chosen period below them. */
export function PeriodTabs({ period, onChange, children }: { period: Period; onChange: (period: Period) => void; children: ReactNode }) {
  const { t } = useTranslation();
  return (
    <Tabs value={period} onValueChange={(value) => isPeriod(value) && onChange(value)} className="space-y-4">
      <TabsList aria-label={t("summary.period")}>
        {PERIODS.map((item) => (
          <TabsTrigger key={item.id} value={item.id}>
            {t(item.unit, { count: item.count })}
          </TabsTrigger>
        ))}
      </TabsList>
      <TabsContent value={period} className="space-y-6">
        {children}
      </TabsContent>
    </Tabs>
  );
}

/** Counts side by side, each under its label. */
export function Figures({ items }: { items: [label: string, value: number][] }) {
  return (
    <dl className="grid grid-cols-2 gap-4 sm:grid-cols-3 xl:grid-cols-5">
      {items.map(([label, value]) => (
        <div key={label} className={cn(CARD, "p-4")}>
          <dt className="text-xs text-muted-foreground">{label}</dt>
          <dd className="mt-1.5 text-2xl font-semibold tracking-tight">{number(value)}</dd>
        </div>
      ))}
    </dl>
  );
}

/** A titled part of a summary; its table is named by the title's `id`. */
export function Section({ id, title, children }: { id: string; title: string; children: ReactNode }) {
  return (
    <div className="space-y-2">
      <h2 id={id} className="text-lg font-semibold tracking-tight">
        {title}
      </h2>
      {children}
    </div>
  );
}

/** A column of counts: right-aligned, digits of equal width. */
export const COUNT = "text-right tabular-nums";
