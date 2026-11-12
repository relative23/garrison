// Metric history charts. Gaps stay gaps: Recharts does not connect null points.
import { useEffect, useRef, useState, type ReactNode } from "react";
import { Bar, BarChart, CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import type { MetricsResponse } from "../api/client";
import { useTranslation } from "../i18n";
import { dateTime, locale, number } from "../lib/format";
import { Card } from "./ui/card";

export interface Series {
  key: string;
  label: string;
}

const COLORS = ["var(--chart-1)", "var(--chart-2)", "var(--chart-3)", "var(--chart-4)", "var(--chart-5)"];

function tick(seconds: number, span: number): string {
  const date = new Date(seconds * 1000);
  return span <= 2 * 86400
    ? date.toLocaleTimeString(locale(), { hour: "2-digit", minute: "2-digit" })
    : date.toLocaleDateString(locale(), { month: "short", day: "numeric" });
}

function label(seconds: unknown): string {
  return typeof seconds === "number" ? dateTime(seconds) : "";
}

/** The chart's place, drawn once it comes near the screen: a page of charts
 * then costs only what can be seen, and the place keeps its height meanwhile. */
function NearScreen({ children }: { children: ReactNode }) {
  const place = useRef<HTMLDivElement>(null);
  const [near, setNear] = useState(false);
  useEffect(() => {
    const element = place.current;
    if (!element || near) return undefined;
    const observer = new IntersectionObserver((entries) => setNear(entries.some((entry) => entry.isIntersecting)), {
      rootMargin: "200px",
    });
    observer.observe(element);
    return () => observer.disconnect();
  }, [near]);
  return (
    <div ref={place} className="h-[220px]">
      {near && children}
    </div>
  );
}

export function MetricChart({
  title,
  history,
  series,
  kind,
  stacked = false,
}: {
  title: string;
  history: MetricsResponse;
  series: Series[];
  kind: "line" | "bar";
  /** Stack bars only where their sum means something. */
  stacked?: boolean;
}) {
  const { t } = useTranslation();
  const present = series.filter((item) => history.points.some((point) => point[item.key] != null));
  const span = history.to - history.from;
  // Bars count events; their sums over the period are the figures people ask for.
  const totals =
    kind === "bar"
      ? present.map((item) => t("common.labelValue", { label: item.label, value: number(history.totals[item.key]) })).join(" · ")
      : "";
  const common = (
    <>
      <CartesianGrid stroke="var(--border)" vertical={false} />
      <XAxis
        dataKey="timestamp"
        tickFormatter={(value: number) => tick(value, span)}
        stroke="var(--muted-foreground)"
        fontSize={12}
        minTickGap={32}
      />
      <YAxis stroke="var(--muted-foreground)" fontSize={12} width={48} tickFormatter={(v: number) => number(v)} />
      <Tooltip
        labelFormatter={label}
        formatter={(value) => number(value)}
        contentStyle={{ background: "var(--popover)", border: "1px solid var(--border)", borderRadius: 8 }}
      />
      <Legend wrapperStyle={{ fontSize: 12 }} />
    </>
  );
  return (
    <Card className="p-4">
      <figure>
        <figcaption className="mb-3 text-sm font-medium">
          {title}
          {totals && <span className="block text-xs font-normal text-muted-foreground">{t("charts.totals", { totals })}</span>}
        </figcaption>
        {present.length === 0 ? (
          <p className="py-8 text-center text-sm text-muted-foreground">{t("charts.empty")}</p>
        ) : (
          <NearScreen>
            <ResponsiveContainer width="100%" height="100%">
              {kind === "line" ? (
                <LineChart data={history.points}>
                  {common}
                  {present.map((item, index) => (
                    <Line
                      key={item.key}
                      dataKey={item.key}
                      name={item.label}
                      stroke={COLORS[index % COLORS.length]}
                      // Isolated samples (with gaps on both sides) are shown as dots.
                      dot={{ r: 2 }}
                      connectNulls={false}
                      isAnimationActive={false}
                    />
                  ))}
                </LineChart>
              ) : (
                <BarChart data={history.points}>
                  {common}
                  {present.map((item, index) => (
                    <Bar
                      key={item.key}
                      dataKey={item.key}
                      name={item.label}
                      fill={COLORS[index % COLORS.length]}
                      stackId={stacked ? "total" : undefined}
                      isAnimationActive={false}
                    />
                  ))}
                </BarChart>
              )}
            </ResponsiveContainer>
          </NearScreen>
        )}
      </figure>
    </Card>
  );
}
