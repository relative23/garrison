// One observation: what was checked, the values, and what it does not prove.
import { useState } from "react";

import type { Observation } from "../api/client";
import { useTranslation } from "../i18n";
import { dateTime, formatValue, relative, type Format } from "../lib/format";
import { EvidenceLabel, StateBadge, type StateName } from "./Status";
import { Button } from "./ui/button";
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from "./ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableHeadRow, TableRow } from "./ui/table";

/** Label and value pairs in two columns, like Stalwart's detail views. */
export function Fields({ items }: { items: { label: string; value: React.ReactNode }[] }) {
  return (
    <dl className="grid gap-x-6 gap-y-3 text-sm sm:grid-cols-2">
      {items.map((item) => (
        <div key={item.label} className="min-w-0">
          <dt className="text-xs text-muted-foreground">{item.label}</dt>
          <dd className="mt-0.5 break-words font-medium">{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

/** A value this long is a key, a digest or a policy rather than a word. */
const LONG_VALUE = 40;

/**
 * A long value breaks inside its cell wherever it must, so that one DKIM key
 * does not push the columns after it out of sight; the cell keeps a width in
 * which it can still be read.
 */
function cellContent(value: React.ReactNode): React.ReactNode {
  if (typeof value !== "string" || value.length <= LONG_VALUE) return value;
  return <span className="block min-w-48 wrap-anywhere">{value}</span>;
}

/** The observation's table; beyond `limit` rows, a button shows the rest. */
function ObservationTable({ observation, limit }: { observation: Observation; limit?: number }) {
  const { t } = useTranslation();
  const [all, setAll] = useState(false);
  const table = observation.table;
  if (!table || table.rows.length === 0) return null;
  const cut = !all && limit !== undefined && table.rows.length > limit;
  const rows = cut ? table.rows.slice(0, limit) : table.rows;
  return (
    <>
      <Table>
        <TableHeader>
          <TableHeadRow>
            {table.columns.map((column) => (
              <TableHead key={column.label}>{column.label}</TableHead>
            ))}
          </TableHeadRow>
        </TableHeader>
        <TableBody>
          {rows.map((row, index) => (
            <TableRow key={index}>
              {row.map((cell, column) => (
                <TableCell key={column}>{cellContent(formatValue(cell, (table.columns[column]?.format ?? "text") as Format))}</TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {cut && (
        <Button variant="outline" size="sm" onClick={() => setAll(true)}>
          {t("observation.showAll", { count: table.rows.length })}
        </Button>
      )}
    </>
  );
}

export function ObservationCard({ observation, limit, className }: { observation: Observation; limit?: number; className?: string }) {
  const { t } = useTranslation();
  const { title, state, stale, evidence, fields, findings, scope, source, checkedAt } = observation;
  return (
    <Card aria-labelledby={`obs-${observation.id}`} className={className}>
      <CardHeader className="flex-row items-start justify-between gap-4 space-y-0">
        <CardTitle id={`obs-${observation.id}`} className="pt-1">
          {title}
        </CardTitle>
        <div className="flex shrink-0 items-center gap-2">
          <EvidenceLabel kind={evidence} />
          <StateBadge state={state as StateName} stale={stale} />
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {findings.length > 0 && (
          <ul className="list-disc space-y-1 pl-5 text-sm">
            {findings.map((finding) => (
              <li key={finding}>{finding}</li>
            ))}
          </ul>
        )}
        {fields.length > 0 && (
          <Fields
            items={fields.map((field) => ({
              label: field.label,
              value: formatValue(field.value, field.format as Format),
            }))}
          />
        )}
        <ObservationTable observation={observation} limit={limit} />
      </CardContent>
      <CardFooter className="flex-col items-start gap-1 text-xs text-muted-foreground">
        {scope && <p>{scope}</p>}
        {/* A source may be an address without a space to break at. */}
        <p className="wrap-anywhere">
          <span title={dateTime(checkedAt)}>{t("observation.checked", { when: relative(checkedAt) })}</span> · {source}
        </p>
      </CardFooter>
    </Card>
  );
}

/** Process and schedule states as one compact table. */
export function ServiceTable({ services }: { services: Observation[] }) {
  const { t } = useTranslation();
  if (services.length === 0) return null;
  return (
    <section aria-labelledby="services-title" className="space-y-2">
      <div className="flex items-center justify-between">
        <h2 id="services-title" className="text-lg font-semibold tracking-tight">
          {t("observation.processes")}
        </h2>
        <EvidenceLabel kind="process" />
      </div>
      <Table>
        <TableHeader>
          <TableHeadRow>
            <TableHead>{t("observation.column.service")}</TableHead>
            <TableHead>{t("observation.column.unit")}</TableHead>
            <TableHead>{t("observation.column.state")}</TableHead>
            <TableHead>{t("observation.column.details")}</TableHead>
          </TableHeadRow>
        </TableHeader>
        <TableBody>
          {services.map((service) => (
            <TableRow key={service.id}>
              <TableCell className="font-medium">{service.title}</TableCell>
              <TableCell>
                <code className="text-xs">{String(service.value.unit ?? service.source)}</code>
              </TableCell>
              <TableCell>
                <StateBadge state={service.state as StateName} stale={service.stale} />
              </TableCell>
              <TableCell className="text-muted-foreground">
                {service.fields
                  .slice(1)
                  .filter((field) => field.value !== null)
                  .map((field) => t("common.labelValue", { label: field.label, value: formatValue(field.value, field.format as Format) }))
                  .join(" · ")}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      <p className="text-xs text-muted-foreground">{t("observation.processHint")}</p>
    </section>
  );
}

export function VersionList({ versions }: { versions: Observation[] }) {
  const { t } = useTranslation();
  if (versions.length === 0) return null;
  return (
    <Card aria-labelledby="versions-title">
      <CardHeader>
        <CardTitle id="versions-title">{t("observation.versions")}</CardTitle>
      </CardHeader>
      <CardContent>
        <Fields
          items={versions.map((item) => ({
            label: String(item.value.component ?? item.title),
            value: (
              <span className="inline-flex items-center gap-2" title={item.scope}>
                {formatValue(item.value.version, "text")} <EvidenceLabel kind={item.evidence} />
              </span>
            ),
          }))}
        />
      </CardContent>
    </Card>
  );
}
