// Event history: every recorded Stalwart event, newest first.
import { RefreshCw } from "lucide-react";
import { useState } from "react";

import { api } from "../api/client";
import { Correlation, CoverageBanner, Pager, SearchForm, Toolbar, useCoverage, useCursors } from "../components/Events";
import { ErrorState, Loading } from "../components/Status";
import { Button } from "../components/ui/button";
import { Select } from "../components/ui/input";
import { Table, TableBody, TableCell, TableEmpty, TableHead, TableHeader, TableHeadRow, TableRow } from "../components/ui/table";
import { useTranslation } from "../i18n";
import { dateTime, text } from "../lib/format";
import { useResource } from "../lib/useResource";

// The category filter values the server accepts; "" means all categories.
const CATEGORIES = [
  "",
  "smtp",
  "queue",
  "delivery",
  "message-ingest",
  "milter",
  "mta-hook",
  "auth",
  "security",
  "spam",
  "tls",
  "server",
  "telemetry",
] as const;

export function Logs() {
  const { t } = useTranslation();
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("");
  const cursors = useCursors();
  const before = cursors.before;
  const page = useResource((signal) => api.events({ search, category, before, limit: 50 }, signal), [search, category, before]);
  const coverage = useCoverage();
  if (!coverage.data && !coverage.error) return <Loading />;
  return (
    <>
      <CoverageBanner data={coverage.data} />
      <Toolbar>
        <SearchForm
          value={search}
          placeholder={t("logs.search")}
          onSearch={(value) => {
            setSearch(value);
            cursors.newest();
          }}
        />
        <Select
          aria-label={t("logs.category")}
          value={category}
          onChange={(event) => {
            setCategory(event.target.value);
            cursors.newest();
          }}
        >
          {CATEGORIES.map((value) => (
            <option key={value} value={value}>
              {t(`logs.categories.${value || "all"}`)}
            </option>
          ))}
        </Select>
        <Button variant="outline" size="icon" onClick={page.reload} aria-label={t("common.refresh")}>
          <RefreshCw aria-hidden />
        </Button>
      </Toolbar>
      {page.error && <ErrorState error={page.error} retry={page.reload} />}
      {!page.data && !page.error && <Loading />}
      {page.data && (
        <Table>
          <TableHeader>
            <TableHeadRow>
              <TableHead>{t("logs.column.time")}</TableHead>
              <TableHead>{t("logs.column.event")}</TableHead>
              <TableHead>{t("logs.column.details")}</TableHead>
              <TableHead>{t("logs.column.related")}</TableHead>
            </TableHeadRow>
          </TableHeader>
          <TableBody>
            {page.data.items.length === 0 && <TableEmpty columns={4}>{t("logs.empty")}</TableEmpty>}
            {page.data.items.map((event) => (
              <TableRow key={event.seq}>
                <TableCell className="whitespace-nowrap">{dateTime(event.createdAt)}</TableCell>
                <TableCell>
                  {event.label}
                  <code className="block text-xs text-muted-foreground">{event.type}</code>
                </TableCell>
                <TableCell className="max-w-xl break-words text-muted-foreground">
                  {Object.entries(event.fields)
                    .filter(([key]) => key !== "spanId" && key !== "queueId")
                    .map(([key, value]) => t("common.labelValue", { label: key, value: text(value) }))
                    .join(" · ")}
                </TableCell>
                <TableCell>
                  <Correlation event={event} />
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
