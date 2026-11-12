// Building blocks shared by Event history, Deliveries and Sessions.
import { ArrowLeft, Search } from "lucide-react";
import { useState, type FormEvent, type ReactNode } from "react";

import { api, type Coverage, type EventItem } from "../api/client";
import { useTranslation } from "../i18n";
import { dateTime, milliseconds, number, relative, text } from "../lib/format";
import { follow, href } from "../lib/router";
import { useResource, type Resource } from "../lib/useResource";
import { Notice } from "./Status";
import { Button } from "./ui/button";
import { Input } from "./ui/input";

const REASONS = ["receiver-offline"] as const;
const LIMITS = ["events", "bytes"] as const;

function isReason(reason: string): reason is (typeof REASONS)[number] {
  return (REASONS as readonly string[]).includes(reason);
}

function isLimit(limit: string): limit is (typeof LIMITS)[number] {
  return (LIMITS as readonly string[]).includes(limit);
}

function Details({ summary, children }: { summary: string; children: ReactNode }) {
  return (
    <details className="mt-2 text-sm">
      <summary className="cursor-pointer text-muted-foreground hover:text-foreground">{summary}</summary>
      <ul className="mt-1 list-disc space-y-0.5 pl-5">{children}</ul>
    </details>
  );
}

/** What the history covers. An event view waits for it before it shows
 * anything, so the banner does not push the list down when it arrives. */
export function useCoverage(): Resource<Coverage> {
  return useResource((signal) => api.coverage(signal), [], 60);
}

/** The coverage on every event view. */
export function CoverageBanner({ data }: { data: Coverage | null }) {
  const { t } = useTranslation();
  if (!data) return null;
  if (!data.available) {
    return <Notice tone="warning">{t("events.coverage.unavailable")}</Notice>;
  }
  // What may be wrong: the receiver is quiet, or events are missing inside the history.
  const warnings = [];
  if (data.receiver !== "running") {
    warnings.push(
      data.heartbeatAt == null
        ? t("events.coverage.receiverQuiet")
        : t("events.coverage.receiverQuietSince", { time: dateTime(data.heartbeatAt) }),
    );
  }
  if (data.gapCount > 0) warnings.push(t("events.coverage.gapsFound", { count: data.gapCount }));
  // A size limit that shortened the history works as configured: said, not warned about.
  const notes = [];
  if (data.trimmed) {
    const limit = isLimit(data.trimmed.limit) ? data.trimmed.limit : "other";
    notes.push(t(`events.coverage.trimmed.${limit}`, { time: dateTime(data.trimmed.until) }));
  }
  const summary = t("events.coverage.summary", {
    since: dateTime(data.recordingSince),
    events: t("events.coverage.count", { count: data.eventCount, value: number(data.eventCount) }),
    // Events that stop arriving while the receiver runs point at Stalwart's webhook.
    received:
      data.lastBatchAt == null ? t("events.coverage.receivedNever") : t("events.coverage.received", { when: relative(data.lastBatchAt) }),
    retention:
      data.retentionDays == null ? t("events.coverage.retentionUnknown") : t("events.coverage.retention", { count: data.retentionDays }),
  });
  return (
    <Notice tone={warnings.length ? "warning" : "info"}>
      <p>{[summary, ...notes, ...warnings].join(" ")}</p>
      {data.gaps.length > 0 && (
        <Details summary={t("events.coverage.gaps")}>
          {data.gaps.map((gap) => (
            <li key={`${gap.start}-${gap.reason}`}>
              {t("events.coverage.gap", {
                start: dateTime(gap.start),
                end: dateTime(gap.end),
                reason: isReason(gap.reason) ? t(`events.gapReason.${gap.reason}`) : gap.reason,
              })}
            </li>
          ))}
        </Details>
      )}
      <Details summary={t("events.coverage.canShow")}>
        {data.limitations.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </Details>
    </Notice>
  );
}

export function SearchForm({ value, onSearch, placeholder }: { value: string; onSearch: (value: string) => void; placeholder: string }) {
  const { t } = useTranslation();
  const [draft, setDraft] = useState(value);
  const submit = (event: FormEvent) => {
    event.preventDefault();
    onSearch(draft.trim());
  };
  return (
    <form className="flex w-full max-w-md items-center gap-2" role="search" onSubmit={submit}>
      <div className="relative flex-1">
        <Search aria-hidden className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
        <Input
          type="search"
          value={draft}
          maxLength={200}
          placeholder={placeholder}
          aria-label={placeholder}
          className="pl-8"
          onChange={(event) => setDraft(event.target.value)}
        />
      </div>
      <Button type="submit" variant="outline">
        {t("common.search")}
      </Button>
    </form>
  );
}

/** Search, filters and buttons above a list. */
export function Toolbar({ children }: { children: ReactNode }) {
  return <div className="flex flex-wrap items-center gap-2">{children}</div>;
}

const HIDDEN_FIELDS = new Set(["spanId", "queueId"]);

/** Events in time order with their recorded fields. */
export function EventTimeline({ events }: { events: EventItem[] }) {
  return (
    <ol className="relative space-y-3 border-l pl-5">
      {events.map((event) => (
        <li key={event.seq} className="relative">
          <span aria-hidden className="absolute -left-[25px] top-1.5 h-2 w-2 rounded-full bg-muted-foreground" />
          <time className="text-xs text-muted-foreground" dateTime={new Date(event.createdAt * 1000).toISOString()}>
            {dateTime(event.createdAt)}
          </time>
          <div className="text-sm">
            <span className="font-medium">{event.label}</span> <code className="text-xs text-muted-foreground">{event.type}</code>
          </div>
          <dl className="mt-1 flex flex-wrap gap-x-4 gap-y-0.5 text-xs">
            {Object.entries(event.fields)
              .filter(([key]) => !HIDDEN_FIELDS.has(key))
              .map(([key, value]) => (
                <div key={key} className="flex gap-1">
                  <dt className="text-muted-foreground">{key}</dt>
                  <dd>{key === "elapsed" && typeof value === "number" ? milliseconds(value) : text(value)}</dd>
                </div>
              ))}
          </dl>
        </li>
      ))}
    </ol>
  );
}

const LINK = "text-sm underline-offset-4 hover:underline";

export function InternalLink({ view, detail, children }: { view: string; detail?: string | null; children: ReactNode }) {
  return (
    <a className={LINK} href={href(view, detail)} onClick={(event) => follow(event, view, detail)}>
      {children}
    </a>
  );
}

export function BackLink({ view, label }: { view: string; label: string }) {
  return (
    <InternalLink view={view}>
      <span className="inline-flex items-center gap-1 text-muted-foreground">
        <ArrowLeft aria-hidden className="h-4 w-4" /> {label}
      </span>
    </InternalLink>
  );
}

export function Correlation({ event }: { event: EventItem }) {
  const { t } = useTranslation();
  return (
    <span className="flex flex-col gap-0.5">
      {event.queueId && (
        <InternalLink view="deliveries" detail={event.queueId}>
          {t("events.queue", { id: event.queueId.slice(-6) })}
        </InternalLink>
      )}
      {event.spanId && event.category === "smtp" && (
        <InternalLink view="sessions" detail={event.spanId}>
          {t("events.session", { id: event.spanId.slice(-6) })}
        </InternalLink>
      )}
    </span>
  );
}

export interface Cursors {
  /** The cursor of the page shown; null for the newest page. */
  before: string | null;
  older: (next: string) => void;
  newest: () => void;
}

/** Keyset paging of a list, newest first: the cursors of the pages opened so far. */
export function useCursors(): Cursors {
  const [cursors, setCursors] = useState<string[]>([]);
  return {
    before: cursors.at(-1) ?? null,
    older: (next) => setCursors([...cursors, next]),
    newest: () => setCursors([]),
  };
}

/** The footer under a list: how many rows are shown and the page buttons. */
export function Pager({ cursors, page }: { cursors: Cursors; page: { items: unknown[]; next: string | null } | null }) {
  const { t } = useTranslation();
  const shown = page?.items.length ?? 0;
  const next = page?.next;
  const newest = cursors.before === null;
  return (
    <div className="flex items-center justify-between text-sm text-muted-foreground">
      <span>{newest ? t("events.showingNewest", { count: shown }) : t("events.showing", { count: shown })}</span>
      <div className="flex gap-2">
        <Button variant="outline" size="sm" disabled={newest} onClick={cursors.newest}>
          {t("events.newest")}
        </Button>
        <Button variant="outline" size="sm" disabled={!next} onClick={() => next && cursors.older(next)}>
          {t("events.older")}
        </Button>
      </div>
    </div>
  );
}
