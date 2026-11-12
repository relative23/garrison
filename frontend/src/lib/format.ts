// Value formatting shared by every view. Missing values are shown as "Unknown",
// never as zero or as an empty success.
import { i18n } from "../i18n";

export function unknown(): string {
  return i18n.t("format.unknown");
}

/** Formats follow the interface language, using the browser's regional variant
 * of it when it has one, e.g. en-GB dates for an English interface. */
export function locale(): string {
  const language = i18n.language;
  const tags = typeof navigator === "undefined" ? [] : navigator.languages;
  return tags.find((tag) => tag.toLowerCase().split("-")[0] === language) ?? language;
}

function decimal(value: number, digits: number): string {
  return value.toLocaleString(locale(), { minimumFractionDigits: digits, maximumFractionDigits: digits });
}

export function bytes(value: unknown): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return unknown();
  // A change can be negative, such as the free space a disk loses a day.
  if (value < 0) return `\u2212${bytes(-value)}`;
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let amount = value;
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024;
    unit += 1;
  }
  return `${decimal(amount, unit === 0 ? 0 : 1)} ${units[unit]}`;
}

/** Accepts ISO strings or Unix seconds. */
function toDate(value: unknown): Date | null {
  if (typeof value === "number" && Number.isFinite(value)) return new Date(value * 1000);
  if (typeof value === "string" && value) {
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? null : parsed;
  }
  return null;
}

export function dateTime(value: unknown): string {
  const date = toDate(value);
  return date ? date.toLocaleString(locale(), { dateStyle: "medium", timeStyle: "short" }) : unknown();
}

export function relative(value: unknown, now: number = Date.now()): string {
  const date = toDate(value);
  if (!date) return unknown();
  const seconds = Math.round((now - date.getTime()) / 1000);
  if (seconds < -60) return i18n.t("format.inFuture", { duration: duration(-seconds) });
  if (seconds < 60) return i18n.t("format.justNow");
  return i18n.t("format.ago", { duration: duration(seconds) });
}

export function duration(value: unknown): string {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) return unknown();
  const seconds = Math.round(value);
  if (seconds < 60) return i18n.t("format.seconds", { value: number(seconds) });
  if (seconds < 3600) return i18n.t("format.minutes", { value: number(Math.round(seconds / 60)) });
  if (seconds < 86400) return i18n.t("format.hours", { value: decimal(seconds / 3600, 1) });
  return i18n.t("format.days", { value: decimal(seconds / 86400, 1) });
}

/** Stalwart reports `elapsed` in milliseconds; under a minute, tenths of a second count. */
export function milliseconds(value: number): string {
  if (value < 1000) return i18n.t("format.milliseconds", { value: number(value) });
  if (value < 60_000) return i18n.t("format.seconds", { value: decimal(value / 1000, 1) });
  return duration(value / 1000);
}

/** A whole number of days, such as a certificate's remaining validity. */
export function days(value: unknown): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return unknown();
  return i18n.t("format.wholeDays", { count: value, value: number(value) });
}

export function gib(value: unknown): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return unknown();
  return i18n.t("format.gib", { value: number(value) });
}

export function number(value: unknown): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return unknown();
  return Number.isInteger(value) ? value.toLocaleString(locale()) : value.toLocaleString(locale(), { maximumFractionDigits: 2 });
}

export function boolean(value: unknown): string {
  return value === true ? i18n.t("format.yes") : value === false ? i18n.t("format.no") : unknown();
}

// Code points that hide or reorder text: controls, bidirectional embeddings,
// overrides and isolates, and zero-width characters. An SMTP peer chooses its
// EHLO name, its addresses and its replies, so these are shown, not applied.
const HIDDEN: readonly (readonly [number, number])[] = [
  [0x0000, 0x001f],
  [0x007f, 0x009f],
  [0x00ad, 0x00ad],
  [0x061c, 0x061c],
  [0x180e, 0x180e],
  [0x200b, 0x200f],
  [0x202a, 0x202e],
  [0x2060, 0x2069],
  [0xfeff, 0xfeff],
];

function visible(value: string): string {
  let shown = "";
  for (const character of value) {
    const point = character.codePointAt(0) ?? 0;
    const hidden = HIDDEN.some(([low, high]) => point >= low && point <= high);
    shown += hidden ? `[U+${point.toString(16).toUpperCase().padStart(4, "0")}]` : character;
  }
  return shown;
}

/** A recorded value as text; hidden characters appear as their code point. */
export function text(value: unknown): string {
  if (value === null || value === undefined || value === "") return unknown();
  if (Array.isArray(value)) return value.map((item) => text(item)).join(", ");
  if (typeof value === "object") return visible(JSON.stringify(value));
  return visible(String(value));
}

export type Format = "text" | "number" | "bytes" | "datetime" | "duration" | "boolean" | "url";

export function formatValue(value: unknown, format: Format): string {
  switch (format) {
    case "bytes":
      return bytes(value);
    case "datetime":
      return dateTime(value);
    case "duration":
      return duration(value);
    case "number":
      return number(value);
    case "boolean":
      return boolean(value);
    default:
      return text(value);
  }
}

/** Accept only plain https links without credentials for clickable URLs. */
export function safeUrl(value: unknown): string | null {
  if (typeof value !== "string") return null;
  try {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password ? url.href : null;
  } catch {
    return null;
  }
}
