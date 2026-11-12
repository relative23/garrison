// Interface texts. Every visible string lives in a catalog; en.json is the
// source and the fallback, so a missing translation shows English, never a key.
// Texts the server sends (observations, events, job messages) stay as sent.
import { cloneElement, createElement, Fragment, type ReactElement, type ReactNode } from "react";

import en from "./en.json";

/** One catalog per language; a new language is one more JSON file here. */
export const CATALOGS = { en } as const;

export type Language = keyof typeof CATALOGS;

/** The first browser language that has a catalog, else English. */
export function preferredLanguage(tags: readonly string[]): Language {
  for (const tag of tags) {
    const base = tag.toLowerCase().split("-")[0] ?? "";
    if (Object.hasOwn(CATALOGS, base)) return base as Language;
  }
  return "en";
}

type PluralForm = "zero" | "one" | "two" | "few" | "many" | "other";

/** The keys of a catalog, nested names joined by dots. A plural's forms
 * (`count_one`, `count_other`) answer to their base name as well, so `t`
 * with a key en.json lacks fails the type check. */
type Keys<T, Prefix extends string = ""> = {
  [K in keyof T & string]: T[K] extends string
    ? `${Prefix}${K extends `${infer Base}_${PluralForm}` ? Base | K : K}`
    : Keys<T[K], `${Prefix}${K}.`>;
}[keyof T & string];

export type Key = Keys<typeof en>;

type Catalog = { readonly [name: string]: string | Catalog };

const language = preferredLanguage(typeof navigator === "undefined" ? [] : navigator.languages);
const plurals = new Intl.PluralRules(language);
const RIGHT_TO_LEFT = new Set(["ar", "dv", "fa", "he", "ku", "ps", "ur", "yi"]);

function lookup(catalog: Catalog, key: string): string | undefined {
  let at: string | Catalog | undefined = catalog;
  for (const name of key.split(".")) at = typeof at === "object" ? at[name] : undefined;
  return typeof at === "string" ? at : undefined;
}

/** The text for `key` in the interface language, else in English. A number
 * `count` picks the plural form; `{{name}}` takes `values.name` as it is,
 * unescaped, since React escapes what it renders. */
function t(key: Key, values: Record<string, string | number> = {}): string {
  const forms = typeof values.count === "number" ? [`${key}_${plurals.select(values.count)}`, `${key}_other`, key] : [key];
  let text: string | undefined;
  for (const catalog of [CATALOGS[language], CATALOGS.en]) {
    for (const form of forms) text ??= lookup(catalog, form);
  }
  return (text ?? key).replace(/{{\s*(\w+)\s*}}/g, (whole, name: string) => (Object.hasOwn(values, name) ? String(values[name]) : whole));
}

export const i18n = { t, language, dir: RIGHT_TO_LEFT.has(language) ? "rtl" : "ltr" } as const;

if (typeof document !== "undefined") {
  document.documentElement.lang = i18n.language;
  document.documentElement.dir = i18n.dir;
}

/** `t` for views; the language does not change while a page is open. */
export function useTranslation() {
  return { t };
}

/** A catalog text with markup: `<name>text</name>` renders `components.name`
 * with the text inside, `<name/>` renders it as given. Everything else stays
 * text, never markup: dynamic text goes in as a component's child. */
export function Trans({ i18nKey, components }: { i18nKey: Key; components: Record<string, ReactElement> }) {
  const text = t(i18nKey);
  const parts: ReactNode[] = [];
  let rest = 0;
  for (const match of text.matchAll(/<(\w+)\s*\/>|<(\w+)>(.*?)<\/\2>/g)) {
    const [whole, single, name = "", inner] = match;
    const component = components[single ?? name];
    parts.push(text.slice(rest, match.index));
    if (!component) parts.push(whole);
    else if (single) parts.push(cloneElement(component, { key: parts.length }));
    else parts.push(cloneElement(component, { key: parts.length }, inner));
    rest = match.index + whole.length;
  }
  parts.push(text.slice(rest));
  return createElement(Fragment, null, ...parts);
}
