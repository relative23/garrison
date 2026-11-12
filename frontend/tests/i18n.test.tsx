import { render } from "@testing-library/react";

import { CATALOGS, i18n, preferredLanguage, Trans } from "../src/i18n";
import { locale } from "../src/lib/format";

type Catalog = { [key: string]: string | Catalog };

function flatten(catalog: Catalog, prefix = ""): Map<string, string> {
  const entries = new Map<string, string>();
  for (const [key, value] of Object.entries(catalog)) {
    if (typeof value === "string") entries.set(prefix + key, value);
    else for (const [inner, text] of flatten(value, `${prefix}${key}.`)) entries.set(inner, text);
  }
  return entries;
}

const placeholders = (text: string) => [...text.matchAll(/{{\s*(\w+)\s*}}|<(\w+)\s*\/?>/g)].map((m) => m[1] ?? m[2] ?? "").sort();

describe("interface language", () => {
  it("uses the first browser language that has a catalog, else English", () => {
    // "zz" stands for any language without a catalog.
    expect(preferredLanguage(["zz-ZZ", "EN-gb"])).toBe("en");
    expect(preferredLanguage(["zz"])).toBe("en");
    expect(preferredLanguage([])).toBe("en");
    expect(i18n.language).toBe("en");
    expect(document.documentElement.lang).toBe("en");
    expect(document.documentElement.dir).toBe("ltr");
  });

  it("formats in the browser's regional variant of the interface language", () => {
    expect(locale()).toMatch(/^en(-|$)/);
  });

  it("fills placeholders and plural forms without HTML entities", () => {
    expect(i18n.t("events.showing", { count: 1 })).toBe("Showing 1 entry");
    expect(i18n.t("events.showing", { count: 2 })).toBe("Showing 2 entries");
    expect(i18n.t("sessions.title", { ip: "<b>192.0.2.1</b>" })).toBe("SMTP session from <b>192.0.2.1</b>");
  });

  it("renders a configured phrase inside a sentence as text, never as markup", () => {
    const phrase = "<strong>restart</strong> & {{x}}";
    const { container } = render(<Trans i18nKey="actions.confirm" components={{ phrase: <code>{phrase}</code> }} />);
    expect(container.textContent).toBe(`Type ${phrase} to confirm.`);
    expect(container.querySelector("strong")).toBeNull();
  });

  it("puts a tag's text from the catalog into its component", () => {
    const { container } = render(<Trans i18nKey="account.access" components={{ code: <code className="c" /> }} />);
    expect(container.querySelector("code.c")?.textContent).toBe("garrison access");
    expect(container.textContent).toBe(
      "Access is granted by your Stalwart roles and the Garrison access policy. Administrators manage it with garrison access on the server.",
    );
  });

  it("shows a tag without a component as text, and a placeholder without a value as written", () => {
    const { container } = render(<Trans i18nKey="account.access" components={{}} />);
    expect(container.textContent).toContain("with <code>garrison access</code> on the server.");
    expect(i18n.t("sessions.title")).toBe("SMTP session from {{ip}}");
  });

  it("keeps every translation in step with the English catalog", () => {
    const english = flatten(CATALOGS.en);
    for (const [language, catalog] of Object.entries(CATALOGS)) {
      for (const [key, text] of flatten(catalog)) {
        // Languages have different plural forms; English needs only the base key.
        const base = key.replace(/_(zero|one|two|few|many|other)$/, "");
        const plural = base !== key;
        const source = english.get(key) ?? english.get(`${base}_other`) ?? english.get(base);
        expect(source, `${language}: ${key} is not in en.json`).toBeDefined();
        const expected = placeholders(source ?? "");
        const used = placeholders(text);
        // A plural form may leave out the number ("one entry"); nothing else may differ.
        const optional = plural ? ["count", "value"] : [];
        expect(
          used.filter((name) => !expected.includes(name)),
          `${language}: ${key}`,
        ).toEqual([]);
        expect(
          expected.filter((name) => !used.includes(name) && !optional.includes(name)),
          `${language}: ${key}`,
        ).toEqual([]);
      }
    }
  });
});
