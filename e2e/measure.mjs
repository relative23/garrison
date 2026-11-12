// Lighthouse and axe for every page of the interface, against the preview
// (`cargo run -p garrison-web --example preview`): Performance, Accessibility
// and Best Practices on desktop and mobile, then axe's WCAG 2.2 AA rules in
// both themes on both screen sizes. Results go to results/<time>/.
//
// Lighthouse throttles for real here. Its default simulation replays the load
// it saw, and on localhost the scripts arrive before the first paint, so it
// would count the frame drawn into each page's HTML as waiting for them.
//
// The pages are measured over HTTP/2 with TLS, as nginx serves them in
// production: through a proxy in front of the preview (http2.mjs). `--http1`
// measures the preview directly; its six connections per host then hold some
// of a page's requests back for another round trip.
//
// Measure a preview that was just started. The flows (flows.mjs) save the dark
// theme in the preview's session; a page measured after them is drawn light
// and turns dark when the session arrives, which the speed index counts.
//
//   npm run measure -- [--url http://localhost:18091] [--runs 1] [--http1]
//                      [--pages deliveries,logs]
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import AxeBuilder from "@axe-core/playwright";
import * as chromeLauncher from "chrome-launcher";
import lighthouse from "lighthouse";
import desktopConfig from "lighthouse/core/config/desktop-config.js";
import { chromium } from "playwright";

import { startHttp2 } from "./http2.mjs";

const options = Object.fromEntries(
  process.argv
    .slice(2)
    .join(" ")
    .split("--")
    .filter(Boolean)
    .map((part) => part.trim().split(/\s+/)),
);
const preview = options.url ?? "http://localhost:18091";
const proxy = Object.hasOwn(options, "http1") ? null : await startHttp2(preview);
const origin = proxy?.origin ?? preview;
// The proxy's certificate is made for the run.
const INSECURE = ["--ignore-certificate-errors"];
const runs = Number(options.runs ?? 1);
const EVERY_PAGE = [
  "dashboard",
  "services",
  "antivirus",
  "spam",
  "attacks",
  "deliveries",
  "sessions",
  "logs",
  "backups",
  "alerts",
  "dns_tls",
  "actions",
  "preferences",
  "account",
];
// Some pages only, to measure one again or to compare two builds in turn.
const PAGES = options.pages ? EVERY_PAGE.filter((name) => options.pages.split(",").includes(name)) : EVERY_PAGE;
const CATEGORIES = ["performance", "accessibility", "best-practices"];
const VIEWPORTS = { desktop: { width: 1350, height: 940 }, mobile: { width: 412, height: 823 } };
const AXE_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"];

const stamp = new Date().toISOString().replace(/[:.]/g, "-");
const output = join(import.meta.dirname, "results", stamp);
mkdirSync(join(output, "lighthouse"), { recursive: true });

/** The preview's session cookie, from its sign-in that approves at once. */
async function signIn() {
  const browser = await chromium.launch({ channel: "chrome" });
  const context = await browser.newContext();
  const page = await context.newPage();
  // Its sign-in sends the browser back to the preview; the cookie serves every port.
  await page.goto(`${preview}/auth/login`);
  await page.waitForURL(`${preview}/admin/`);
  const cookie = (await context.cookies()).find((each) => each.name === "__Host-garrison_session");
  await browser.close();
  if (!cookie) throw new Error(`no session from ${preview}; is the preview running?`);
  return cookie;
}

const median = (values) => [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];

/** What keeps a category below 100: audits that count and did not pass. */
function shortfalls(lhr, category) {
  return lhr.categories[category].auditRefs
    .filter((ref) => ref.weight > 0 || category !== "performance")
    .map((ref) => lhr.audits[ref.id])
    .filter((audit) => audit.score !== null && audit.score < 1)
    .map((audit) => `${audit.id}${audit.displayValue ? ` (${audit.displayValue})` : ""}`);
}

async function measureLighthouse(cookie) {
  const chrome = await chromeLauncher.launch({ chromeFlags: ["--headless=new", "--no-first-run", ...INSECURE] });
  const results = [];
  try {
    for (const [name, url, headers] of [
      ["sign-in", `${origin}/admin/`, {}],
      ...PAGES.map((page) => [page, `${origin}/admin/${page}`, { Cookie: `${cookie.name}=${cookie.value}` }]),
    ]) {
      for (const form of ["desktop", "mobile"]) {
        const scores = Object.fromEntries(CATEGORIES.map((category) => [category, []]));
        let last;
        for (let run = 0; run < runs; run += 1) {
          const result = await lighthouse(
            url,
            {
              port: chrome.port,
              output: "html",
              logLevel: "error",
              onlyCategories: CATEGORIES,
              throttlingMethod: "devtools",
              extraHeaders: headers,
            },
            form === "desktop" ? desktopConfig : undefined,
          );
          last = result;
          for (const category of CATEGORIES) scores[category].push(Math.round(result.lhr.categories[category].score * 100));
        }
        writeFileSync(join(output, "lighthouse", `${name}-${form}.html`), last.report);
        const entry = { page: name, form };
        for (const category of CATEGORIES) {
          entry[category] = median(scores[category]);
          entry[`${category} shortfalls`] = shortfalls(last.lhr, category);
        }
        entry.metrics = Object.fromEntries(
          ["first-contentful-paint", "largest-contentful-paint", "total-blocking-time", "cumulative-layout-shift", "speed-index"].map(
            (id) => [id, last.lhr.audits[id].displayValue],
          ),
        );
        results.push(entry);
        console.log(`${name.padEnd(12)} ${form.padEnd(8)} ${CATEGORIES.map((category) => `${category} ${entry[category]}`).join("  ")}`);
      }
    }
  } finally {
    chrome.kill();
  }
  return results;
}

async function measureAxe(cookie) {
  const browser = await chromium.launch({ channel: "chrome", args: INSECURE });
  const results = [];
  try {
    for (const [form, viewport] of Object.entries(VIEWPORTS)) {
      for (const theme of ["light", "dark"]) {
        const context = await browser.newContext({ viewport, colorScheme: theme, isMobile: form === "mobile", ignoreHTTPSErrors: true });
        await context.addCookies([{ ...cookie }]);
        const page = await context.newPage();
        for (const name of ["sign-in", ...PAGES]) {
          if (name === "sign-in") await context.clearCookies();
          await page.goto(name === "sign-in" ? `${origin}/admin/` : `${origin}/admin/${name}`);
          await page.waitForLoadState("networkidle");
          const dark = await page.evaluate(() => document.documentElement.classList.contains("dark"));
          const { violations } = await new AxeBuilder({ page }).withTags(AXE_TAGS).analyze();
          // Reflow (WCAG 1.4.10), which axe cannot judge: the page itself must
          // not be wider than the screen; a wide table scrolls inside its frame.
          // Held against the screen, not the window: a phone's browser widens
          // its window to what the page needs.
          const beyond = (await page.evaluate(() => document.documentElement.scrollWidth)) - viewport.width;
          results.push({
            page: name,
            form,
            theme,
            themeApplied: dark === (theme === "dark"),
            beyond: Math.max(0, beyond),
            violations: violations.map((violation) => ({
              id: violation.id,
              impact: violation.impact,
              nodes: violation.nodes.length,
              help: violation.help,
              targets: violation.nodes.slice(0, 3).map((node) => node.target.join(" ")),
            })),
          });
          if (name === "sign-in") await context.addCookies([{ ...cookie }]);
        }
        await context.close();
      }
    }
  } finally {
    await browser.close();
  }
  return results;
}

const cookie = await signIn();
console.log(`Lighthouse, ${runs} run(s) each, median:`);
const scores = await measureLighthouse(cookie);
console.log("axe:");
const accessibility = await measureAxe(cookie);
for (const entry of accessibility) {
  const found = entry.violations.map((violation) => `${violation.id} (${violation.impact}, ${violation.nodes})`).join(", ");
  console.log(
    `${entry.page.padEnd(12)} ${entry.form.padEnd(8)} ${entry.theme.padEnd(6)} ${found || "no violations"}${entry.themeApplied ? "" : "  [theme not applied]"}${entry.beyond ? `  [${entry.beyond} px wider than the screen]` : ""}`,
  );
}
proxy?.close();
const protocol = proxy ? "HTTP/2" : "HTTP/1.1";
writeFileSync(join(output, "summary.json"), JSON.stringify({ origin, protocol, runs, scores, accessibility }, null, 2));
console.log(`Results: ${output}`);
