// The screenshots of the README, taken in a real Chrome from the preview as a
// busy mail server, whose data is made up from reserved example names and
// addresses (crates/web/examples/preview/busy.rs):
//
//   cargo run -p garrison-web --example preview -- 18091 --busy
//   npm run screenshots -- [--url http://localhost:18091] [--out ../.github/screenshots]
//
// Each picture is what a visitor sees at the top of a page on a laptop
// screen, at twice the density so that it stays sharp on GitHub. `pngquant`
// makes the files small afterwards, where it is installed.
import { execFileSync } from "node:child_process";
import { mkdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

import { chromium } from "playwright";

const options = Object.fromEntries(
  process.argv
    .slice(2)
    .join(" ")
    .split("--")
    .filter(Boolean)
    .map((part) => part.trim().split(/\s+/)),
);
const origin = options.url ?? "http://localhost:18091";
// Beside the workflows, not in docs/: a release archive carries docs/ to every
// host, and these pictures are only for the repository's page.
const out = resolve(options.out ?? join(import.meta.dirname, "..", ".github", "screenshots"));
const SCREEN = { width: 1440, height: 900 };

/** Brings the heading `name` up to just below the page's header. Cards and
 * charts drawn as they come near the screen move the page, so twice. */
async function bringUp(page, name) {
  const heading = page.getByRole("heading", { name, exact: true }).first();
  for (let pass = 0; pass < 2; pass += 1) {
    await heading.evaluate((element) => {
      element.style.scrollMarginTop = "90px";
      element.scrollIntoView({ block: "start" });
    });
    await page.waitForTimeout(1200);
  }
}

/** The pictures: file name, page, theme, and what to do on the page first. */
const SHOTS = [
  { name: "dashboard", view: "dashboard", theme: "dark" },
  {
    name: "dashboard-history",
    view: "dashboard",
    theme: "dark",
    before: async (page) => {
      await page.getByRole("tab", { name: "7 days" }).click();
      await bringUp(page, "History");
    },
  },
  { name: "attacks", view: "attacks", theme: "dark", before: (page) => page.getByRole("tab", { name: "7 days" }).click() },
  { name: "sending-accounts", view: "attacks", theme: "light", before: (page) => bringUp(page, "Sending accounts") },
  {
    name: "delivery-problems",
    view: "deliveries",
    theme: "light",
    before: async (page) => {
      await page.getByRole("tab", { name: "Problems by destination" }).click();
      await page.getByRole("tab", { name: "7 days" }).click();
    },
  },
  { name: "spam-filter", view: "spam", theme: "light" },
  { name: "dns-tls", view: "dns_tls", theme: "dark", before: (page) => bringUp(page, "Reverse names") },
  { name: "antivirus", view: "antivirus", theme: "dark", before: (page) => bringUp(page, "Test messages") },
  { name: "backups", view: "backups", theme: "light" },
  { name: "services", view: "services", theme: "light" },
  { name: "sessions", view: "sessions", theme: "dark" },
];

mkdirSync(out, { recursive: true });
const browser = await chromium.launch({ channel: "chrome" });
const context = await browser.newContext({ viewport: SCREEN, deviceScaleFactor: 2 });
const page = await context.newPage();
let failed = false;
try {
  await page.goto(`${origin}/admin/`);
  await page.getByRole("link", { name: "Sign in with Stalwart" }).click();
  await page.waitForURL(`${origin}/admin/`);
  for (const shot of SHOTS) {
    await page.emulateMedia({ colorScheme: shot.theme });
    await page.goto(`${origin}/admin/${shot.view}`);
    await page.waitForLoadState("networkidle");
    await shot.before?.(page);
    await page.waitForLoadState("networkidle");
    // Charts draw a moment after their data arrives; the pointer rests where
    // it opens no tooltip.
    await page.mouse.move(4, 4);
    await page.waitForTimeout(600);
    const file = join(out, `${shot.name}.png`);
    await page.screenshot({ path: file });
    try {
      execFileSync("pngquant", ["--force", "--skip-if-larger", "--quality", "70-95", "--output", file, file]);
    } catch {
      // Without pngquant, or where it would not help, the picture stays as taken.
    }
    console.log(`${shot.name}.png  ${Math.round(statSync(file).size / 1024)} KiB  (${shot.view}, ${shot.theme})`);
  }
} catch (error) {
  failed = true;
  console.error(`Failed: ${error.message}`);
} finally {
  await browser.close();
}
process.exit(failed ? 1 : 0);
