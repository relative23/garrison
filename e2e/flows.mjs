// What a user does, in a real Chrome against the preview
// (`cargo run -p garrison-web --example preview`): signing in, every page,
// moving through the menu, searching the event history, saving settings,
// running a maintenance action and signing out. Along the way nothing may
// write an error to the console, no request to the preview may fail, and axe
// may find nothing on any page (WCAG 2.2 AA, light and dark).
//
// It is a check, not a measurement: it exits with 1 and lists what failed.
// `measure.mjs` measures the same pages with Lighthouse, by hand.
//
//   npm run flows -- [--url http://localhost:18091]
import AxeBuilder from "@axe-core/playwright";
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
const PAGES = [
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
const AXE_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"];

const failures = [];
let step = "start";
const fail = (message) => failures.push(`${step}: ${message}`);
const expect = (condition, message) => condition || fail(message);

const browser = await chromium.launch({ channel: "chrome" });
const DESKTOP = { width: 1350, height: 940 };
const PHONE = { width: 412, height: 823 };
const context = await browser.newContext({ viewport: DESKTOP });
const page = await context.newPage();
// Whatever goes wrong behind a step is that step's failure.
page.on("console", (message) => message.type() === "error" && fail(`console: ${message.text()}`));
page.on("pageerror", (error) => fail(`script: ${error.message}`));
// A signed-out visit asks for the session and may be told there is none.
const expected = new Set();
page.on("response", (response) => {
  const url = new URL(response.url());
  const key = `${response.status()} ${url.pathname}`;
  if (url.origin === origin && response.status() >= 400 && !expected.delete(key)) fail(`${key} answered`);
});

/** The page's main heading once it has loaded. */
async function heading() {
  await page.waitForLoadState("networkidle");
  return (await page.locator("h1").first().innerText()).trim();
}

async function accessible(name) {
  for (const theme of ["light", "dark"]) {
    await page.emulateMedia({ colorScheme: theme });
    const { violations } = await new AxeBuilder({ page }).withTags(AXE_TAGS).analyze();
    for (const violation of violations) fail(`axe on ${name} (${theme}): ${violation.id}, ${violation.help}`);
  }
  await page.emulateMedia({ colorScheme: "light" });
  // Reflow (WCAG 1.4.10), which axe cannot judge: at a phone's width the page
  // itself is no wider than the screen; a wide table scrolls inside its frame.
  await page.setViewportSize(PHONE);
  // Charts follow the new width a moment later; a page that is too wide stays so.
  const fits = await page
    .waitForFunction(() => document.documentElement.scrollWidth <= window.innerWidth, null, { timeout: 3000 })
    .then(
      () => true,
      () => false,
    );
  if (!fits) {
    const beyond = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    fail(`${name} is ${beyond} px wider than a phone's screen`);
  }
  await page.setViewportSize(DESKTOP);
}

try {
  step = "signed out";
  expected.add("401 /api/status");
  expect((await page.request.get(`${origin}/api/status`)).status() === 401, "the API answers without a session");
  await page.goto(`${origin}/admin/`);
  expect((await heading()) === "Garrison", "the sign-in page is shown");
  await accessible("sign-in");

  step = "sign in";
  await page.getByRole("link", { name: "Sign in with Stalwart" }).click();
  await page.waitForURL(`${origin}/admin/`);
  expect((await heading()) === "Dashboard", "the dashboard follows the sign-in");
  const { session } = await (await page.request.get(`${origin}/api/session`)).json();
  expect(Boolean(session?.email), "the session names the user");

  for (const name of PAGES) {
    step = `page ${name}`;
    await page.goto(`${origin}/admin/${name}`);
    expect((await heading()).length > 0, "the page has a heading");
    expect((await page.locator("main").count()) === 1, "the page has one main region");
    await accessible(name);
  }

  step = "menu";
  await page.goto(`${origin}/admin/dashboard`);
  await heading();
  await page.getByRole("navigation").getByRole("link", { name: "Services", exact: true }).click();
  await page.waitForURL(`${origin}/admin/services`);
  expect((await heading()) === "Services", "a menu entry opens its page without a reload");
  await page.getByRole("button", { name: "Mail flow" }).click();
  await page.getByRole("navigation").getByRole("link", { name: "Event history" }).click();
  await page.waitForURL(`${origin}/admin/logs`);
  expect((await heading()) === "Event history", "a menu group opens and leads to its pages");

  step = "search";
  const searched = page.waitForResponse((response) => response.url().includes("/api/events?") && response.url().includes("search=example"));
  await page.getByRole("searchbox").fill("example");
  await page.getByRole("button", { name: "Search", exact: true }).click();
  expect((await searched).status() === 200, "the event history answers a search");

  step = "settings";
  await page.goto(`${origin}/admin/preferences`);
  await heading();
  await page.getByRole("radio", { name: /dark/i }).check();
  const saved = page.waitForResponse((response) => response.url().endsWith("/api/preferences") && response.request().method() === "PUT");
  await page.getByRole("button", { name: "Save settings" }).click();
  expect((await saved).status() === 200, "the settings are saved");
  await page.reload();
  await heading();
  expect(await page.evaluate(() => document.documentElement.classList.contains("dark")), "the saved theme is used after a reload");

  step = "maintenance";
  const catalog = await (await page.request.get(`${origin}/api/actions`)).json();
  const action = catalog.actions[0];
  await page.goto(`${origin}/admin/actions`);
  await heading();
  await page.getByRole("button", { name: "Run…" }).first().click();
  const start = page.getByRole("button", { name: "Start", exact: true });
  expect(await start.isDisabled(), "an action does not start before its phrase is typed");
  await page.getByLabel(`Type ${action.confirmation} to confirm.`).fill(action.confirmation);
  const submitted = page.waitForResponse((response) => response.url().endsWith("/api/actions") && response.request().method() === "POST");
  await start.click();
  expect((await submitted).status() === 202, "a confirmed action is accepted");

  step = "sign out";
  await page.goto(`${origin}/admin/account`);
  await heading();
  await page.getByRole("button", { name: "Sign out" }).click();
  await page.getByRole("link", { name: "Sign in with Stalwart" }).waitFor();
  const after = await (await page.request.get(`${origin}/api/session`)).json();
  expect(after.session === null, "the session is gone");
} catch (error) {
  fail(error.message.split("\n")[0]);
} finally {
  await browser.close();
}

if (failures.length > 0) {
  console.log(failures.join("\n"));
  process.exit(1);
}
console.log(`Passed: sign-in, ${PAGES.length} pages, menu, search, settings, maintenance and sign-out.`);
