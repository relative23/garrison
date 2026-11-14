// What a user does, in a real Chrome against the preview
// (`cargo run -p garrison-web --example preview`): signing in, every page,
// moving through the menu, also on a phone, searching the event history,
// going Back, the page search on a phone, saving settings, running a
// maintenance action and signing out. Along the way nothing may write an
// error to the console, no request to the preview may fail, and axe may find
// nothing on any page (WCAG 2.2 AA, light and dark, as the system switches
// the page between them); a page as the build drew it starts in the system's
// theme.
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

/** The theme the signed-in user saved; "system" follows the system's. */
let savedTheme = "system";

async function accessible(name) {
  for (const theme of ["light", "dark"]) {
    await page.emulateMedia({ colorScheme: theme });
    // The page follows the system while it is open, so axe sees the theme it is
    // checked in; a theme the user saved (by an earlier run) stays.
    const wanted = savedTheme === "system" ? theme : savedTheme;
    const shown = await page
      .waitForFunction((scheme) => getComputedStyle(document.documentElement).colorScheme === scheme, wanted, { timeout: 2000 })
      .then(
        () => true,
        () => false,
      );
    expect(shown, `${name} shows the ${wanted} theme while the system's is ${theme}`);
    // Colours with a transition fade into the new theme; axe judges them once they have.
    const faded = () => document.getAnimations().every((each) => !(each instanceof CSSTransition) || each.playState !== "running");
    await page.waitForFunction(faded, null, { timeout: 2000 }).catch(() => undefined);
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
  savedTheme = session?.preferences?.theme ?? "system";

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

  step = "menu on a phone";
  await page.setViewportSize(PHONE);
  await page.goto(`${origin}/admin/dashboard`);
  await heading();
  const menu = page.getByRole("navigation", { name: "Garrison" });
  expect(!(await menu.isVisible()), "the closed menu is out of sight");
  // From the header's last entry, Tab goes on to the page, past the closed menu.
  await page.locator("header").getByRole("link", { name: "Account" }).focus();
  await page.keyboard.press("Tab");
  expect(await page.evaluate(() => !document.activeElement?.closest("aside")), "the closed menu takes no focus");
  await page.getByRole("button", { name: "Open menu" }).click();
  await menu.getByRole("link", { name: "Services", exact: true }).click();
  await page.waitForURL(`${origin}/admin/services`);
  expect((await heading()) === "Services", "the open menu leads to its pages");
  await page.setViewportSize(DESKTOP);

  step = "back";
  await page.goto(`${origin}/admin/services`);
  await heading();
  // The interface leads away from a page it does not have; Back then skips that page.
  await page.goto(`${origin}/admin/nowhere`);
  await page.waitForURL(`${origin}/admin/dashboard`);
  await page.goBack();
  const back = await page.waitForURL(`${origin}/admin/services`, { timeout: 3000 }).then(
    () => true,
    () => false,
  );
  expect(back, `Back returns to the page before (it is at ${new URL(page.url()).pathname})`);

  step = "page search on a phone";
  await page.setViewportSize(PHONE);
  await page.goto(`${origin}/admin/dashboard`);
  await heading();
  // The header has no room for the search button here; the shortcut still works.
  await page.keyboard.press("Control+k");
  expect(await page.getByRole("dialog", { name: "Search pages" }).isVisible(), "Ctrl+K shows the page search on a small screen too");
  await page.keyboard.type("spam");
  await page.keyboard.press("Enter");
  const found = await page.waitForURL(`${origin}/admin/spam`, { timeout: 3000 }).then(
    () => true,
    () => false,
  );
  expect(found, "the page search leads to the page typed");
  if (!found) await page.keyboard.press("Escape");
  await page.setViewportSize(DESKTOP);

  step = "first paint";
  // A page as the build drew it, before any of its code runs: the system's theme.
  for (const [name, path, signedIn] of [
    ["sign-in", "/admin/", false],
    ["services", "/admin/services", true],
  ]) {
    for (const theme of ["light", "dark"]) {
      const drawn = await browser.newContext({ viewport: DESKTOP, colorScheme: theme });
      if (signedIn) await drawn.addCookies(await context.cookies());
      const first = await drawn.newPage();
      await first.route("**/admin/assets/*.js", (route) => route.abort());
      await first.goto(`${origin}${path}`);
      const scheme = await first.evaluate(() => getComputedStyle(document.documentElement).colorScheme);
      expect(scheme === theme, `the drawn ${name} page starts in the system's ${theme} theme, not ${scheme}`);
      await drawn.close();
    }
  }

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
console.log(`Passed: sign-in, ${PAGES.length} pages, menu, search, phone, back, first paint, settings, maintenance and sign-out.`);
