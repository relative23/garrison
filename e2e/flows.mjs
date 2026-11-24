// What a user does, in a real Chrome against the preview
// (`cargo run -p garrison-web --example preview`): signing in, every page,
// moving through the menu, also on a phone and from the keyboard, searching
// the event history and paging through it from the keyboard, going Back, the
// page search on a phone, saving settings, running a maintenance action from
// the keyboard, what each page shows when a request fails (also over HTTP/2,
// as nginx serves Garrison), a browser whose clock runs hours ahead or
// behind, a session answer without a time left a timer can count, the checks
// of a computer that slept, a profile that grants the dashboard alone, a
// change of rights while a page is open, two tabs that follow what the other
// does, a session the policy refuses, and signing out. Along the way nothing
// may write an error to the console, no request to the preview may fail but
// those a step makes fail, and axe may find nothing on any page (WCAG 2.2 AA,
// light and dark, as the system switches the page between them); a page
// starts in the theme its user chose, from its first frame on, and without a
// session or a choice in the system's.
//
// It is a check, not a measurement: it exits with 1 and lists what failed.
// `measure.mjs` measures the same pages with Lighthouse, by hand.
//
//   npm run flows -- [--url http://localhost:18091]
import AxeBuilder from "@axe-core/playwright";
import { chromium } from "playwright";

import { skewed, slept, untimed } from "./clocks.mjs";
import { failingRequests } from "./failures.mjs";
import { vanishing } from "./focus.mjs";
import { uncertainResult } from "./jobs.mjs";
import { paging } from "./paging.mjs";
import { refusedSession, rightsChange, twoTabs } from "./tabs.mjs";
import { chosenTheme, firstPaint } from "./themes.mjs";

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
// A signed-out visit asks for the session and may be told there is none.
const expected = new Set();
// The answers a step makes fail on purpose, as "status path"; while there are
// any, so are the console's lines about a resource that failed to load.
const failing = new Set();
/** Whatever goes wrong behind a step in `watched` is that step's failure: an
 * error in the console or a script, and a request to `at` that failed. */
function watch(watched, at = origin) {
  watched.on("console", (message) => {
    if (message.type() !== "error") return;
    if (failing.size > 0 && message.text().startsWith("Failed to load resource")) return;
    fail(`console: ${message.text()}`);
  });
  watched.on("pageerror", (error) => fail(`script: ${error.message}`));
  watched.on("response", (response) => {
    const url = new URL(response.url());
    const key = `${response.status()} ${url.pathname}`;
    if (url.origin === at && response.status() >= 400 && !failing.has(key) && !expected.delete(key)) fail(`${key} answered`);
  });
}
watch(page);
/** An answer as the web service gives one when the broker cannot be asked. */
const unavailable = (route) =>
  route.fulfill({
    status: 503,
    contentType: "application/json",
    body: JSON.stringify({ detail: "Authorization is temporarily unavailable" }),
  });
/** Whether the focus is on `locator`'s element. */
const focused = (locator) => locator.evaluate((element) => element === document.activeElement);

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

/** What the steps in the other files (themes.mjs, failures.mjs, tabs.mjs)
 * share with these. */
const shared = {
  browser,
  context,
  origin,
  DESKTOP,
  /** The step that follows: its name heads what fails in it. */
  at: (name) => {
    step = name;
  },
  expect,
  watch,
  unavailable,
  failing,
  /** The theme the signed-in user saved, as read at the sign-in. */
  savedTheme: () => savedTheme,
  /** axe in both themes and the phone's width, on the flows' own tab. */
  accessible,
};

try {
  step = "signed out";
  expected.add("401 /api/status");
  expect((await page.request.get(`${origin}/api/status`)).status() === 401, "the API answers without a session");
  await page.goto(`${origin}/admin/`);
  expect((await heading()) === "Garrison", "the sign-in page is shown");
  await accessible("sign-in");
  // Where the web service sends a sign-in back for a fault of its own.
  await page.goto(`${origin}/admin/?login_error=internal&reference=0123456789ab`);
  await heading();
  expect(
    await page.getByText("Reference 0123456789ab in the journal of garrison-web").isVisible(),
    "a sign-in that Garrison's own fault ended shows the journal's reference",
  );
  await accessible("sign-in after a fault of Garrison's own");

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

  await paging(shared, page);
  await vanishing(shared, page);

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
  // Opened, the menu takes the focus at once, while it slides in: a key
  // pressed straight away does not pass it by. The focus is tried the moment
  // the page has written the change, as the slide begins.
  const reached = await page.evaluate(
    () =>
      new Promise((done) => {
        const toggle = [...document.querySelectorAll("header button")].find((button) => button.getAttribute("aria-label") === "Open menu");
        const first = document.querySelector("aside nav a");
        if (!toggle || !first) return done(false);
        new MutationObserver((_, observer) => {
          if (toggle.getAttribute("aria-expanded") !== "true") return;
          observer.disconnect();
          first.focus();
          done(document.activeElement === first);
        }).observe(toggle, { attributes: true, attributeFilter: ["aria-expanded"] });
        toggle.click();
      }),
  );
  expect(reached, "the menu takes the focus as soon as it opens");
  await page.getByRole("button", { name: "Open menu" }).click();
  await menu.waitFor({ state: "hidden" });
  await page.getByRole("button", { name: "Open menu" }).click();
  await menu.getByRole("link", { name: "Services", exact: true }).click();
  await page.waitForURL(`${origin}/admin/services`);
  expect((await heading()) === "Services", "the open menu leads to its pages");
  // From the keyboard: Enter opens the menu, and Escape and its close button
  // close it on the button that opened it.
  const toggle = page.getByRole("button", { name: "Open menu" });
  for (const close of ["Escape", "the close button"]) {
    await toggle.focus();
    await page.keyboard.press("Enter");
    await menu.waitFor({ state: "visible" });
    if (close === "Escape") await page.keyboard.press("Escape");
    else await page.getByRole("button", { name: "Close menu" }).press("Enter");
    const closed = await menu.waitFor({ state: "hidden", timeout: 2000 }).then(
      () => true,
      () => false,
    );
    expect(closed && (await focused(toggle)), `${close} closes the menu on the button that opened it`);
  }
  // A page chosen in it takes the focus to its content: the link is gone with the menu.
  await toggle.focus();
  await page.keyboard.press("Enter");
  await menu.waitFor({ state: "visible" });
  await menu.getByRole("link", { name: "Dashboard", exact: true }).press("Enter");
  await page.waitForURL(`${origin}/admin/dashboard`);
  expect(await page.evaluate(() => document.activeElement?.id === "content"), "a page chosen in the menu takes the focus to its content");
  await page.setViewportSize(DESKTOP);
  // On a desk, a group opens on Enter and its entries follow it.
  await page.goto(`${origin}/admin/dashboard`);
  await heading();
  const group = page.getByRole("navigation").getByRole("button", { name: "Mail flow" });
  await group.press("Enter");
  expect((await group.getAttribute("aria-expanded")) === "true", "Enter opens a menu group");
  await page.keyboard.press("Tab");
  await page.keyboard.press("Enter");
  await page.waitForURL((url) => url.pathname !== "/admin/dashboard", { timeout: 3000 }).catch(() => undefined);
  expect(new URL(page.url()).pathname !== "/admin/dashboard", "Tab and Enter lead to the group's first page");

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

  await firstPaint(shared);

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
  // Left dark, as this step saved it.
  await chosenTheme(shared, page, "dark");
  savedTheme = "dark";

  step = "maintenance";
  const catalog = await (await page.request.get(`${origin}/api/actions`)).json();
  const action = catalog.actions[0];
  await page.goto(`${origin}/admin/actions`);
  await heading();
  // The dialog opens from the keyboard and holds the focus: Tab and Shift+Tab
  // go round its own controls (and the browser's), never to the page behind.
  const run = page.getByRole("button", { name: "Run…" }).first();
  await run.focus();
  await page.keyboard.press("Enter");
  const dialog = page.locator("dialog[open]");
  expect((await dialog.count()) === 1, "Enter on Run… opens the dialog");
  const behind = () =>
    page.evaluate(() => {
      const element = document.activeElement;
      return element !== null && element !== document.body && !element.closest("dialog[open]");
    });
  for (const key of ["Tab", "Tab", "Tab", "Tab", "Shift+Tab", "Shift+Tab", "Shift+Tab", "Shift+Tab"]) {
    await page.keyboard.press(key);
    if (await behind()) {
      fail(`${key} takes the focus out of the open dialog`);
      break;
    }
  }
  // Escape closes it, and the focus is where it was before.
  await page.keyboard.press("Escape");
  expect((await dialog.count()) === 0, "Escape closes the dialog");
  expect(await focused(run), "the focus is back on the button that opened the dialog");
  await run.click();
  const start = page.getByRole("button", { name: "Start", exact: true });
  expect(await start.isDisabled(), "an action does not start before its phrase is typed");
  await page.getByLabel(`Type ${action.confirmation} to confirm.`).fill(action.confirmation);
  // A start that fails keeps the dialog, and the focus on Start, where it was.
  failing.add("503 /api/actions");
  await page.route("**/api/actions", (route) => (route.request().method() === "POST" ? unavailable(route) : route.continue()));
  await start.focus();
  await page.keyboard.press("Enter");
  await dialog.getByText("Authorization is temporarily unavailable").waitFor();
  expect(await focused(start), "a start that failed leaves the focus on Start");
  await page.unroute("**/api/actions");
  failing.clear();
  // A start whose answer is lost: the request may have started the job, and
  // the page says that it does not know.
  failing.add("no answer to POST /api/actions");
  await page.route("**/api/actions", (route) => (route.request().method() === "POST" ? route.abort() : route.continue()));
  await start.focus();
  await page.keyboard.press("Enter");
  const unknown = await dialog
    .getByText(/^No readable answer came, so it is not known whether the job started\./)
    .waitFor({ timeout: 3000 })
    .then(
      () => true,
      () => false,
    );
  expect(unknown, "a start without an answer says that it is not known whether the job started");
  expect(await focused(start), "a start without an answer leaves the focus on Start");
  await page.unroute("**/api/actions");
  failing.clear();
  const submitted = page.waitForResponse((response) => response.url().endsWith("/api/actions") && response.request().method() === "POST");
  await start.click();
  expect((await submitted).status() === 202, "a confirmed action is accepted");
  expect((await dialog.count()) === 0 && (await focused(run)), "the started dialog closes on the button that opened it");
  await uncertainResult(shared, page, 2);

  await failingRequests(shared, catalog);
  await skewed(shared);
  await untimed(shared);
  await slept(shared);

  step = "a profile that grants the dashboard alone";
  const narrow = await browser.newContext({ viewport: DESKTOP });
  const viewer = await narrow.newPage();
  watch(viewer);
  try {
    // The preview's issuer signs in with a viewer's rights where the sign-in asks for them.
    const login = await viewer.request.get(`${origin}/auth/login`, { maxRedirects: 0 });
    await viewer.goto(`${new URL(login.headers().location, origin)}&profile=viewer`);
    await viewer.waitForURL(`${origin}/admin/`);
    await viewer.waitForLoadState("networkidle");
    expect((await viewer.locator("h1").first().innerText()).trim() === "Dashboard", "the viewer starts on the dashboard");
    const entries = await viewer.getByRole("navigation", { name: "Garrison" }).getByRole("link").allInnerTexts();
    expect(entries.join(", ") === "Dashboard", `the menu offers the dashboard alone, not ${entries.join(", ")}`);
    expect(await viewer.getByText("Your profile grants only the dashboard.").isVisible(), "the dashboard says what the profile grants");
    // A page the profile does not grant leads to one it does; the page as
    // drawn asked for its data all the same, and was refused.
    failing.add("403 /api/actions");
    await viewer.goto(`${origin}/admin/actions`);
    await viewer.waitForURL(`${origin}/admin/dashboard`);
    const refused = await viewer.request.get(`${origin}/api/actions`);
    expect(
      refused.status() === 403 && (await refused.json()).detail === "This Garrison module is not authorized",
      "the API refuses the viewer the maintenance actions",
    );
  } finally {
    failing.clear();
    await narrow.close();
  }

  await rightsChange(shared, page);
  // Its last step signs in again in one of the tabs, which the next ones use.
  await twoTabs(shared, page);
  await refusedSession(shared, page);

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
console.log(
  `Passed: sign-in, ${PAGES.length} pages, menu, search, paging, buttons that go, phone, back, first paint, settings, the chosen theme from the first frame, maintenance, an uncertain job, failures, HTTP/2, a clock ahead and behind, a session without a time left, a computer that slept, a viewer, a change of rights, two tabs, a refused session and sign-out.`,
);
