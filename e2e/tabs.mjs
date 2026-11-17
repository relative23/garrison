// Two tabs of one browser, in the flows (flows.mjs). They share the session
// cookie, and each follows what the other does, without a reload: a theme
// saved in one, a sign-out, and a sign-in made while the other says that the
// session has ended. A change of rights reaches the menu with the next
// refresh of the status, and the session read that brings it asks the broker
// nothing: the preview's broker (examples/preview/fakes.rs) counts its
// questions and lets the flows change the rights it grants. A session whose
// user the policy refuses ends on the page whose read of it is refused.

/** Whether `wait` ends within `timeout` milliseconds. */
const within = (wait) =>
  wait.then(
    () => true,
    () => false,
  );

/** The flows' signed-in context with two more tabs beside `page`; at its end
 * the context has the session of a sign-in made in one of them. */
export async function twoTabs(shared, page) {
  const { context, origin, at, expect, watch, failing } = shared;
  at("two tabs");
  // The flows' own tab waits on a page that asks for nothing but the status.
  await page.goto(`${origin}/admin/account`);
  await page.waitForLoadState("networkidle");
  const first = await context.newPage();
  const second = await context.newPage();
  watch(first);
  watch(second);
  try {
    await first.goto(`${origin}/admin/services`);
    await second.goto(`${origin}/admin/account`);
    await Promise.all([first.waitForLoadState("networkidle"), second.waitForLoadState("networkidle")]);
    const dark = (page) => page.evaluate(() => document.documentElement.classList.contains("dark"));
    const was = await dark(second);
    for (const wanted of [!was, was]) {
      await first.getByRole("button", { name: wanted ? "Use the dark theme" : "Use the light theme" }).click();
      const taken = second.waitForFunction((value) => document.documentElement.classList.contains("dark") === value, wanted, {
        timeout: 3000,
      });
      expect(await within(taken), `a theme saved in one tab is taken by the other at once (${wanted ? "dark" : "light"})`);
    }

    at("a sign-out in another tab");
    // A tab's refresh that leaves just before it hears of the sign-out is
    // refused, as it should be.
    failing.add("401 /api/status");
    await second.getByRole("button", { name: "Sign out" }).click();
    await second.getByText("Your session has ended").waitFor();
    const told = first.getByText("Your session has ended").waitFor({ timeout: 3000 });
    expect(await within(told), "the other tab says at once that the session has ended");

    at("a sign-in in another tab");
    // The tab that says the session has ended takes the session that the
    // other one makes, by itself.
    await second.getByRole("link", { name: "Sign in with Stalwart" }).click();
    await second.waitForURL(`${origin}/admin/`);
    const back = first.getByRole("heading", { level: 1, name: "Services" }).waitFor({ timeout: 3000 });
    expect(await within(back), "the tab that said the session had ended shows its page again");
    expect((await first.getByText("Your session has ended").count()) === 0, "and no longer says it has ended");
  } finally {
    failing.clear();
    await first.close();
    await second.close();
  }
}

/** A module taken from the profile and given back while a page is open. */
export async function rightsChange(shared) {
  const { browser, context, origin, DESKTOP, at, expect, watch } = shared;
  at("a change of rights");
  const control = `${origin}/preview-broker/grant`;
  const broker = async () => (await context.request.get(control)).json();
  const grant = (modules) => context.request.put(control, { data: { modules } });
  const all = (await broker()).modules;
  const timed = await browser.newContext({ viewport: DESKTOP });
  await timed.addCookies(await context.cookies());
  await timed.clock.install();
  const tab = await timed.newPage();
  watch(tab);
  const menu = tab.getByRole("navigation", { name: "Garrison" });
  const offered = async () => (await menu.getByRole("link", { name: "Backups", exact: true }).count()) === 1;
  try {
    await tab.goto(`${origin}/admin/backups`);
    await tab.waitForLoadState("networkidle");
    expect(await offered(), "the menu offers Backups");
    for (const [modules, given] of [
      [all.filter((id) => id !== "backups"), false],
      [all, true],
    ]) {
      await grant(modules);
      // The web service keeps a confirmed grant for five seconds: then the
      // next refresh of the status asks the broker again.
      await tab.waitForTimeout(5500);
      const before = (await broker()).authorized;
      await tab.clock.fastForward("01:01");
      const followed = tab.waitForFunction(
        (wanted) => [...document.querySelectorAll("nav a")].some((link) => link.textContent === "Backups") === wanted,
        given,
        { timeout: 3000 },
      );
      expect(await within(followed), `the menu ${given ? "offers Backups again" : "no longer offers Backups"} after a refresh`);
      if (!given) {
        // The page of a module the profile no longer grants leads to one it grants.
        expect(await within(tab.waitForURL(`${origin}/admin/dashboard`, { timeout: 3000 })), "Backups leads to the dashboard");
      }
      await tab.waitForLoadState("networkidle");
      const asked = (await broker()).authorized - before;
      expect(asked === 1, `the refresh and the session read after it asked the broker ${asked} times, not once`);
    }
  } finally {
    await grant(all);
    await timed.close();
  }
}

/** A session the policy refuses at the read another tab's start brings
 * about. The web service then ends the session and answers that read 403,
 * and knows no such session after it; `page` stands in for that answer. */
export async function refusedSession(shared, page) {
  const { context, origin, at, expect, watch, failing } = shared;
  at("a session the policy refuses");
  await page.goto(`${origin}/admin/account`);
  await page.waitForLoadState("networkidle");
  let refused = false;
  failing.add("403 /api/session");
  await page.route("**/api/session", (route) => {
    if (refused) return route.fulfill({ json: { session: null } });
    refused = true;
    return route.fulfill({ status: 403, json: { detail: "Garrison access is not authorized" } });
  });
  // A tab that starts says so, and this one reads its session again.
  const other = await context.newPage();
  watch(other);
  try {
    await other.goto(`${origin}/admin/services`);
    const told = page.getByText("Your session has ended").waitFor({ timeout: 3000 });
    expect(await within(told), "the page whose session the server refused says that the session has ended");
  } finally {
    await page.unroute("**/api/session");
    failing.clear();
    await other.close();
  }
}
