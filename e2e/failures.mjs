// What the pages say when a request fails, in the flows (flows.mjs): a status
// refresh, a search, a refresh without an answer over the rows it keeps, a
// theme the header's button could not save and a look at a job, with the
// page's clock moved on, and answers over HTTP/2, which carries no status
// text, through the proxy of `npm run measure`.
import { startHttp2 } from "./http2.mjs";

/** Whether `wait` ends within its timeout. */
const within = (wait) =>
  wait.then(
    () => true,
    () => false,
  );

/** `catalog` is the maintenance actions as the API lists them. */
export async function failingRequests(shared, catalog) {
  const { browser, context, origin, DESKTOP, at, expect, watch, unavailable, failing } = shared;
  // A context of its own with a clock the steps move on, signed in as the
  // flows' user.
  at("a status refresh that fails");
  const timed = await browser.newContext({ viewport: DESKTOP });
  await timed.addCookies(await context.cookies());
  await timed.clock.install();
  const later = await timed.newPage();
  watch(later);
  try {
    await later.goto(`${origin}/admin/dashboard`);
    await later.waitForLoadState("networkidle");
    const tiles = later.locator("section[aria-labelledby=health-title] a");
    const shown = await tiles.count();
    failing.add("503 /api/status");
    await later.route("**/api/status", unavailable);
    // The status is read again after a minute, and that fails: the tiles stay,
    // under a notice that says so and why.
    await later.clock.fastForward("01:01");
    await later.getByText("The status could not be refreshed.").waitFor();
    expect(await later.getByText("Authorization is temporarily unavailable").isVisible(), "the notice says why the refresh failed");
    expect(shown > 0 && (await tiles.count()) === shown, "the tiles of the last status stay");
    // Kept longer than their checks may be old, they no longer pass for current.
    await later.clock.fastForward("10:00");
    await later
      .getByText(/· \d+ stale/)
      .first()
      .waitFor();
    await later.unroute("**/api/status");
    failing.clear();

    at("a search that fails");
    await later.goto(`${origin}/admin/logs`);
    await later.waitForLoadState("networkidle");
    const rows = later.locator("main tbody tr");
    expect((await rows.count()) > 0, "the event history lists events");
    failing.add("500 /api/events");
    await later.route("**/api/events?**", (route) =>
      new URL(route.request().url()).searchParams.get("search") === "unreadable"
        ? route.fulfill({ status: 500, contentType: "application/json", body: JSON.stringify({ detail: "The history could not be read" }) })
        : route.continue(),
    );
    await later.getByRole("searchbox").fill("unreadable");
    await later.getByRole("button", { name: "Search", exact: true }).click();
    await later.getByText("The history could not be read").waitFor();
    expect((await rows.count()) === 0, "no events of the list before stand under the search that failed");
    await later.unroute("**/api/events?**");
    failing.clear();

    at("a refresh without an answer over the rows it keeps");
    await later.getByRole("searchbox").fill("");
    await later.getByRole("button", { name: "Search", exact: true }).click();
    await rows.first().waitFor();
    const listed = await rows.count();
    failing.add("no answer to GET /api/events");
    await later.route("**/api/events?**", (route) => route.abort());
    await later.getByRole("button", { name: "Refresh" }).click();
    const kept = later.getByRole("status").filter({ hasText: "The list could not be refreshed; it shows what was read last." });
    await kept.waitFor();
    expect(
      (await kept.innerText()).includes("No readable answer came from Garrison"),
      "a request without an answer is said in Garrison's words, not the browser's",
    );
    expect((await later.getByText("Failed to fetch").count()) === 0, "the browser's own words are not shown");
    expect((await rows.count()) === listed, "the rows read before stay under the warning");
    await later.unroute("**/api/events?**");
    failing.clear();

    at("a theme that could not be saved");
    for (const [answer, said] of [
      [(route) => route.abort(), "No readable answer came, so it is not known whether the theme was saved."],
      [unavailable, "The theme could not be saved."],
    ]) {
      failing.add(answer === unavailable ? "503 /api/preferences" : "no answer to PUT /api/preferences");
      await later.route("**/api/preferences", (route) => (route.request().method() === "PUT" ? answer(route) : route.continue()));
      const button = later.locator("header").getByRole("button", { name: /^Use the (dark|light) theme$/ });
      const before = await button.getAttribute("aria-label");
      await button.click();
      const notice = later.getByRole("alert").filter({ hasText: said });
      expect(await within(notice.waitFor({ timeout: 3000 })), `a theme save that failed says "${said}"`);
      if (answer === unavailable) expect((await notice.innerText()).includes("Authorization is temporarily unavailable"), "and why");
      expect((await button.getAttribute("aria-label")) === before, "the page keeps the theme it had");
      await later.unroute("**/api/preferences");
      failing.clear();
    }

    at("a job whose status cannot be read for a while");
    const second = catalog.actions[1];
    await later.goto(`${origin}/admin/actions`);
    await later.waitForLoadState("networkidle");
    await later.getByRole("button", { name: "Run…" }).nth(1).click();
    await later.getByLabel(`Type ${second.confirmation} to confirm.`).fill(second.confirmation);
    const accepted = later.waitForResponse((response) => response.url().endsWith("/api/actions") && response.request().method() === "POST");
    await later.getByRole("button", { name: "Start", exact: true }).click();
    const { job } = await (await accepted).json();
    failing.add(`503 /api/actions/jobs/${job.id}`);
    await later.route(`**/api/actions/jobs/${job.id}`, unavailable, { times: 1 });
    // The first look fails and is said; the next comes later and finds the job done.
    await later.clock.fastForward("00:03");
    await later.getByText(`The status of job ${job.id.slice(0, 8)} could not be read`).waitFor();
    await later.clock.fastForward("00:06");
    await later.getByText(/^Job [0-9a-f]{8}: Succeeded/).waitFor();
    expect(
      (await later.getByText("could not be read; it will be asked for again").count()) === 0,
      "a look that succeeded ends the notice of the one that failed",
    );
    failing.clear();
  } finally {
    await timed.close();
  }

  // nginx serves Garrison over HTTP/2, which carries a status and no status
  // text: what a failure says must come from the answer's body, or be said
  // without one.
  at("errors over HTTP/2");
  let own = () => null;
  const proxy = await startHttp2(origin, 18443, (path) => own(path));
  const secure = await browser.newContext({ viewport: DESKTOP, ignoreHTTPSErrors: true });
  const cookie = (await context.cookies()).find((each) => each.name === "__Host-garrison_session");
  await secure.addCookies([
    { name: cookie.name, value: cookie.value, url: proxy.origin, secure: true, httpOnly: true, sameSite: cookie.sameSite },
  ]);
  const overHttp2 = await secure.newPage();
  watch(overHttp2, proxy.origin);
  try {
    await overHttp2.goto(`${proxy.origin}/admin/dashboard`);
    await overHttp2.waitForLoadState("networkidle");
    expect((await overHttp2.locator("h1").first().innerText()).trim() === "Dashboard", "the dashboard is served over HTTP/2");
    // nginx's own page for a Garrison that does not answer: nothing to read.
    failing.add("502 /api/status");
    own = (path) =>
      path === "/api/status" ? { status: 502, type: "text/html", body: "<html><body><h1>502 Bad Gateway</h1></body></html>" } : null;
    await overHttp2.reload();
    await overHttp2
      .getByText("Something between this browser and Garrison, such as a proxy, answered with status 502 instead of Garrison.")
      .waitFor();
    // An answer that carries a reason has it shown.
    failing.add("503 /api/status");
    own = (path) =>
      path === "/api/status"
        ? { status: 503, type: "application/json", body: JSON.stringify({ detail: "Authorization is temporarily unavailable" }) }
        : null;
    await overHttp2.reload();
    await overHttp2.getByText("Authorization is temporarily unavailable").waitFor();
  } finally {
    own = () => null;
    failing.clear();
    await secure.close();
    proxy.close();
  }
}
