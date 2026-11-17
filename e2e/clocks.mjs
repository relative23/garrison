// What a page does with the browser's clocks, in the flows (flows.mjs): a
// browser whose clock runs hours ahead of the host's or behind it, a session
// answer without a time left that a timer can count, and a computer that
// slept, whose wall clock moved on while the page's timers and
// performance.now() did not. Playwright's clock does to a page what waking up
// does to it: `setSystemTime` moves the wall clock alone, as a resume does on
// Linux and macOS.

/** Whether `wait` ends within its timeout. */
const within = (wait) =>
  wait.then(
    () => true,
    () => false,
  );

/** Pages in a browser whose clock runs three hours ahead of the host's, more
 * than a session lasts, and in one three hours behind it. The preview's
 * checks are asked every minute, its last events a few minutes before. */
export async function skewed(shared) {
  const { browser, context, origin, DESKTOP, at, expect, watch } = shared;
  for (const hours of [3, -3]) {
    at(`a browser whose clock runs ${hours > 0 ? "ahead" : "behind"}`);
    const other = await browser.newContext({ viewport: DESKTOP });
    await other.addCookies(await context.cookies());
    await other.clock.install({ time: Date.now() + hours * 3600_000 });
    const page = await other.newPage();
    watch(page);
    try {
      await page.goto(`${origin}/admin/services`);
      await page.waitForLoadState("networkidle");
      expect((await page.getByText("Your session has ended").count()) === 0, "the session the server keeps stays");
      const checked = (await page.locator("main span[title]").allInnerTexts()).filter((text) => text.startsWith("Checked"));
      const current = checked.length > 0 && checked.every((text) => /^Checked (just now|\d+ min ago)$/.test(text));
      expect(current, `the checks say how old they are by the server's clock (${[...new Set(checked)].join("; ")})`);
      await page.goto(`${origin}/admin/logs`);
      await page.waitForLoadState("networkidle");
      const banner = await page
        .getByText(/^Recording since/)
        .innerText({ timeout: 3000 })
        .catch(() => "no coverage shown");
      expect(
        / · last received (just now|\d+ min ago) · /.test(banner),
        `the event history says when events last came by the server's clock (${banner})`,
      );
    } finally {
      await other.close();
    }
  }
}

/** A session answered without its time left, as a release before this one
 * answers it after a rollback, and with thirty days left, beyond what a
 * browser's timer takes: the page still reads its session no oftener than
 * once a second. */
export async function untimed(shared) {
  const { context, origin, at, expect, watch } = shared;
  for (const [name, change] of [
    ["none", (session) => delete session.expiresIn],
    ["thirty days", (session) => (session.expiresIn = 30 * 86400)],
  ]) {
    at(`a session answer with a time left of ${name}`);
    const page = await context.newPage();
    watch(page);
    const reads = [];
    await page.route("**/api/session", async (route) => {
      reads.push(Date.now());
      const response = await route.fetch();
      const body = await response.json();
      if (body.session) change(body.session);
      return route.fulfill({ response, json: body });
    });
    try {
      await page.goto(`${origin}/admin/account`);
      await page.waitForTimeout(3000);
      const closest = Math.min(...reads.slice(1).map((time, index) => time - (reads[index] ?? 0)));
      expect(
        reads.length <= 4 && closest >= 900,
        `the page reads its session no oftener than once a second (${reads.length} reads in 3 s)`,
      );
    } finally {
      await page.close();
    }
  }
}

/** The dashboard of a computer that slept for ten minutes. */
export async function slept(shared) {
  const { browser, context, origin, DESKTOP, at, expect, watch } = shared;
  at("a computer that slept");
  const asleep = await browser.newContext({ viewport: DESKTOP });
  await asleep.addCookies(await context.cookies());
  await asleep.clock.install();
  const page = await asleep.newPage();
  watch(page);
  try {
    await page.goto(`${origin}/admin/dashboard`);
    await page.waitForLoadState("networkidle");
    const stale = page.getByText(/· \d+ stale/);
    expect((await stale.count()) === 0, "the checks are current before the sleep");
    // Ten minutes asleep: longer than a check may be old, shorter than a
    // session lasts, so its cookie still counts.
    await page.clock.setSystemTime(Date.now() + 10 * 60_000);
    // The page looks at its clock again within fifteen seconds; it asks for
    // the status again only after a minute.
    await page.clock.runFor(16_000);
    expect(await within(stale.first().waitFor({ timeout: 3000 })), "after the sleep the checks are stale before the next refresh");
  } finally {
    await asleep.close();
  }
}
