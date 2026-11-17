// What a page does with the browser's clocks, in the flows (flows.mjs): a
// computer that slept, whose wall clock moved on while the page's timers and
// performance.now() did not. Playwright's clock does to a page what waking up
// does to it: `setSystemTime` moves the wall clock alone, as a resume does on
// Linux and macOS.

/** Whether `wait` ends within its timeout. */
const within = (wait) =>
  wait.then(
    () => true,
    () => false,
  );

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
