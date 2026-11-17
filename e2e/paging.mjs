// Paging through a list from the keyboard, in the flows (flows.mjs): the
// buttons under Event history keep the focus while the next page loads, and
// where they cannot act. The preview holds one page of events; the step gives
// its first page a cursor to a second one, which answers a moment later.

/** `page` is the flows' signed-in tab. */
export async function paging(shared, page) {
  const { origin, at, expect } = shared;
  at("paging from the keyboard");
  const OLDER = "flows-older";
  await page.route("**/api/events?**", async (route) => {
    const url = new URL(route.request().url());
    if (url.searchParams.get("before") === OLDER) {
      await new Promise((done) => setTimeout(done, 500));
      return route.fulfill({ json: { items: [], next: null } });
    }
    const response = await route.fetch();
    return route.fulfill({ response, json: { ...(await response.json()), next: OLDER } });
  });
  /** Whether the focus is on the button that says `name`, two frames on: a
   * browser moves the focus off a control that turned disabled at its next
   * rendering step, not at once. */
  const on = (name) =>
    page.evaluate(async (text) => {
      await new Promise((done) => requestAnimationFrame(() => requestAnimationFrame(done)));
      return document.activeElement?.textContent === text;
    }, name);
  try {
    await page.goto(`${origin}/admin/logs`);
    await page.waitForLoadState("networkidle");
    await page.getByRole("button", { name: "Older" }).focus();
    const asked = page.waitForRequest((request) => request.url().includes(`before=${OLDER}`));
    await page.keyboard.press("Enter");
    await asked;
    expect(await on("Older"), "Older keeps the focus while the next page loads");
    await page.getByText("No recorded events match.").waitFor();
    expect(await on("Older"), "Older keeps the focus on the last page, where it cannot act");
    await page.keyboard.press("Shift+Tab");
    expect(await on("Newest"), "Shift+Tab goes from Older to Newest");
    const back = page.waitForResponse((response) => response.url().includes("/api/events?") && !response.url().includes("before="));
    await page.keyboard.press("Enter");
    await back;
    await page.getByText(/newest first/).waitFor();
    expect(await on("Newest"), "Newest keeps the focus on the newest page, where it cannot act");
  } finally {
    await page.unroute("**/api/events?**");
  }
}
