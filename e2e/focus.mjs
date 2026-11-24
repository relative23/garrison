// Buttons that go away once pressed, in the flows (flows.mjs), from the
// keyboard: the focus they held goes on where a keyboard user reads on,
// never to the page. "Show all N rows" gives it to the first row it showed,
// and "Try again", which goes with its notice once the retry is answered,
// to the page's content.

/** Whether the focus is on an element that `test`, run in the page, accepts. */
const focusIs = (page, test) => page.evaluate(`(${test})(document.activeElement)`);

/** `page` is the flows' signed-in tab. */
export async function vanishing(shared, page) {
  const { origin, at, expect, failing } = shared;
  at("a button that goes once pressed: Show all rows");
  // The preview's mailbox card has three rows; this one has twelve, two more than the dashboard shows.
  await page.route("**/api/status", async (route) => {
    const response = await route.fetch();
    const status = await response.json();
    for (const item of status.observations) {
      if (item.id !== "stalwart.mailboxes" || !item.table) continue;
      item.table.rows = Array.from({ length: 12 }, (_, index) => [`mailbox${index}@example.test`, 1024 * index, null, null]);
    }
    return route.fulfill({ response, json: status });
  });
  try {
    await page.goto(`${origin}/admin/dashboard`);
    await page.waitForLoadState("networkidle");
    await page.getByRole("button", { name: "Show all 12 rows" }).focus();
    await page.keyboard.press("Enter");
    await page.getByText("mailbox11@example.test").waitFor();
    expect(
      await focusIs(page, (element) => element?.tagName === "TR" && element.textContent.startsWith("mailbox10@example.test")),
      "the focus goes to the first row Show all showed",
    );
  } finally {
    await page.unroute("**/api/status");
  }

  at("a button that goes once pressed: Try again");
  failing.add("503 /api/events");
  await page.route("**/api/events?**", (route) =>
    route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ detail: "The event history is busy." }) }),
  );
  try {
    await page.goto(`${origin}/admin/logs`);
    await page.waitForLoadState("networkidle");
    const retry = page.getByRole("button", { name: "Try again" });
    await retry.focus();
    await page.unroute("**/api/events?**");
    await page.keyboard.press("Enter");
    await retry.waitFor({ state: "detached" });
    expect(await focusIs(page, (element) => element?.id === "content"), "the focus goes to the page's content once the retry is answered");
  } finally {
    await page.unroute("**/api/events?**");
    failing.clear();
  }
}
