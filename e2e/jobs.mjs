// A started job as the Maintenance page follows it, in the flows (flows.mjs):
// a result the broker could not confirm is announced as a warning, as its row
// in Recent jobs shows it, never in the calm tile of a success.

/** `page` is the flows' signed-in tab; `index` the action's place in the catalog. */
export async function uncertainResult(shared, page, index) {
  const { origin, at, expect, accessible } = shared;
  at("a job whose result is uncertain");
  // The preview's job succeeds at its first look; this one's broker could not tell.
  await page.route("**/api/actions/jobs/*", async (route) => {
    const response = await route.fetch();
    const job = await response.json();
    return route.fulfill({
      response,
      json: { ...job, status: "uncertain", message: "The result could not be confirmed. Consult the host journal." },
    });
  });
  try {
    await page.goto(`${origin}/admin/actions`);
    await page.waitForLoadState("networkidle");
    // From the keyboard, as a user who does not see the tone would: Enter
    // opens the dialog on its field, the phrase, Enter starts.
    const { actions } = await (await page.request.get(`${origin}/api/actions`)).json();
    await page.getByRole("button", { name: "Run…" }).nth(index).press("Enter");
    await page.keyboard.type(actions[index].confirmation);
    await page.keyboard.press("Enter");
    const notice = page.getByRole("status").filter({ hasText: /^Job [0-9a-f]{8}: Result uncertain/ });
    await notice.waitFor({ timeout: 10_000 });
    // What a screen reader gets: a status, which says that the result is uncertain.
    const tree = await notice.ariaSnapshot();
    expect(
      tree.startsWith("- status") && tree.includes("Result uncertain — The result could not be confirmed. Consult the host journal."),
      `the notice reads ${JSON.stringify(tree)}`,
    );
    const tone = (await notice.getAttribute("class")) ?? "";
    expect(/\bbg-warning-background\b/.test(tone), `the notice is a warning, not the tile of a success (${tone})`);
    await accessible("Maintenance with an uncertain job");
  } finally {
    await page.unroute("**/api/actions/jobs/*");
  }
}
