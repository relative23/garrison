// A started job as the Maintenance page follows it, in the flows (flows.mjs):
// a result the broker could not confirm is announced as a warning, as its row
// in Recent jobs shows it, never in the calm tile of a success.
import AxeBuilder from "@axe-core/playwright";

const AXE_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"];

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
  const { session } = await (await page.request.get(`${origin}/api/session`)).json();
  /** Saves `theme` for the user, and has the page read its session again, as it does when it is shown. */
  const choose = async (theme) => {
    const headers = { Origin: origin, "X-CSRF-Token": session.csrf };
    const saved = await page.request.put(`${origin}/api/preferences`, { headers, data: { ...session.preferences, theme } });
    expect(saved.ok(), `the ${theme} theme is saved`);
    await page.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
  };
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
    // The warning's colours in each theme a user can choose, as axe judges them.
    for (const theme of ["light", "dark"]) {
      await choose(theme);
      await page.waitForFunction((scheme) => getComputedStyle(document.documentElement).colorScheme === scheme, theme, { timeout: 3000 });
      const faded = () => document.getAnimations().every((each) => !(each instanceof CSSTransition) || each.playState !== "running");
      await page.waitForFunction(faded, null, { timeout: 2000 }).catch(() => undefined);
      const { violations } = await new AxeBuilder({ page }).withTags(AXE_TAGS).analyze();
      for (const violation of violations) expect(false, `axe with an uncertain job (${theme}): ${violation.id}, ${violation.help}`);
    }
  } finally {
    await choose(session.preferences.theme);
    await page.unroute("**/api/actions/jobs/*");
  }
  await accessible("Maintenance with an uncertain job");
}
