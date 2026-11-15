// The theme of a page as the server sends it, in the flows (flows.mjs).

/** The theme a page starts in. */
export async function firstPaint(shared) {
  const { browser, context, origin, DESKTOP, at, expect } = shared;
  at("first paint");
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
}
