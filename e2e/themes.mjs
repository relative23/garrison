// The theme of a page as the server sends it, in the flows (flows.mjs).

/** The theme a page starts in. Without a session, or for a user who chose
 * "system", it is the system's; `shared.savedTheme()` is the user's choice. */
export async function firstPaint(shared) {
  const { browser, context, origin, DESKTOP, at, expect } = shared;
  at("first paint");
  // A page as the build drew it, before any of its code runs.
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
      const saved = shared.savedTheme();
      const wanted = signedIn && saved !== "system" ? saved : theme;
      expect(scheme === wanted, `the drawn ${name} page starts in the ${wanted} theme with the system's ${theme}, not ${scheme}`);
      await drawn.close();
    }
  }
}

/** Runs in a page before any of its scripts: the theme of every frame, read in
 * the animation frame that comes just before the frame is painted, from the
 * first one with a body until the page is told to stop. */
function sampleThemes() {
  const themes = [];
  window.garrisonThemes = themes;
  const sample = () => {
    if (document.body) themes.push(getComputedStyle(document.documentElement).colorScheme);
    if (!window.garrisonStop) requestAnimationFrame(sample);
  };
  requestAnimationFrame(sample);
}

/** A theme chosen against the system's, light on a dark system and dark on a
 * light one: the page comes in it, and no frame from the first one on is in
 * the other theme, neither before the page's code runs nor after. A detail
 * gets the index, which the server sends in that theme as well. The theme is
 * left as `left`. */
export async function chosenTheme(shared, page, left) {
  const { browser, context, origin, DESKTOP, at, expect, watch } = shared;
  at("first paint in the chosen theme");
  const { session } = await (await page.request.get(`${origin}/api/session`)).json();
  const choose = async (theme) => {
    const answer = await page.request.put(`${origin}/api/preferences`, {
      headers: { Origin: origin, "X-CSRF-Token": session.csrf },
      data: { ...session.preferences, theme },
    });
    expect(answer.status() === 200, `the ${theme} theme is saved`);
  };
  for (const [chosen, system] of [
    ["light", "dark"],
    ["dark", "light"],
  ]) {
    await choose(chosen);
    for (const path of ["/admin/services", "/admin/deliveries/880000000000000100"]) {
      const shown = await browser.newContext({ viewport: DESKTOP, colorScheme: system });
      await shown.addCookies(await context.cookies());
      const sent = await shown.newPage();
      await sent.route("**/admin/assets/*.js", (route) => route.abort());
      await sent.goto(`${origin}${path}`);
      const scheme = await sent.evaluate(() => getComputedStyle(document.documentElement).colorScheme);
      expect(scheme === chosen, `${path} comes in the chosen ${chosen} theme on a ${system} system, not ${scheme}`);
      await sent.close();
      await shown.addInitScript(sampleThemes);
      const live = await shown.newPage();
      watch(live);
      await live.goto(`${origin}${path}`);
      await live.waitForLoadState("networkidle");
      const themes = await live.evaluate(() => {
        window.garrisonStop = true;
        return window.garrisonThemes;
      });
      const other = themes.filter((theme) => theme !== chosen).length;
      expect(themes.length > 0 && other === 0, `${path}: ${other} of ${themes.length} frames not in the chosen ${chosen} theme`);
      await shown.close();
    }
  }
  await choose(left);
}
