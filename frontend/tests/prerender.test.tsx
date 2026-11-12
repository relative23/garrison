import { screen, waitFor } from "@testing-library/react";

import { FIRST, frame, pages, signIn } from "../src/prerender";
import { attacks, catalog, coverage, metrics, session, status } from "./support/fixtures";
import { openApp } from "./support/render";
import { serve } from "./support/server";

/** The innermost element holding `text`, with every tag and class from <main>
 * down to it: two equal results are the same element at the same place. */
function placed(root: ParentNode, text: RegExp) {
  const matching = [...root.querySelectorAll("main *")].filter((element) => text.test(element.textContent ?? ""));
  const element = matching.find((candidate) => !matching.some((other) => other !== candidate && candidate.contains(other)));
  const path = [];
  for (let at: Element | null | undefined = element; at && at.tagName !== "MAIN"; at = at.parentElement) {
    path.unshift(`${at.tagName}.${at.className}`);
  }
  return { path, html: element?.outerHTML };
}

describe("pages drawn by the build", () => {
  it.each([
    ["actions", /^Each action starts or restarts one reviewed system service/],
    ["account", /^Access is granted by your Stalwart roles/],
    ["preferences", /^The header button switches between light and dark/],
  ])("carry the top of the %s view that needs no data, as the view renders it", async (view, text) => {
    const drawn = document.createElement("div");
    drawn.innerHTML = frame(view);
    // The view's own data never comes: the top must stand without it.
    serve({
      "GET session": { body: { session: session() } },
      "GET status": { body: status([]) },
      "GET actions": () => new Promise(() => undefined),
    });
    const { container } = openApp(`/admin/${view}`);
    await screen.findByText(text);
    expect(placed(drawn, text).html).toBeTruthy();
    expect(placed(container, text)).toEqual(placed(drawn, text));
  });

  it("keep a line for each account value they cannot know, so the text below stays put", () => {
    const drawn = document.createElement("div");
    drawn.innerHTML = frame("account");
    const values = [...drawn.querySelectorAll("main dd")].map((value) => value.textContent);
    expect(values).toHaveLength(4);
    expect(values.every((value) => value === "\u00a0")).toBe(true);
  });

  it("cover every module and both sections", () => {
    expect(pages).toEqual(expect.arrayContaining(["dashboard", "services", "attacks", "deliveries", "actions", "preferences", "account"]));
  });

  it("draw a view's frame with its title and intro, and nobody's menu", () => {
    const html = frame("services");
    expect(html).toMatch(/<h1 class="[^"]*">Services<\/h1>/);
    expect(html).toContain("Process and schedule states, installed versions, newer releases and collector health.");
    expect(html).toContain('aria-label="Garrison"');
    expect(html).not.toContain('href="/admin/antivirus"');
  });

  it("draw the sign-in page without an error", () => {
    const html = signIn();
    expect(html).toContain("Sign in with Stalwart");
    expect(html).not.toContain('role="alert"');
  });
});

describe("what the drawn pages start ahead", () => {
  it.each(pages)("is what the %s page asks for when it opens", async (view) => {
    const empty = { body: { items: [], next: null } };
    const server = serve({
      "GET session": { body: { session: session() } },
      "GET status": { body: status([]) },
      "GET metrics": { body: metrics() },
      "GET coverage": { body: coverage() },
      "GET deliveries": empty,
      "GET sessions": empty,
      "GET events": empty,
      "GET actions": { body: catalog() },
      "GET attacks": { body: attacks() },
    });
    openApp(`/admin/${view}`);
    const asked = () =>
      server.calls
        .filter((call) => call.method === "GET" && call.path !== "session")
        .map((call) => (call.query.size ? `${call.path}?${call.query}` : call.path));
    const expected = [...(FIRST[view]?.requests ?? [])].sort();
    await waitFor(() => expect(asked()).toEqual(expect.arrayContaining(expected)));
    // Then nothing more: the view asks for exactly what its page started.
    for (let count = asked().length, quiet = 0; quiet < 3;) {
      await new Promise((resolve) => setTimeout(resolve, 30));
      quiet = asked().length === count ? quiet + 1 : 0;
      count = asked().length;
    }
    expect(asked().sort()).toEqual(expected);
  });
});
