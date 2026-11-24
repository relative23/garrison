// Every write the interface sends says, where no answer of Garrison's came,
// that the page does not know whether it was done: the request may have
// reached the server and been done there. That is so with no answer at all
// and with a proxy's own error page, which nginx sends while the web service
// restarts. The writes are found from the API client itself, so a new one
// fails here until it has a case.
import { fireEvent, screen } from "@testing-library/react";

import { api, configure } from "../src/api/client";
import { Actions } from "../src/modules/Actions";
import { catalog, metrics, session, status } from "./support/fixtures";
import { openApp, renderView } from "./support/render";
import { serve, type Route } from "./support/server";

/** The API client's methods that send something other than a read. */
async function writes(): Promise<string[]> {
  const found = [];
  for (const [name, send] of Object.entries(api)) {
    let method = "GET";
    vi.stubGlobal("fetch", (_: string, init: RequestInit = {}) => {
      method = init.method ?? "GET";
      return Promise.resolve(new Response("{}"));
    });
    await (send as (argument?: unknown) => Promise<unknown>)().catch(() => undefined);
    if (method !== "GET") found.push(name);
  }
  return found.sort();
}

/** What a write gets where Garrison did not answer it. */
const UNANSWERED: Record<string, Route> = {
  "no answer": () => {
    throw new TypeError("Failed to fetch");
  },
  "a proxy's 502 page": { status: 502, statusText: "", raw: "<html><body><h1>502 Bad Gateway</h1></body></html>" },
  "a proxy's 504 in JSON of its own": { status: 504, statusText: "", body: { message: "The upstream timed out." } },
};

/** Garrison's own answer that it did not do the write. */
const REFUSED: Route = { status: 503, body: { detail: "The broker is busy." } };

const signedIn = {
  "GET session": { body: { session: session() } },
  "GET status": { body: status([]) },
  "GET metrics": { body: metrics() },
};

/** Each write, sent from where the interface sends it, with `answer` to it.
 * The header's theme button saves the preferences as the Settings page does;
 * it says nothing of any failed save yet. */
const CASES: Record<string, (answer: Route) => Promise<void>> = {
  submitAction: async (answer) => {
    configure({ csrf: "csrf-token", onUnauthorized: () => undefined, onRefused: () => undefined });
    serve({ "GET actions": { body: catalog() }, "POST actions": answer });
    renderView(<Actions />);
    fireEvent.click(await screen.findByRole("button", { name: "Run…" }));
    fireEvent.change(screen.getByLabelText(/to confirm/), { target: { value: "RUN HEALTH CHECKS" } });
    fireEvent.click(screen.getByRole("button", { name: "Start" }));
  },
  savePreferences: async (answer) => {
    serve({ ...signedIn, "PUT preferences": answer });
    openApp("/admin/preferences");
    fireEvent.click(await screen.findByRole("button", { name: "Save settings" }));
  },
  logout: async (answer) => {
    serve({ ...signedIn, "POST logout": answer });
    openApp("/admin/account");
    fireEvent.click(await screen.findByRole("button", { name: "Sign out" }));
  },
};

/** What each write says when Garrison answered that it did not do it. */
const NOT_DONE: Record<string, RegExp> = {
  submitAction: /The broker is busy\./,
  savePreferences: /could not be saved/,
  logout: /still signed in/,
};

const each = Object.keys(CASES).flatMap((name) => Object.keys(UNANSWERED).map((kind) => [name, kind] as const));

describe("a write without an answer of Garrison's", () => {
  it("has a case for every write the interface sends", async () => {
    expect(await writes()).toEqual(Object.keys(CASES).sort());
    expect(Object.keys(NOT_DONE).sort()).toEqual(Object.keys(CASES).sort());
  });

  it.each(each)("says, for %s with %s, that it is not known whether it was done", async (name, kind) => {
    await CASES[name]?.(UNANSWERED[kind] ?? {});
    expect(await screen.findByText(/, so it is not known whether /)).toBeTruthy();
    for (const claim of [/could not be sent/, /still signed in/, /could not be saved/, /answered with status/]) {
      expect(screen.queryByText(claim)).toBeNull();
    }
  });

  it.each(Object.keys(CASES))("says, for %s, what Garrison answered when it refused", async (name) => {
    await CASES[name]?.(REFUSED);
    expect(await screen.findByText(NOT_DONE[name] ?? /never/)).toBeTruthy();
    expect(screen.queryByText(/, so it is not known whether /)).toBeNull();
  });
});
