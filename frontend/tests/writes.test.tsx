// Every write the interface sends says, where no answer came, that the page
// does not know whether it was done: the request may have reached the server
// and been done there. The writes are found from the API client itself, so a
// new one fails here until it has a case.
import { fireEvent, screen } from "@testing-library/react";

import { api, configure } from "../src/api/client";
import { Actions } from "../src/modules/Actions";
import { catalog, metrics, session, status } from "./support/fixtures";
import { openApp, renderView } from "./support/render";
import { serve } from "./support/server";

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

const lost = () => {
  throw new TypeError("Failed to fetch");
};

const signedIn = {
  "GET session": { body: { session: session() } },
  "GET status": { body: status([]) },
  "GET metrics": { body: metrics() },
};

/** Each write, sent from where the interface sends it, without an answer.
 * The header's theme button saves the preferences as the Settings page does;
 * it says nothing of any failed save yet. */
const CASES: Record<string, () => Promise<void>> = {
  submitAction: async () => {
    configure({ csrf: "csrf-token", onUnauthorized: () => undefined, onRefused: () => undefined });
    serve({ "GET actions": { body: catalog() }, "POST actions": lost });
    renderView(<Actions />);
    fireEvent.click(await screen.findByRole("button", { name: "Run…" }));
    fireEvent.change(screen.getByLabelText(/to confirm/), { target: { value: "RUN HEALTH CHECKS" } });
    fireEvent.click(screen.getByRole("button", { name: "Start" }));
  },
  savePreferences: async () => {
    serve({ ...signedIn, "PUT preferences": lost });
    openApp("/admin/preferences");
    fireEvent.click(await screen.findByRole("button", { name: "Save settings" }));
  },
  logout: async () => {
    serve({ ...signedIn, "POST logout": lost });
    openApp("/admin/account");
    fireEvent.click(await screen.findByRole("button", { name: "Sign out" }));
  },
};

describe("a write without an answer", () => {
  it("has a case for every write the interface sends", async () => {
    expect(await writes()).toEqual(Object.keys(CASES).sort());
  });

  it.each(Object.keys(CASES))("says, for %s, that it is not known whether it was done", async (name) => {
    await CASES[name]?.();
    expect(await screen.findByText(/, so it is not known whether /)).toBeTruthy();
    for (const claim of [/could not be sent/, /still signed in/, /could not be saved/]) {
      expect(screen.queryByText(claim)).toBeNull();
    }
  });
});
