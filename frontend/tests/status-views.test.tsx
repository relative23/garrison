// Every view that shows the collector's checks says when the status could not
// be read, that it shows an earlier status because a refresh failed, or that
// there is none yet: a check that is missing or old never reads as a quiet
// one. The views are found from the registry, by whether the status changes
// what they show, so a new view that shows checks is held to the same.
import { act, screen } from "@testing-library/react";

import { ApiError, type StatusResponse } from "../src/api/client";
import { ChunkView, VIEWS } from "../src/modules/registry";
import { attacks, catalog, coverage, metrics, observation, status } from "./support/fixtures";
import { renderView } from "./support/render";
import { serve, type FakeServer } from "./support/server";

const MODULES = Object.keys(VIEWS);

/** A status with a check of every module. */
const EVERY = status(MODULES.map((id) => observation({ id: `${id}.check`, title: `A check of ${id}`, modules: [id] })));

/** Until the view asks for nothing more and shows nothing that still loads. */
async function settled(server: FakeServer) {
  for (let asked = -1, quiet = 0; quiet < 3;) {
    await act(() => new Promise((resolve) => setTimeout(resolve, 20)));
    const loading = screen.queryAllByText(/Loading/).length > 0;
    quiet = server.calls.length === asked && !loading ? quiet + 1 : 0;
    asked = server.calls.length;
  }
}

/** What module `id`'s view shows with the status as `state` gives it. */
async function shown(id: string, state: { status: StatusResponse | Error; refreshError?: Error }): Promise<string> {
  const empty = { body: { items: [], next: null } };
  const server = serve({
    "GET metrics": { body: metrics() },
    "GET coverage": { body: coverage() },
    "GET attacks": { body: attacks() },
    "GET events": empty,
    "GET deliveries": empty,
    "GET sessions": empty,
    "GET actions": { body: catalog() },
  });
  const chunk = VIEWS[id]?.chunk;
  if (!chunk) throw new Error(`no view for ${id}`);
  const view = renderView(<ChunkView chunk={chunk} props={{ moduleId: id, detail: null }} />, state);
  await settled(server);
  const text = document.body.textContent ?? "";
  view.unmount();
  return text;
}

beforeAll(async () => {
  await Promise.all(MODULES.map((id) => VIEWS[id]?.chunk.preload()));
});

/** The views in which the status changes what is shown. A view outside this
 * list that comes to show checks fails the first test until it is held here. */
const SHOWING = ["dashboard", "services", "antivirus", "spam", "attacks", "backups", "alerts", "dns_tls"];

// One test for each view: together they wait longer than one test may take.
describe("a view that shows the collector's checks", () => {
  it("is one of the registry's", () => {
    expect(MODULES).toEqual(expect.arrayContaining(SHOWING));
  });

  it.each(MODULES)("is known as one, or as none: %s", async (id) => {
    const shows = (await shown(id, { status: EVERY })) !== (await shown(id, { status: status([]) }));
    expect(shows).toBe(SHOWING.includes(id));
  });

  it.each(SHOWING)("says when the status cannot be read, was not refreshed, or is not there yet: %s", async (id) => {
    const unread = await shown(id, { status: new ApiError(503, "The status database is not readable") });
    expect(unread).toContain("The status database is not readable");
    const kept = await shown(id, { status: EVERY, refreshError: new ApiError(503, "The broker is not reachable") });
    expect(kept).toContain("The status could not be refreshed.");
    expect(kept).toContain("The broker is not reachable");
    const none = await shown(id, { status: status([], { available: false }) });
    expect(none).toContain("The collector has not produced a status snapshot yet.");
  });
});
