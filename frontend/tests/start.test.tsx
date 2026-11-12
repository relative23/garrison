import { render, screen } from "@testing-library/react";

import { App } from "../src/App";
import { PAGE_VIEWS, preloadView } from "../src/modules/registry";
import { prepare } from "../src/start";
import { session, status } from "./support/fixtures";
import { serve } from "./support/server";

describe("a page with a drawn frame", () => {
  it("waits for the session and its view's code", async () => {
    const server = serve({ "GET session": { body: { session: session() } } });
    const state = await prepare("/admin/preferences");
    expect(state?.session?.email).toBe("admin@example.test");
    expect(PAGE_VIEWS.preferences.loaded).not.toBeNull();
    expect(server.requests("GET session")).toHaveLength(1);
  });

  it("leaves the session to the app when the request fails", async () => {
    serve({ "GET session": { status: 500, body: { detail: "Internal error" } } });
    expect(await prepare("/admin/services")).toBeUndefined();
  });

  it("renders at once with what it waited for: no fallback, no second session request", async () => {
    const server = serve({ "GET status": { body: status([]) } });
    await preloadView("account");
    history.replaceState(null, "", "/admin/account");
    render(<App shell="frame" initial={{ session: session() }} />);
    // Synchronously after the first render: the view did not suspend.
    expect(screen.getByText(/Access is granted by your Stalwart roles/)).toBeTruthy();
    expect(screen.getByText("admin@example.test")).toBeTruthy();
    expect(server.requests("GET session")).toHaveLength(0);
  });
});
