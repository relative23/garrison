import { act, fireEvent, screen } from "@testing-library/react";

import { coverage, metrics, session, status } from "./support/fixtures";
import { openApp } from "./support/render";
import { serve } from "./support/server";

/** A signed-in user whose dashboard has nothing to show yet. */
function signedIn(modules?: string[]) {
  return {
    "GET session": { body: { session: session({}, modules) } },
    "GET status": { body: status([]) },
    "GET metrics": { body: metrics() },
  };
}

const heading = (name: string) => screen.findByRole("heading", { level: 1, name });

describe("sign-in", () => {
  it("starts at Stalwart when there is no session", async () => {
    serve({ "GET session": { body: { session: null } } });
    openApp();
    const link = await screen.findByRole("link", { name: "Sign in with Stalwart" });
    expect(link.getAttribute("href")).toBe("/auth/login");
    expect(screen.queryByText(/session has ended/)).toBeNull();
  });

  it("explains why the last sign-in failed", async () => {
    serve({ "GET session": { body: { session: null } } });
    openApp("/admin/?login_error=cross-site");
    expect(await screen.findByText(/Sign-in must start from this page/)).toBeTruthy();
  });

  it("asks to wait after too many sign-ins from one network", async () => {
    serve({ "GET session": { body: { session: null } } });
    openApp("/admin/?login_error=rate");
    expect(await screen.findByText(/Too many sign-ins from your network/)).toBeTruthy();
  });

  it("reads an unknown sign-in error as a failed sign-in", async () => {
    serve({ "GET session": { body: { session: null } } });
    openApp("/admin/?login_error=%3Cscript%3E");
    expect(await screen.findByText(/Sign-in could not be completed/)).toBeTruthy();
    expect(screen.queryByText(/script/)).toBeNull();
  });

  it("offers a retry when the session cannot be loaded", async () => {
    const server = serve({ "GET session": { status: 503, body: { detail: "Stalwart is not reachable" } } });
    openApp();
    const retry = await screen.findByRole("button", { name: "Try again" });
    expect(screen.getByText("Stalwart is not reachable")).toBeTruthy();
    server.answer("GET session", signedIn()["GET session"]);
    server.answer("GET status", { body: status([]) });
    server.answer("GET metrics", { body: metrics() });
    fireEvent.click(retry);
    expect(await heading("Dashboard")).toBeTruthy();
  });
});

describe("first paint", () => {
  it("shows the frame the server drew until the session arrives", async () => {
    let answer: () => void = () => undefined;
    const arrived = new Promise<void>((resolve) => {
      answer = resolve;
    });
    const server = serve({
      ...signedIn(["services"]),
      "GET session": async () => {
        await arrived;
        return { body: { session: session({}, ["services"]) } };
      },
    });
    openApp("/admin/services", "frame");
    expect(screen.getByRole("heading", { level: 1, name: "Services" })).toBeTruthy();
    // Nothing to save before the session is known.
    fireEvent.click(screen.getByRole("button", { name: /theme/ }));
    expect(server.requests("PUT preferences")).toHaveLength(0);
    answer();
    expect(await screen.findByText(/Status collected/)).toBeTruthy();
  });

  it("shows the sign-in page the server drew while it asks", async () => {
    serve({ "GET session": { body: { session: null } } });
    openApp("/admin/", "sign-in");
    expect(screen.getByRole("link", { name: "Sign in with Stalwart" })).toBeTruthy();
    expect(await screen.findByRole("link", { name: "Sign in with Stalwart" })).toBeTruthy();
  });
});

describe("navigation", () => {
  it("opens the first granted module for an unknown page", async () => {
    serve(signedIn());
    openApp("/admin/nowhere");
    expect(await heading("Dashboard")).toBeTruthy();
    expect(location.pathname).toBe("/admin/dashboard");
  });

  it("never opens a module the profile does not grant", async () => {
    const server = serve(signedIn(["deliveries"]));
    server.answer("GET coverage", { body: { available: false } });
    server.answer("GET deliveries", { body: { items: [], next: null } });
    openApp("/admin/actions");
    expect(await heading("Deliveries")).toBeTruthy();
    expect(server.requests("GET actions")).toHaveLength(0);
  });

  it.each([
    ["services", () => screen.findByText(/Status collected/)],
    ["deliveries", () => screen.findByPlaceholderText("Search by address, domain or queue ID")],
    ["sessions", () => screen.findByPlaceholderText("Search by IP, EHLO name or address")],
    ["logs", () => screen.findByPlaceholderText("Search events (address, host, IP, type)")],
  ])("loads the code of the %s page when it opens", async (id, shown) => {
    const server = serve(signedIn([id]));
    server.answer("GET coverage", { body: coverage() });
    for (const list of ["deliveries", "sessions", "events"]) server.answer(`GET ${list}`, { body: { items: [], next: null } });
    openApp(`/admin/${id}`);
    expect(await shown()).toBeTruthy();
  });

  it("follows the browser's back button", async () => {
    serve(signedIn());
    openApp("/admin/preferences");
    expect(await heading("Settings")).toBeTruthy();
    history.pushState(null, "", "/admin/account");
    act(() => {
      dispatchEvent(new PopStateEvent("popstate"));
    });
    expect(await heading("Account")).toBeTruthy();
  });
});

describe("account", () => {
  it("shows who is signed in and what the profile grants", async () => {
    serve({ ...signedIn(), "GET session": { body: { session: session({ profiles: [] }) } } });
    openApp("/admin/account");
    const value = (label: string) => screen.getByText(label, { selector: "dt" }).nextElementSibling?.textContent;
    // The view's chunk can arrive after the frame has drawn its heading.
    await screen.findByText("Account", { selector: "dt" });
    expect(value("Account")).toBe("admin@example.test");
    expect(value("Profiles")).toBe("None");
    expect(value("Garrison version")).toBe("0.1.0");
  });
});

describe("sign-out", () => {
  it("ends the session at the server, then shows the sign-in page", async () => {
    const server = serve({ ...signedIn(), "POST logout": { body: { ok: true } } });
    openApp("/admin/account");
    fireEvent.click(await screen.findByRole("button", { name: "Sign out" }));
    expect(await screen.findByText(/Your session has ended/)).toBeTruthy();
    expect(server.requests("POST logout")[0]?.headers.get("x-csrf-token")).toBe("csrf-token");
  });

  it("stays signed in and says so when sign-out fails", async () => {
    serve({ ...signedIn(), "POST logout": { status: 500, body: { detail: "Internal error" } } });
    openApp("/admin/account");
    fireEvent.click(await screen.findByRole("button", { name: "Sign out" }));
    expect(await screen.findByText(/this browser is still signed in/)).toBeTruthy();
    expect(screen.getByRole("heading", { level: 1, name: "Account" })).toBeTruthy();
  });

  it("shows the sign-in page as soon as the server ends the session", async () => {
    serve({ ...signedIn(), "GET status": { status: 401, body: {} } });
    openApp();
    expect(await screen.findByText(/Your session has ended/)).toBeTruthy();
  });

  it("shows the sign-in page when the session expires", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
    const expiresAt = Math.floor(Date.now() / 1000) + 60;
    serve({ ...signedIn(), "GET session": { body: { session: session({ expiresAt }) } } });
    openApp();
    await act(async () => vi.advanceTimersByTimeAsync(1000));
    expect(screen.getByRole("heading", { level: 1, name: "Dashboard" })).toBeTruthy();
    await act(async () => vi.advanceTimersByTimeAsync(60_000));
    expect(screen.getByText(/Your session has ended/)).toBeTruthy();
  });
});
