// What a tab learns of what happens beside it: another tab that signs in,
// signs out or saves its settings, and a change of the user's rights.
import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";

import { coverage, metrics, session, status } from "./support/fixtures";
import { openApp } from "./support/render";
import { serve } from "./support/server";

const channels: BroadcastChannel[] = [];

/** Another tab of this browser: what it hears from this one, and how it
 * tells this one that something changed. */
function otherTab() {
  const channel = new BroadcastChannel("garrison-session");
  channels.push(channel);
  const heard: unknown[] = [];
  channel.onmessage = (event: MessageEvent) => heard.push(event.data);
  return { heard, say: () => channel.postMessage("changed") };
}

afterEach(() => {
  for (const channel of channels.splice(0)) channel.close();
});

/** A signed-in user whose dashboard has nothing to show yet. */
function signedIn(modules?: string[]) {
  return {
    "GET session": { body: { session: session({}, modules) } },
    "GET status": { body: status([]) },
    "GET metrics": { body: metrics() },
  };
}

const other = { body: { session: session({ email: "other@example.test", csrf: "csrf-other" }) } };
const nobody = { body: { session: null } };

/** This tab is shown again after another one was in front. */
function shown() {
  vi.spyOn(document, "visibilityState", "get").mockReturnValue("visible");
  act(() => {
    document.dispatchEvent(new Event("visibilitychange"));
  });
}

describe("the page that says the session has ended", () => {
  it("takes a session that another tab made, as soon as that tab says so", async () => {
    const server = serve({ ...signedIn(), "POST logout": { body: { ok: true } } });
    const tab = otherTab();
    openApp("/admin/account");
    fireEvent.click(await screen.findByRole("button", { name: "Sign out" }));
    expect(await screen.findByText(/Your session has ended/)).toBeTruthy();
    server.answer("GET session", other);
    tab.say();
    expect(await screen.findByText("other@example.test")).toBeTruthy();
    expect(screen.queryByText(/Your session has ended/)).toBeNull();
  });

  it("takes a session that another tab made when it is shown again", async () => {
    const server = serve({ ...signedIn(), "POST logout": { body: { ok: true } } });
    openApp("/admin/account");
    fireEvent.click(await screen.findByRole("button", { name: "Sign out" }));
    expect(await screen.findByText(/Your session has ended/)).toBeTruthy();
    server.answer("GET session", other);
    shown();
    expect(await screen.findByText("other@example.test")).toBeTruthy();
    expect(screen.queryByText(/Your session has ended/)).toBeNull();
  });

  it("is not shown when the session ended because another tab signed in again", async () => {
    vi.useFakeTimers();
    vi.spyOn(document, "visibilityState", "get").mockReturnValue("visible");
    const server = serve(signedIn());
    openApp();
    await act(async () => vi.advanceTimersByTimeAsync(100));
    // The header names who is signed in.
    const who = () => within(screen.getByRole("banner")).getByRole("link", { name: "Account" }).getAttribute("title");
    expect(who()).toBe("admin@example.test");
    // That sign-in ended this tab's session: its next request is refused,
    // and the browser's cookie is the new session's.
    let refused = false;
    server.answer("GET status", () => {
      if (refused) return { body: status([]) };
      refused = true;
      return { status: 401, body: { detail: "Sign-in required" } };
    });
    server.answer("GET session", other);
    await act(async () => vi.advanceTimersByTimeAsync(60_000));
    // The session is read again after the refusal.
    await act(async () => vi.advanceTimersByTimeAsync(100));
    expect(screen.queryByText(/Your session has ended/)).toBeNull();
    expect(who()).toBe("other@example.test");
  });

  it("appears at once when another tab signs out", async () => {
    const server = serve(signedIn());
    const tab = otherTab();
    openApp("/admin/account");
    expect(await screen.findByText("admin@example.test")).toBeTruthy();
    server.answer("GET session", nobody);
    tab.say();
    expect(await screen.findByText(/Your session has ended/)).toBeTruthy();
    expect(screen.queryByText("admin@example.test")).toBeNull();
  });
});

describe("a browser without BroadcastChannel", () => {
  it("still signs in and out, and reads the session when a tab is shown", async () => {
    vi.stubGlobal("BroadcastChannel", undefined);
    const server = serve({ ...signedIn(), "POST logout": { body: { ok: true } } });
    openApp("/admin/account");
    fireEvent.click(await screen.findByRole("button", { name: "Sign out" }));
    expect(await screen.findByText(/Your session has ended/)).toBeTruthy();
    server.answer("GET session", other);
    shown();
    expect(await screen.findByText("other@example.test")).toBeTruthy();
  });
});

describe("what a tab tells the others", () => {
  it("that it started with a session", async () => {
    serve(signedIn());
    const tab = otherTab();
    openApp("/admin/account");
    expect(await screen.findByText("admin@example.test")).toBeTruthy();
    await waitFor(() => expect(tab.heard).toEqual(["changed"]));
  });

  it("that it signed out", async () => {
    serve({ ...signedIn(), "POST logout": { body: { ok: true } } });
    const tab = otherTab();
    openApp("/admin/account");
    expect(await screen.findByText("admin@example.test")).toBeTruthy();
    await waitFor(() => expect(tab.heard).toHaveLength(1));
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    expect(await screen.findByText(/Your session has ended/)).toBeTruthy();
    await waitFor(() => expect(tab.heard).toHaveLength(2));
  });

  it("that it saved its settings; nothing it does not save", async () => {
    serve({ ...signedIn(), "PUT preferences": (call) => ({ body: call.body }) });
    const tab = otherTab();
    openApp("/admin/account");
    expect(await screen.findByText("admin@example.test")).toBeTruthy();
    await waitFor(() => expect(tab.heard).toHaveLength(1));
    fireEvent.click(screen.getByRole("button", { name: "Use the dark theme" }));
    await screen.findByRole("button", { name: "Use the light theme" });
    await waitFor(() => expect(tab.heard).toHaveLength(2));
  });
});

describe("a change made elsewhere", () => {
  it("to the theme is taken as soon as the other tab says so", async () => {
    const server = serve(signedIn());
    const tab = otherTab();
    openApp("/admin/account");
    expect(await screen.findByText("admin@example.test")).toBeTruthy();
    expect(document.documentElement.className).toBe("light");
    server.answer("GET session", { body: { session: session({ preferences: { theme: "dark", hiddenModules: [], showSwitch: true } }) } });
    tab.say();
    await waitFor(() => expect(document.documentElement.className).toBe("dark"));
    expect(screen.getByRole("button", { name: "Use the light theme" })).toBeTruthy();
  });

  it("to the rights reaches the menu with the next refresh of the status, in one more request", async () => {
    vi.useFakeTimers();
    vi.spyOn(document, "visibilityState", "get").mockReturnValue("visible");
    const server = serve(signedIn(["dashboard", "services", "backups"]));
    openApp("/admin/backups");
    await act(async () => vi.advanceTimersByTimeAsync(100));
    const menu = () => within(screen.getByRole("navigation", { name: "Garrison" }));
    expect(menu().getByRole("link", { name: "Backups" })).toBeTruthy();
    // The operator takes Backups from the profile.
    server.answer("GET session", { body: { session: session({}, ["dashboard", "services"]) } });
    await act(async () => vi.advanceTimersByTimeAsync(60_000));
    expect(menu().queryByRole("link", { name: "Backups" })).toBeNull();
    expect(location.pathname).toBe("/admin/dashboard");
    // The session is read once with each refresh of the status, not more.
    expect(server.requests("GET session")).toHaveLength(2);
    expect(server.requests("GET status")).toHaveLength(2);
  });

  it("to the rights reaches the menu as soon as a request is refused", async () => {
    let reads = 0;
    serve({
      ...signedIn(),
      "GET session": () => {
        reads += 1;
        return { body: { session: session({}, reads === 1 ? ["dashboard", "logs"] : ["dashboard"]) } };
      },
      "GET coverage": { body: coverage() },
      "GET events": { status: 403, body: { detail: "This Garrison module is not authorized" } },
    });
    openApp("/admin/logs");
    await waitFor(() => expect(location.pathname).toBe("/admin/dashboard"));
    const menu = within(screen.getByRole("navigation", { name: "Garrison" }));
    expect(menu.queryByRole("link", { name: "Event history" })).toBeNull();
  });
});

describe("settings saved in this tab", () => {
  it("stay while the session read after the save fails, until one is read that holds them", async () => {
    const server = serve({ ...signedIn(), "PUT preferences": (call) => ({ body: call.body }) });
    openApp("/admin/account");
    expect(await screen.findByText("admin@example.test")).toBeTruthy();
    server.answer("GET session", { status: 503, body: { detail: "The broker is not reachable" } });
    fireEvent.click(screen.getByRole("button", { name: "Use the dark theme" }));
    await waitFor(() => expect(server.requests("GET session")).toHaveLength(2));
    await screen.findByRole("button", { name: "Use the light theme" });
    expect(document.documentElement.className).toBe("dark");
    // The next read holds the saved theme, as the server has it now.
    server.answer("GET session", { body: { session: session({ preferences: { theme: "dark", hiddenModules: [], showSwitch: true } }) } });
    shown();
    await waitFor(() => expect(server.requests("GET session")).toHaveLength(3));
    expect(document.documentElement.className).toBe("dark");
    expect(screen.getByRole("button", { name: "Use the light theme" })).toBeTruthy();
  });
});
