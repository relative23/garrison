import { act, fireEvent, screen, waitFor } from "@testing-library/react";

import { coverage, metrics, observation, session, status } from "./support/fixtures";
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

  it("asks to wait while sign-ins come from too many networks at once", async () => {
    serve({ "GET session": { body: { session: null } } });
    openApp("/admin/?login_error=busy");
    expect(await screen.findByText(/Too many sign-ins from many networks/)).toBeTruthy();
    expect(screen.queryByText(/from your network/)).toBeNull();
  });

  it("says that Stalwart did not answer, and when to try again", async () => {
    serve({ "GET session": { body: { session: null } } });
    openApp("/admin/?login_error=unavailable");
    expect(await screen.findByText(/Stalwart did not answer, .* Try again in a few minutes\./)).toBeTruthy();
    expect(screen.queryByText(/may not have Garrison access/)).toBeNull();
  });

  it("says that Stalwart is busy with its rate limit, and to wait a minute", async () => {
    serve({ "GET session": { body: { session: null } } });
    openApp("/admin/?login_error=limited");
    expect(await screen.findByText(/Stalwart is busy: .*rate limit\. Wait a minute and try again\./)).toBeTruthy();
    expect(screen.queryByText(/may not have Garrison access/)).toBeNull();
  });

  it("says that access could not be checked just then, not that it is missing", async () => {
    serve({ "GET session": { body: { session: null } } });
    openApp("/admin/?login_error=unchecked");
    expect(await screen.findByText(/Your access could not be checked just now\. Try again in a few minutes\./)).toBeTruthy();
    expect(screen.queryByText(/may not have Garrison access/)).toBeNull();
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

  it("keeps the theme the server sent the page in until the session arrives", async () => {
    // A detail gets no drawn frame: the server sends the index, in the theme
    // the user chose, here dark on a light system (tests/setup.ts).
    document.documentElement.className = "dark";
    let answer: () => void = () => undefined;
    const arrived = new Promise<void>((resolve) => {
      answer = resolve;
    });
    const dark = session({ preferences: { theme: "dark", hiddenModules: [], showSwitch: false } }, ["deliveries"]);
    serve({
      "GET session": async () => {
        await arrived;
        return { body: { session: dark } };
      },
      "GET status": { body: status([]) },
      "GET coverage": { body: coverage() },
      "GET deliveries/abc": { status: 404, body: { detail: "Not found" } },
    });
    openApp("/admin/deliveries/abc");
    expect(screen.getByText("Loading Garrison…")).toBeTruthy();
    await act(async () => undefined);
    expect(document.documentElement.className).toBe("dark");
    answer();
    expect(await screen.findByText("Not found")).toBeTruthy();
    expect(document.documentElement.className).toBe("dark");
  });

  it("follows the system for a visitor without a session", async () => {
    document.documentElement.className = "dark";
    serve({ "GET session": { body: { session: null } } });
    openApp("/admin/");
    expect(await screen.findByRole("link", { name: "Sign in with Stalwart" })).toBeTruthy();
    expect(document.documentElement.className).toBe("light");
  });
});

describe("navigation", () => {
  it("opens the first granted module for an unknown page", async () => {
    serve(signedIn());
    openApp("/admin/nowhere");
    expect(await heading("Dashboard")).toBeTruthy();
    expect(location.pathname).toBe("/admin/dashboard");
  });

  it("leads away from a page it does not offer in that page's place, so Back skips it", async () => {
    serve(signedIn());
    const entries = history.length;
    openApp("/admin/nowhere");
    expect(await heading("Dashboard")).toBeTruthy();
    expect(location.pathname).toBe("/admin/dashboard");
    expect(history.length).toBe(entries);
  });

  it("opens the first granted module for a page name that does not decode", async () => {
    serve(signedIn());
    // A "%" that starts no escape: the web service passes it as written.
    openApp("/admin/%zz");
    expect(await heading("Dashboard")).toBeTruthy();
    expect(location.pathname).toBe("/admin/dashboard");
  });

  it("opens the page of an address whose detail does not decode, and asks for that detail as written", async () => {
    const server = serve(signedIn(["deliveries"]));
    server.answer("GET coverage", { body: coverage() });
    server.answer("GET deliveries/%25FF", { status: 404, body: { detail: "Not found" } });
    openApp("/admin/deliveries/%FF");
    expect(await heading("Deliveries")).toBeTruthy();
    expect(await screen.findByText("Not found")).toBeTruthy();
    expect(server.requests("GET deliveries/%25FF")).toHaveLength(1);
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

describe("a sign-in or sign-out in another tab", () => {
  /** This tab is shown again after another one was in front. */
  function shown() {
    vi.spyOn(document, "visibilityState", "get").mockReturnValue("visible");
    act(() => {
      document.dispatchEvent(new Event("visibilitychange"));
    });
  }
  const other = { body: { session: session({ email: "other@example.test", csrf: "csrf-other" }) } };

  it("is taken over when this tab is shown again: its account and its token", async () => {
    const server = serve({ ...signedIn(), "PUT preferences": (call) => ({ body: call.body }) });
    openApp("/admin/account");
    expect(await screen.findByText("admin@example.test")).toBeTruthy();
    // The browser's cookie now belongs to the session the other tab made.
    server.answer("GET session", other);
    shown();
    expect(await screen.findByText("other@example.test")).toBeTruthy();
    expect(screen.queryByText("admin@example.test")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Use the dark theme" }));
    await screen.findByRole("button", { name: "Use the light theme" });
    expect(server.requests("PUT preferences")[0]?.headers.get("x-csrf-token")).toBe("csrf-other");
  });

  it("is taken over when a write is refused, and the next write carries its token", async () => {
    const server = serve({
      ...signedIn(),
      "PUT preferences": (call) =>
        call.headers.get("x-csrf-token") === "csrf-other"
          ? { body: call.body }
          : { status: 403, body: { detail: "Origin or CSRF validation failed" } },
    });
    openApp("/admin/preferences");
    await screen.findByRole("radio", { name: "Dark" });
    server.answer("GET session", other);
    fireEvent.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(server.requests("GET session")).toHaveLength(2));
    fireEvent.click(await screen.findByRole("button", { name: "Save settings" }));
    expect(await screen.findByText("Settings saved.")).toBeTruthy();
    expect(server.requests("PUT preferences").map((call) => call.headers.get("x-csrf-token"))).toEqual(["csrf-token", "csrf-other"]);
  });

  it("shows the sign-in page when the other tab signed out", async () => {
    const server = serve(signedIn());
    openApp("/admin/account");
    expect(await screen.findByText("admin@example.test")).toBeTruthy();
    server.answer("GET session", { body: { session: null } });
    shown();
    expect(await screen.findByRole("link", { name: "Sign in with Stalwart" })).toBeTruthy();
  });

  it("is not looked for at the cost of the page when the session cannot be read again", async () => {
    const server = serve(signedIn());
    openApp("/admin/account");
    expect(await screen.findByText("admin@example.test")).toBeTruthy();
    server.answer("GET session", { status: 503, body: { detail: "The broker is not reachable" } });
    shown();
    await waitFor(() => expect(server.requests("GET session")).toHaveLength(2));
    expect(screen.getByText("admin@example.test")).toBeTruthy();
    expect(screen.queryByText("The broker is not reachable")).toBeNull();
  });
});

describe("a status that stops arriving", () => {
  it("is said, and its checks go stale by themselves once they are too old", async () => {
    vi.useFakeTimers();
    vi.spyOn(document, "visibilityState", "get").mockReturnValue("visible");
    // Checked 100 seconds before the answer, current for 300.
    const check = observation({ modules: ["antivirus"], state: "ok", age: 100, maxAge: 300 });
    const server = serve({ ...signedIn(), "GET status": { body: status([check]) } });
    openApp();
    await act(async () => vi.advanceTimersByTimeAsync(100));
    const card = () => screen.getByRole("link", { name: /^Antivirus/ }).textContent;
    expect(card()).toContain("OK");
    // The next refreshes fail: the page says so and keeps what it has.
    server.answer("GET status", { status: 503, body: { detail: "The broker is not reachable" } });
    await act(async () => vi.advanceTimersByTimeAsync(60_000));
    expect(screen.getByText(/The status could not be refreshed/)).toBeTruthy();
    expect(card()).toContain("OK");
    // 100 seconds old when it arrived, and five minutes have passed since.
    await act(async () => vi.advanceTimersByTimeAsync(240_000));
    expect(card()).toContain("Unknown");
    expect(card()).toContain("1 stale");
    // A new answer makes it current again.
    server.answer("GET status", { body: status([check]) });
    await act(async () => vi.advanceTimersByTimeAsync(60_000));
    expect(card()).toContain("OK");
    expect(screen.queryByText(/The status could not be refreshed/)).toBeNull();
  });
});
