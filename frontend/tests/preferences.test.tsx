import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";

import type { Preferences } from "../src/api/client";
import { metrics, session, status } from "./support/fixtures";
import { openApp } from "./support/render";
import { serve, type Call } from "./support/server";

/** The settings the stand-in server keeps, as the web service does: the
 * session read after a save holds what was saved. */
let kept = session().preferences;
const echo = (call: Call) => {
  kept = call.body as Preferences;
  return { body: call.body };
};

/** A save that the server answers only when the test lets it. */
function held() {
  const waiting: (() => void)[] = [];
  return {
    route: (call: Call) => new Promise<{ body: unknown }>((resolve) => waiting.push(() => resolve(echo(call)))),
    answer: () => act(async () => waiting.shift()?.()),
  };
}
const menu = () => within(screen.getByRole("navigation", { name: "Garrison" }));
const dark = () => document.documentElement.classList.contains("dark");

function signedIn(preferences = session().preferences) {
  kept = preferences;
  return {
    "GET session": () => ({ body: { session: session({ preferences: kept }) } }),
    "GET status": { body: status([]) },
    "GET metrics": { body: metrics() },
  };
}

describe("settings", () => {
  it("save the theme and hidden modules, and the menu follows", async () => {
    const server = serve({ ...signedIn(), "PUT preferences": echo });
    openApp("/admin/preferences");
    fireEvent.click(await screen.findByRole("radio", { name: "Dark" }));
    fireEvent.click(screen.getByRole("checkbox", { name: "Backups" }));
    fireEvent.click(screen.getByRole("checkbox", { name: "Antivirus" }));
    fireEvent.click(screen.getByRole("button", { name: "Save settings" }));
    // The answer to what the user did is announced.
    expect((await screen.findByText("Settings saved.")).closest("[role]")?.getAttribute("role")).toBe("status");
    expect(server.requests("PUT preferences")[0]?.body).toEqual({
      theme: "dark",
      hiddenModules: ["antivirus", "backups"],
      showSwitch: true,
    });
    expect(dark()).toBe(true);
    expect(menu().queryByRole("link", { name: "Backups" })).toBeNull();
  });

  it("show a hidden module again", async () => {
    const server = serve({ ...signedIn({ theme: "light", hiddenModules: ["backups"], showSwitch: true }), "PUT preferences": echo });
    openApp("/admin/preferences");
    const backups = await screen.findByRole("checkbox", { name: "Backups" });
    expect(backups).toHaveProperty("checked", false);
    fireEvent.click(backups);
    fireEvent.click(screen.getByRole("button", { name: "Save settings" }));
    await screen.findByText("Settings saved.");
    expect(server.requests("PUT preferences")[0]?.body).toEqual({ theme: "light", hiddenModules: [], showSwitch: true });
    expect(menu().getByRole("link", { name: "Backups" })).toBeTruthy();
  });

  it("hide the switch rows", async () => {
    const server = serve({ ...signedIn(), "PUT preferences": echo });
    openApp("/admin/preferences");
    expect(await screen.findByRole("link", { name: "Switch to Stalwart WebUI" })).toBeTruthy();
    // The link belongs to the frame; the page's own chunk can still be loading.
    const box = await screen.findByRole("checkbox", {
      name: "Show “Switch to Stalwart WebUI” here and “Switch to Garrison WebUI” in the Stalwart WebUI",
    });
    expect(box).toHaveProperty("checked", true);
    fireEvent.click(box);
    fireEvent.click(screen.getByRole("button", { name: "Save settings" }));
    await screen.findByText("Settings saved.");
    expect(server.requests("PUT preferences")[0]?.body).toEqual({ theme: "light", hiddenModules: [], showSwitch: false });
    expect(screen.queryByRole("link", { name: "Switch to Stalwart WebUI" })).toBeNull();
  });

  it("say that they are being saved, and are saved once", async () => {
    const save = held();
    const server = serve({ ...signedIn(), "PUT preferences": save.route });
    openApp("/admin/preferences");
    fireEvent.click(await screen.findByRole("radio", { name: "Dark" }));
    fireEvent.click(screen.getByRole("button", { name: "Save settings" }));
    const busy = await screen.findByRole("button", { name: "Saving…" });
    expect(busy.getAttribute("aria-disabled")).toBe("true");
    fireEvent.click(busy);
    // The header's theme button saves the preferences too: it waits as well.
    fireEvent.click(screen.getByRole("button", { name: "Use the dark theme" }));
    expect(server.requests("PUT preferences")).toHaveLength(1);
    await save.answer();
    expect(await screen.findByText("Settings saved.")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Save settings" }).hasAttribute("aria-disabled")).toBe(false);
    expect(dark()).toBe(true);
  });

  it("keep the old look when saving fails", async () => {
    serve({ ...signedIn(), "PUT preferences": { status: 500, body: { detail: "Internal error" } } });
    openApp("/admin/preferences");
    fireEvent.click(await screen.findByRole("radio", { name: "Dark" }));
    fireEvent.click(screen.getByRole("button", { name: "Save settings" }));
    expect(await screen.findByText("Settings could not be saved.")).toBeTruthy();
    expect(dark()).toBe(false);
  });

  it("say, where no answer came, that it is not known whether they were saved", async () => {
    serve({
      ...signedIn(),
      "PUT preferences": () => {
        throw new TypeError("Failed to fetch");
      },
    });
    openApp("/admin/preferences");
    fireEvent.click(await screen.findByRole("radio", { name: "Dark" }));
    fireEvent.click(screen.getByRole("button", { name: "Save settings" }));
    // The request may have reached the web service, which saved them.
    expect(
      await screen.findByText(
        "No readable answer came, so it is not known whether the settings were saved. Check the connection and save again.",
      ),
    ).toBeTruthy();
    expect(screen.queryByText("Settings could not be saved.")).toBeNull();
  });
});

describe("settings saved in another tab", () => {
  const channels: BroadcastChannel[] = [];
  afterEach(() => {
    for (const channel of channels.splice(0)) channel.close();
  });

  it("are taken by every box not changed here, and a save here keeps them", async () => {
    const server = serve({ ...signedIn(), "PUT preferences": echo });
    const other = new BroadcastChannel("garrison-session");
    channels.push(other);
    openApp("/admin/preferences");
    const box = (name: string | RegExp) => screen.getByRole("checkbox", { name });
    await screen.findByRole("checkbox", { name: "Backups" });
    // Changed here and not saved yet: the theme and the Antivirus box.
    fireEvent.click(screen.getByRole("radio", { name: "Dark" }));
    fireEvent.click(box("Antivirus"));
    // The other tab saves a theme, hides Backups and the switch rows, and says so.
    kept = { theme: "system", hiddenModules: ["backups"], showSwitch: false };
    other.postMessage("changed");
    await waitFor(() => expect(box("Backups")).toHaveProperty("checked", false));
    expect(box(/^Show “Switch to Stalwart WebUI”/)).toHaveProperty("checked", false);
    expect(box("Antivirus")).toHaveProperty("checked", false);
    expect(screen.getByRole("radio", { name: "Dark" })).toHaveProperty("checked", true);
    fireEvent.click(screen.getByRole("button", { name: "Save settings" }));
    await screen.findByText("Settings saved.");
    expect(server.requests("PUT preferences")[0]?.body).toEqual({
      theme: "dark",
      hiddenModules: ["antivirus", "backups"],
      showSwitch: false,
    });
  });
});

describe("theme button", () => {
  it("and the settings page show the same saved theme", async () => {
    serve({ ...signedIn(), "PUT preferences": echo });
    openApp("/admin/preferences");
    fireEvent.click(await screen.findByRole("button", { name: "Use the dark theme" }));
    await screen.findByRole("button", { name: "Use the light theme" });
    expect(await screen.findByRole("radio", { name: "Dark" })).toHaveProperty("checked", true);
    fireEvent.click(screen.getByRole("radio", { name: "Light" }));
    fireEvent.click(screen.getByRole("button", { name: "Save settings" }));
    expect(await screen.findByRole("button", { name: "Use the dark theme" })).toBeTruthy();
    expect(dark()).toBe(false);
  });

  it("switches and saves the theme", async () => {
    const server = serve({ ...signedIn(), "PUT preferences": echo });
    openApp();
    fireEvent.click(await screen.findByRole("button", { name: "Use the dark theme" }));
    expect(dark()).toBe(true);
    expect(await screen.findByRole("button", { name: "Use the light theme" })).toBeTruthy();
    expect(server.requests("PUT preferences")[0]?.body).toEqual({ theme: "dark", hiddenModules: [], showSwitch: true });
  });

  it("saves one theme at a time, and shows it until it is saved", async () => {
    const save = held();
    const server = serve({ ...signedIn(), "PUT preferences": save.route });
    openApp();
    fireEvent.click(await screen.findByRole("button", { name: "Use the dark theme" }));
    // While that save is under way, a second click changes nothing.
    fireEvent.click(screen.getByRole("button", { name: "Use the light theme" }));
    expect(server.requests("PUT preferences")).toHaveLength(1);
    expect(dark()).toBe(true);
    expect(screen.getByRole("button", { name: "Use the light theme" }).getAttribute("aria-disabled")).toBe("true");
    await save.answer();
    expect(screen.getByRole("button", { name: "Use the light theme" }).hasAttribute("aria-disabled")).toBe(false);
    expect(dark()).toBe(true);
    expect(server.requests("PUT preferences").map((call) => call.body)).toEqual([{ theme: "dark", hiddenModules: [], showSwitch: true }]);
  });

  it("restores the saved theme when saving fails", async () => {
    serve({ ...signedIn(), "PUT preferences": { status: 500, body: {} } });
    openApp();
    fireEvent.click(await screen.findByRole("button", { name: "Use the dark theme" }));
    expect(await screen.findByRole("button", { name: "Use the dark theme" })).toBeTruthy();
    expect(dark()).toBe(false);
  });
});

/** The system's preference for dark colours, which the test changes. */
function system(dark: boolean) {
  const listeners = new Set<() => void>();
  let matches = dark;
  vi.stubGlobal("matchMedia", (query: string) => ({
    get matches() {
      return query === "(prefers-color-scheme: dark)" && matches;
    },
    media: query,
    onchange: null,
    addEventListener: (_: string, listener: () => void) => listeners.add(listener),
    removeEventListener: (_: string, listener: () => void) => listeners.delete(listener),
    addListener: () => undefined,
    removeListener: () => undefined,
    dispatchEvent: () => false,
  }));
  return {
    turn(value: boolean) {
      matches = value;
      act(() => listeners.forEach((listener) => listener()));
    },
  };
}

describe("the system's theme", () => {
  it("is followed while the page is open", async () => {
    const preference = system(false);
    serve(signedIn({ theme: "system", hiddenModules: [], showSwitch: true }));
    openApp();
    expect(await screen.findByRole("button", { name: "Use the dark theme" })).toBeTruthy();
    expect(dark()).toBe(false);
    preference.turn(true);
    expect(dark()).toBe(true);
    expect(screen.getByRole("button", { name: "Use the light theme" })).toBeTruthy();
    preference.turn(false);
    expect(dark()).toBe(false);
  });

  it("does not change a theme the user chose", async () => {
    const preference = system(true);
    serve(signedIn({ theme: "light", hiddenModules: [], showSwitch: true }));
    openApp();
    expect(await screen.findByRole("button", { name: "Use the dark theme" })).toBeTruthy();
    preference.turn(false);
    preference.turn(true);
    expect(dark()).toBe(false);
    // Said outright, so that the stylesheet's own following of the system,
    // for the pages the build draws, does not apply.
    expect(document.documentElement.classList.contains("light")).toBe(true);
  });

  it("is followed on the sign-in page", async () => {
    const preference = system(false);
    serve({ "GET session": { body: { session: null } } });
    openApp("/admin/");
    expect(await screen.findByRole("link", { name: "Sign in with Stalwart" })).toBeTruthy();
    preference.turn(true);
    expect(dark()).toBe(true);
  });
});
