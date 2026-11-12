import { fireEvent, screen, within } from "@testing-library/react";

import { metrics, session, status } from "./support/fixtures";
import { openApp } from "./support/render";
import { serve, type Call } from "./support/server";

const echo = (call: Call) => ({ body: call.body });
const menu = () => within(screen.getByRole("navigation", { name: "Garrison" }));
const dark = () => document.documentElement.classList.contains("dark");

function signedIn(preferences = session().preferences) {
  return {
    "GET session": { body: { session: session({ preferences }) } },
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
    expect(await screen.findByText("Settings saved.")).toBeTruthy();
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

  it("keep the old look when saving fails", async () => {
    serve({ ...signedIn(), "PUT preferences": { status: 500, body: { detail: "Internal error" } } });
    openApp("/admin/preferences");
    fireEvent.click(await screen.findByRole("radio", { name: "Dark" }));
    fireEvent.click(screen.getByRole("button", { name: "Save settings" }));
    expect(await screen.findByText("Settings could not be saved.")).toBeTruthy();
    expect(dark()).toBe(false);
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

  it("restores the saved theme when saving fails", async () => {
    serve({ ...signedIn(), "PUT preferences": { status: 500, body: {} } });
    openApp();
    fireEvent.click(await screen.findByRole("button", { name: "Use the dark theme" }));
    expect(await screen.findByRole("button", { name: "Use the dark theme" })).toBeTruthy();
    expect(dark()).toBe(false);
  });
});
