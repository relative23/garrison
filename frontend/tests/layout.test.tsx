import { fireEvent, screen, within } from "@testing-library/react";
import { useState } from "react";

import type { SessionInfo } from "../src/api/client";
import { Layout } from "../src/components/Layout";
import { session } from "./support/fixtures";
import { renderView } from "./support/render";

const MODULES = ["dashboard", "services", "antivirus", "spam", "deliveries", "sessions", "logs", "backups"];

function show(
  current: string,
  value: SessionInfo = session({ preferences: { theme: "light", hiddenModules: ["backups"], showSwitch: true } }, MODULES),
) {
  renderView(
    <Layout current={current} section="" title="Page" intro="">
      content
    </Layout>,
    { session: value },
  );
  return within(screen.getByRole("navigation", { name: "Garrison" }));
}

describe("menu", () => {
  it("opens the group of the current module and marks the page", () => {
    const menu = show("antivirus");
    expect(menu.getByRole("link", { name: "Antivirus" }).getAttribute("aria-current")).toBe("page");
    expect(menu.getByRole("link", { name: "Spam filter" })).toBeTruthy();
    expect(menu.getByRole("button", { name: "Mail flow" })).toBeTruthy();
    // "Mail flow" stays closed: its entries are not rendered.
    expect(menu.queryByRole("link", { name: "Deliveries" })).toBeNull();
    // Granted but hidden in the user's settings.
    expect(menu.queryByRole("link", { name: "Backups" })).toBeNull();
  });

  it("opens the group of a page opened from elsewhere, and lets the user close it", () => {
    // The layout stays mounted while the route changes, as in the application.
    function Moving() {
      const [current, setCurrent] = useState("dashboard");
      return (
        <>
          <button type="button" onClick={() => setCurrent("deliveries")}>
            Open deliveries
          </button>
          <Layout current={current} section="" title="Page" intro="">
            content
          </Layout>
        </>
      );
    }
    renderView(<Moving />, { session: session({}, MODULES) });
    const menu = within(screen.getByRole("navigation", { name: "Garrison" }));
    expect(menu.queryByRole("link", { name: "Deliveries" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Open deliveries" }));
    expect(menu.getByRole("link", { name: "Deliveries" }).getAttribute("aria-current")).toBe("page");
    expect(menu.getByRole("button", { name: "Mail flow" }).getAttribute("aria-expanded")).toBe("true");
    fireEvent.click(menu.getByRole("button", { name: "Mail flow" }));
    expect(menu.queryByRole("link", { name: "Deliveries" })).toBeNull();
  });

  it("hides hidden and ungranted modules and empty groups", () => {
    const menu = show("dashboard", session({}, ["dashboard"]));
    expect(menu.getByRole("link", { name: "Dashboard" })).toBeTruthy();
    expect(menu.queryByRole("button", { name: "Protection" })).toBeNull();
    expect(menu.queryByRole("link", { name: "Services" })).toBeNull();
  });

  it("keeps a hidden module in the menu while it is open", () => {
    const menu = show("backups");
    expect(menu.getByRole("link", { name: "Backups" }).getAttribute("aria-current")).toBe("page");
  });

  it("follows plain clicks without reloading, and leaves other clicks to the browser", () => {
    const menu = show("dashboard");
    const services = menu.getByRole("link", { name: "Services" });
    expect(fireEvent.click(services, { ctrlKey: true })).toBe(true);
    expect(location.pathname).toBe("/admin/");
    expect(fireEvent.click(services)).toBe(false);
    expect(location.pathname).toBe("/admin/services");
  });

  it("opens and closes on small screens", () => {
    show("dashboard");
    const toggle = screen.getByRole("button", { name: "Open menu" });
    fireEvent.click(toggle);
    expect(toggle.getAttribute("aria-expanded")).toBe("true");
    fireEvent.click(screen.getByRole("button", { name: "Close menu" }));
    expect(toggle.getAttribute("aria-expanded")).toBe("false");
    expect(screen.queryByRole("button", { name: "Close menu" })).toBeNull();
    // Its close button goes with it: the focus goes back to the menu button.
    expect(document.activeElement).toBe(toggle);
  });

  it("closes on Escape with the focus on its button, and leaves Escape to an open dialog", () => {
    show("dashboard");
    const toggle = screen.getByRole("button", { name: "Open menu" });
    fireEvent.click(toggle);
    const dialog = document.body.appendChild(document.createElement("dialog"));
    dialog.setAttribute("open", "");
    fireEvent.keyDown(document, { key: "Escape" });
    expect(toggle.getAttribute("aria-expanded")).toBe("true");
    dialog.remove();
    fireEvent.keyDown(document, { key: "Enter" });
    expect(toggle.getAttribute("aria-expanded")).toBe("true");
    fireEvent.keyDown(document, { key: "Escape" });
    expect(toggle.getAttribute("aria-expanded")).toBe("false");
    expect(document.activeElement).toBe(toggle);
  });

  it("takes the focus to the page's content when a page is chosen in the open menu", () => {
    const menu = show("dashboard");
    // On a large screen the menu is never opened: the focus stays on the link.
    const services = menu.getByRole("link", { name: "Services" });
    services.focus();
    fireEvent.click(services);
    expect(document.activeElement).toBe(services);
    fireEvent.click(screen.getByRole("button", { name: "Open menu" }));
    fireEvent.click(menu.getByRole("link", { name: "Dashboard" }));
    expect(document.activeElement?.id).toBe("content");
    expect(screen.getByRole("button", { name: "Open menu" }).getAttribute("aria-expanded")).toBe("false");
  });
});

describe("header", () => {
  it("switches to the Stalwart WebUI in the same tab", () => {
    show("dashboard");
    const link = screen.getByRole("link", { name: "Switch to Stalwart WebUI" });
    expect(link.getAttribute("href")).toBe("https://mail.example.test/admin/");
    expect(link.hasAttribute("target")).toBe(false);
  });

  it("offers no switch when no Stalwart WebUI address is configured", () => {
    show("dashboard", session({ links: { admin: "", other: {} } }));
    expect(screen.queryByRole("link", { name: "Switch to Stalwart WebUI" })).toBeNull();
  });

  it("links other interfaces over https only, by their known names", () => {
    const other = {
      webmail: "https://webmail.example.test/",
      alarms: "http://alarms.example.test/",
      status: "https://status.example.test/",
    };
    show("dashboard", session({ links: { admin: "", other } }));
    expect(screen.getByRole("link", { name: "Webmail" }).getAttribute("href")).toBe("https://webmail.example.test/");
    expect(screen.getByRole("link", { name: "status" }).getAttribute("href")).toBe("https://status.example.test/");
    expect(screen.queryByRole("link", { name: "Alerts channel" })).toBeNull();
  });
});
