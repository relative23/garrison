// @ts-check
// Adds one "Switch to Garrison WebUI" row to the Stalwart WebUI's sidebar, right
// below its menu, styled with the classes of Stalwart's own menu entries.
// nginx adds this script to the Stalwart WebUI only where the operator includes
// the file from `garrison stalwart-switch`; the tag pins it by hash. It
// reads no page data, tokens or storage. It asks Garrison one thing, with
// the user's Garrison cookie: whether that user turned the row off; when the
// answer is missing the row is shown. Garrison has a host name of its own, so
// the include names its HTTPS address; without one the row is not shown.
// Elements are built with DOM calls only (no HTML parsing). If Stalwart's
// layout changes, it shows nothing.
(() => {
  "use strict";

  const ID = "garrison-switch";
  const SVG = "http://www.w3.org/2000/svg";
  const PATHS = ["M8 3 4 7l4 4", "M4 7h16", "m16 21 4-4-4-4", "M20 17H4"];
  // What Stalwart adds to the entry of the open page; the row is never that.
  const OPEN = /^(hover:)?(bg-highlight|text-highlight-foreground)$|^font-semibold$/;

  /** Garrison's address from the include; only an absolute HTTPS address counts. */
  function target() {
    try {
      const url = new URL(document.currentScript?.dataset.garrison ?? "");
      if (url.protocol === "https:") return url.href;
    } catch {
      // Not an address.
    }
    return null;
  }

  /** @param {Element} entry A menu entry; the icon takes the size of its icon. */
  function icon(entry) {
    const svg = document.createElementNS(SVG, "svg");
    const attributes = {
      viewBox: "0 0 24 24",
      fill: "none",
      stroke: "currentColor",
      "stroke-width": "2",
      "stroke-linecap": "round",
      "stroke-linejoin": "round",
      "aria-hidden": "true",
      class: entry.querySelector("svg")?.getAttribute("class") ?? "h-4 w-4 shrink-0",
    };
    for (const [key, value] of Object.entries(attributes)) svg.setAttribute(key, value);
    for (const d of PATHS) {
      const path = document.createElementNS(SVG, "path");
      path.setAttribute("d", d);
      svg.append(path);
    }
    return svg;
  }

  /**
   * Whether the user signed in to Garrison wants the row; yes unless it
   * says no, so a signed-out user or an unreachable Garrison keeps it.
   * @param {string} base
   * @returns {Promise<boolean>}
   */
  function wanted(base) {
    try {
      // The API sits at the root of Garrison's host, beside the interface.
      return fetch(new URL("/api/switch", base), { credentials: "include", cache: "no-store" })
        .then((answer) => (answer.ok ? answer.json() : null))
        .then((answer) => !(answer && answer.show === false))
        .catch(() => true);
    } catch {
      return Promise.resolve(true);
    }
  }

  /** @param {string} href */
  function place(href) {
    if (document.getElementById(ID)) return;
    // Expect Stalwart's layout: a sidebar whose menu is a list of links. The
    // menu scrolls in a child of the sidebar; whatever follows it (the section
    // buttons, where there are several sections) stays below the row.
    const aside = document.querySelector("aside");
    const nav = aside?.querySelector("nav");
    let menu = nav ?? null;
    while (menu && menu.parentElement !== aside) menu = menu.parentElement;
    // A top-level entry that is not the open page looks as the row should.
    const entry =
      nav?.querySelector(":scope > a[href]:not([aria-current])") ??
      nav?.querySelector("a[href]:not([aria-current])") ??
      nav?.querySelector("a[href]");
    if (!aside || !nav || !menu || !entry) return;
    const link = document.createElement("a");
    link.href = href;
    link.referrerPolicy = "no-referrer";
    link.className = [...entry.classList].filter((name) => !OPEN.test(name)).join(" ");
    const label = document.createElement("span");
    label.className = entry.querySelector("span")?.className ?? "truncate";
    label.textContent = "Switch to Garrison WebUI";
    link.append(icon(entry), label);
    const row = document.createElement("div");
    row.id = ID;
    // The menu's own side padding, under a line that sets the row apart.
    const side = [...nav.classList].find((name) => /^px-[\d.]+$/.test(name)) ?? "px-2";
    row.className = `border-t border-border ${side} py-2`;
    row.append(link);
    menu.after(row);
  }

  // Read while the script runs: document.currentScript is unset afterwards.
  const href = target();
  const body = document.body;
  if (!href || !body) return;
  wanted(href).then((show) => {
    if (!show) return;
    // Stalwart renders its menu after loading and again on navigation.
    let pending = false;
    new MutationObserver(() => {
      if (pending) return;
      pending = true;
      setTimeout(() => {
        pending = false;
        place(href);
      }, 50);
    }).observe(body, { childList: true, subtree: true });
    place(href);
  });
})();
