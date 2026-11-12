import source from "../public/stalwart-switch.js?raw";

// A minimal copy of the Stalwart WebUI layout the script relies on: a sidebar
// whose menu scrolls in one of its children, the entry of the open page marked
// and highlighted, and the section buttons below where there are several.
const OPEN = "bg-highlight font-semibold text-highlight-foreground hover:bg-highlight hover:text-highlight-foreground";
const entry = (name: string, extra = "", marks = "") =>
  `<a href="/admin/Management/${name}"${marks} class="flex h-9 text-sm rounded-[10px] text-muted-foreground hover:bg-muted ${extra}">` +
  `<svg class="h-4 w-4 shrink-0"></svg><span class="truncate">${name}</span></a>`;
const SECTIONS = `<div role="group" aria-label="Sections"><button aria-label="Management"></button><button aria-label="Settings"></button></div>`;
const sidebar = (entries: string, below = SECTIONS) => `
  <aside aria-label="Sidebar">
    <span class="sr-only">Enterprise feature</span>
    <div class="flex-1 overflow-y-auto"><nav aria-label="Management" class="flex flex-col gap-0.5 px-2.5">${entries}</nav></div>
    ${below}
  </aside>`;
const STALWART = sidebar(entry("Overview", OPEN, ' aria-current="page"') + entry("Accounts"));

const asked: { url: string; init: RequestInit | undefined }[] = [];

// The script watches the page for good; each test disconnects what it started.
const observers: MutationObserver[] = [];

class Recorded extends MutationObserver {
  constructor(callback: MutationCallback) {
    super(callback);
    observers.push(this);
  }
}

/** What Garrison answers when the script asks whether to show the row. */
function answer(reply: () => Promise<unknown>) {
  vi.stubGlobal("fetch", (url: URL | string, init?: RequestInit) => {
    asked.push({ url: String(url), init });
    return reply();
  });
}

const shows = (show: boolean) => () => Promise.resolve({ ok: true, json: () => Promise.resolve({ show }) });

async function run(garrison?: string) {
  const tag = document.createElement("script");
  if (garrison !== undefined) tag.dataset.garrison = garrison;
  Object.defineProperty(document, "currentScript", { value: tag, configurable: true });
  new Function(source)();
  // The row follows Garrison's answer and the script's delayed menu check.
  await vi.runAllTimersAsync();
}

describe("Stalwart WebUI switch row", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.stubGlobal("MutationObserver", Recorded);
    asked.length = 0;
    answer(shows(true));
  });

  afterEach(() => {
    for (const observer of observers.splice(0)) observer.disconnect();
    vi.unstubAllGlobals();
    document.body.innerHTML = "";
  });

  it("adds one row below the menu and above the section buttons, looking like a menu entry", async () => {
    document.body.innerHTML = STALWART;
    await run("https://admin.example.test/admin/");
    const row = document.getElementById("garrison-switch");
    expect(row?.previousElementSibling).toBe(document.querySelector("nav")?.parentElement);
    expect(row?.nextElementSibling?.getAttribute("aria-label")).toBe("Sections");
    // The menu's side padding, so the row lines up with the entries.
    expect(row?.className).toBe("border-t border-border px-2.5 py-2");
    const link = row?.querySelector("a");
    expect(link?.getAttribute("href")).toBe("https://admin.example.test/admin/");
    expect(link?.referrerPolicy).toBe("no-referrer");
    expect(link?.textContent).toBe("Switch to Garrison WebUI");
    // The classes of an entry that is not the open page, its icon size and its label.
    expect(link?.className).toBe("flex h-9 text-sm rounded-[10px] text-muted-foreground hover:bg-muted");
    expect(link?.querySelector("svg")?.getAttribute("class")).toBe("h-4 w-4 shrink-0");
    expect(link?.querySelector("span")?.className).toBe("truncate");
    await run("https://admin.example.test/admin/");
    expect(document.querySelectorAll("#garrison-switch")).toHaveLength(1);
  });

  it("never looks like the open page, even when every entry it finds is that", async () => {
    document.body.innerHTML = sidebar(entry("Overview", OPEN, ' aria-current="page"'));
    await run("https://admin.example.test/admin/");
    const link = document.querySelector("#garrison-switch a");
    expect(link?.className).toBe("flex h-9 text-sm rounded-[10px] text-muted-foreground hover:bg-muted");
    expect(link?.hasAttribute("aria-current")).toBe(false);
  });

  it("is the last thing in a sidebar without section buttons", async () => {
    document.body.innerHTML = sidebar(entry("Overview"), "");
    await run("https://admin.example.test/admin/");
    const row = document.getElementById("garrison-switch");
    expect(row).not.toBeNull();
    expect(row?.nextElementSibling).toBeNull();
    expect(row?.parentElement).toBe(document.querySelector("aside"));
  });

  it("takes an entry inside a group when the menu has no entry of its own, and falls back where the entry has no icon or label", async () => {
    document.body.innerHTML = sidebar(`<div><div><a href="/admin/x" class="flex h-8 text-[13px]">Nested</a></div></div>`);
    await run("https://admin.example.test/admin/");
    const link = document.querySelector("#garrison-switch a");
    expect(link?.className).toBe("flex h-8 text-[13px]");
    expect(link?.querySelector("svg")?.getAttribute("class")).toBe("h-4 w-4 shrink-0");
    expect(link?.querySelector("span")?.className).toBe("truncate");
  });

  it("uses a default side padding when the menu names none", async () => {
    document.body.innerHTML = `<aside><nav>${entry("Overview")}</nav></aside>`;
    await run("https://admin.example.test/admin/");
    const row = document.getElementById("garrison-switch");
    expect(row?.className).toBe("border-t border-border px-2 py-2");
    // The menu is the sidebar's own child here: the row follows it.
    expect(row?.previousElementSibling).toBe(document.querySelector("nav"));
  });

  // Garrison never shares the Stalwart WebUI's origin, so a path or a
  // non-HTTPS address cannot be its address.
  it.each([["javascript:alert(1)"], ["//other.example/"], ["http://other.example/"], ["data:text/html,x"], ["/admin/"], [undefined]])(
    "shows no row for %s and asks nothing",
    async (given) => {
      document.body.innerHTML = STALWART;
      await run(given);
      expect(document.getElementById("garrison-switch")).toBeNull();
      expect(asked).toEqual([]);
    },
  );

  it.each([
    ["there is no sidebar", "<main><nav><a href='/x'>x</a></nav></main>"],
    ["the sidebar has no menu", "<aside><div><a href='/x'>x</a></div></aside>"],
    ["the menu has no links", "<aside><nav><button>x</button></nav></aside>"],
  ])("shows nothing when %s", async (_, layout) => {
    document.body.innerHTML = layout;
    await run("https://admin.example.test/admin/");
    expect(document.getElementById("garrison-switch")).toBeNull();
  });

  it("asks Garrison with the user's cookie and stays away when the user turned the row off", async () => {
    answer(shows(false));
    document.body.innerHTML = STALWART;
    await run("https://admin.example.test/admin/");
    expect(document.getElementById("garrison-switch")).toBeNull();
    // The interface lives under /admin/, the API at the root beside it.
    expect(asked).toEqual([{ url: "https://admin.example.test/api/switch", init: { credentials: "include", cache: "no-store" } }]);
  });

  it.each([
    ["Garrison is unreachable", () => Promise.reject(new Error("offline"))],
    ["the answer is an error", () => Promise.resolve({ ok: false, json: () => Promise.resolve({ show: false }) })],
    ["the answer is not JSON", () => Promise.resolve({ ok: true, json: () => Promise.reject(new SyntaxError("x")) })],
  ])("keeps the row when %s", async (_, reply) => {
    answer(reply);
    document.body.innerHTML = STALWART;
    await run("https://admin.example.test/admin/");
    expect(document.getElementById("garrison-switch")).not.toBeNull();
  });
});
