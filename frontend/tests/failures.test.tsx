// What a page says when a request fails, for every request of every page and
// every write from every place that sends one (tests/support/pages.ts finds
// them by pressing what each page offers). A failure says why in Garrison's
// own words, never in the browser's, the parser's or a proxy's, and names an
// internal error's reference. A read the page has nothing of to show is an
// error with Try again; one whose earlier answer the page keeps is a warning
// that says what is still shown. A write says what was not done, or, without
// an answer of Garrison's, that it is not known whether it was.
import { within } from "@testing-library/react";

import { api } from "../src/api/client";
import { status } from "./support/fixtures";
import {
  answers,
  controls,
  DETAIL,
  describeSteps,
  explore,
  fakeTime,
  PAGES,
  preload,
  press,
  settled,
  visit,
  wait,
  type Found,
} from "./support/pages";
import type { Route } from "./support/server";

const REFERENCE = "0123456789ab";

/** Each way a request fails, as the page's fetch meets it. */
const KINDS: Record<string, Route> = {
  "no answer": () => {
    throw new TypeError("Failed to fetch");
  },
  "a cut answer": { raw: '{"items": [' },
  "a proxy's error page": { status: 502, statusText: "Bad Gateway", raw: "<html><body><h1>502 Bad Gateway</h1></body></html>" },
  "a proxy's refusal": {
    status: 413,
    statusText: "Request Entity Too Large",
    raw: "<html><body><h1>413 Request Entity Too Large</h1></body></html>",
  },
  "an internal error": { status: 500, body: { detail: "Internal error" }, headers: { "x-request-id": REFERENCE } },
  "a refusal": { status: 503, body: { detail: "Authorization is temporarily unavailable" }, headers: { "x-request-id": "ba9876543210" } },
};

const UNANSWERED = "No readable answer came from Garrison: the connection may be down, or Garrison may be restarting.";
const foreign = (code: number) =>
  `Something between this browser and Garrison, such as a proxy, answered with status ${code} instead of Garrison.`;

/** What a failure of each kind says, whatever failed. */
const SAID: Record<string, string[]> = {
  "no answer": [UNANSWERED],
  "a cut answer": [UNANSWERED],
  "a proxy's error page": [foreign(502)],
  "a proxy's refusal": [foreign(413)],
  "an internal error": ["Internal error", `Reference ${REFERENCE} in the journal of garrison-web`],
  "a refusal": ["Authorization is temporarily unavailable"],
};

/** What no page says: the browser's, the parser's and a proxy's words, and the
 * reference of anything but an internal error. */
const NEVER = [/Failed to fetch/, /JSON/, /Unexpected/, /Bad Gateway/, /Entity Too Large/, /ba9876543210/, /gave no reason/];

/** A write without Garrison's answer cannot know whether it was done. */
const UNKNOWN = new Set(["no answer", "a cut answer", "a proxy's error page"]);

/** What each write from each place says when Garrison answered that it did not do it. */
const WRITES: Record<string, string> = {
  "POST actions after Run… › Start": "The job was not started.",
  "PUT preferences after Use the dark theme": "The theme could not be saved.",
  "PUT preferences after Save settings": "Settings could not be saved.",
  "POST logout after Sign out": "Sign-out did not complete, so this browser is still signed in. Try again.",
};

/** The live notices of the page that say `text`. */
function notices(text: string): Element[] {
  return [...document.querySelectorAll("[role=alert], [role=status]")].filter((each) => each.textContent?.includes(text));
}

/** What the page says against the rule, for a failure of `kind`. */
function judge(kind: string, write: string | null, kept: boolean): string[] {
  const wrong: string[] = [];
  const page = document.body.textContent ?? "";
  for (const never of NEVER) if (never.test(page)) wrong.push(`says ${never}`);
  if (write !== null && UNKNOWN.has(kind)) {
    const told = notices(", so it is not known whether ");
    if (told.length === 0) wrong.push("does not say that it is not known whether it was done");
    if (page.includes(WRITES[write] ?? "")) wrong.push("says that it was not done");
    return wrong;
  }
  const reasons = SAID[kind] ?? [];
  const notice = notices(reasons[0] ?? "")[0];
  if (!notice) return [...wrong, `does not say "${reasons[0]}" in a notice`];
  for (const reason of reasons) if (!notice.textContent?.includes(reason)) wrong.push(`does not say "${reason}"`);
  const role = notice.getAttribute("role");
  if (write !== null) {
    if (!notice.textContent?.startsWith(WRITES[write] ?? "?")) wrong.push(`does not lead with "${WRITES[write]}"`);
    if (role !== "alert") wrong.push(`says it as ${role}, not as an error`);
  } else if (kept) {
    if (role !== "status") wrong.push(`says it as ${role}, not as a warning over what it keeps`);
    if (!/could not be (refreshed|read)/.test(notice.querySelector("p")?.textContent ?? ""))
      wrong.push("does not lead with what is still shown");
  } else if (role === "alert" && !within(notice as HTMLElement).queryByRole("button", { name: "Try again" })) {
    wrong.push("offers no Try again");
  }
  return wrong;
}

/** Whether `page` shows the status: the collector's checks change it. */
async function showsStatus(page: string): Promise<boolean> {
  const texts = [];
  for (const checks of [undefined, { body: status([]) }]) {
    const routes = answers();
    if (checks) routes["GET status"] = checks;
    const { view } = await visit(page, routes);
    texts.push(document.querySelector("main")?.textContent ?? "");
    view.unmount();
  }
  return texts[0] !== texts[1];
}

/** What `page` shows of an earlier answer: its cells, figures and cards. */
function shown(): string[] {
  return [...document.querySelectorAll("main td, main dd, main [id^=obs-]")].map((each) => each.textContent ?? "");
}

/** Each failure of `read` on `page`, from its first answer on and after an
 * earlier answer that the page keeps. */
async function reads(page: string, read: Found, problems: string[]) {
  for (const [kind, route] of Object.entries(KINDS)) {
    const at = `${read.key} ${describeSteps(read.steps)} with ${kind}`;
    const failing = { ...answers(), [read.key]: route };
    const first = await visit(page, failing, read.steps);
    for (const wrong of judge(kind, null, false)) problems.push(`${at}: ${wrong}`);
    first.view.unmount();
    // The page's own session is not said over a signed-in page: it stays as read last.
    if (read.key === "GET session") continue;
    const later = await visit(page, answers(), read.steps);
    const before = shown();
    const asked = later.server.requests(read.key).length;
    later.server.answer(read.key, route);
    await wait(later.server, 61_000);
    for (const refresh of controls("main").flatMap((element, index) =>
      element.getAttribute("aria-label") === "Refresh" ? [{ scope: "main" as const, index, name: "Refresh" }] : [],
    )) {
      press(refresh);
      await settled(later.server);
    }
    // Asked once only, as a detail is: there is no earlier answer to keep.
    if (later.server.requests(read.key).length > asked) {
      for (const wrong of judge(kind, null, true)) problems.push(`${at}, over an earlier answer: ${wrong}`);
      const gone = before.filter((text) => !shown().includes(text));
      if (gone.length > 0) problems.push(`${at}, over an earlier answer: no longer shows ${gone.slice(0, 3).join(", ")}`);
    }
    later.view.unmount();
  }
}

/** Each failure of a write from where `found` sends it. */
async function writes(page: string, found: Found, problems: string[]) {
  const place = `${found.key} ${describeSteps(found.steps)}`;
  if (!Object.hasOwn(WRITES, place)) {
    problems.push(`${place}: a write from a place this test does not know; give it its words in WRITES`);
    return;
  }
  met.add(place);
  for (const [kind, route] of Object.entries(KINDS)) {
    const { view } = await visit(page, { ...answers(), [found.key]: route }, found.steps);
    for (const wrong of judge(kind, place, false)) problems.push(`${place} with ${kind}: ${wrong}`);
    view.unmount();
  }
}

/** The places of writes found on the pages, against WRITES. */
const met = new Set<string>();

/** Every read and write `found` on `page`, failed in turn, but those of
 * `known`. The frame around every page, with its own requests and controls,
 * is held on the first page. */
async function hold(page: string, found: Found[], frame: boolean, known = new Set<string>()): Promise<string[]> {
  const problems: string[] = [];
  const unanswered = found.filter((each) => !Object.hasOwn(answers(), each.key)).map((each) => each.key);
  if (unanswered.length > 0) return [`asks what this test does not answer: ${unanswered.join(", ")}`];
  const status = await showsStatus(page);
  for (const each of found) {
    if (known.has(each.key)) continue;
    if (each.key === "GET session" && !frame) continue;
    if (each.key === "GET status" && !status) continue;
    if (each.key.startsWith("GET ")) await reads(page, each, problems);
    else await writes(page, each, problems);
  }
  return problems;
}

/** What each page asks and sends without a detail, as `explore` found it. */
const plain = new Map<string, Found[]>();

beforeAll(preload);
beforeEach(fakeTime);

describe("a request that fails", () => {
  it.each(PAGES)(
    "is said in Garrison's words, with what is still shown, on the %s page",
    async (page) => {
      const found = await explore(page, page === PAGES[0]);
      plain.set(page, found);
      expect(await hold(page, found, page === PAGES[0])).toEqual([]);
    },
    180_000,
  );

  // A page that shows a detail, such as a delivery's queue, asks for it:
  // what it asks beyond the page without one is held here.
  it.each(PAGES)(
    "is said in Garrison's words on the %s page with a detail",
    async (page) => {
      const known = new Set((plain.get(page) ?? (await explore(page, false))).map((each) => each.key));
      const detail = `${page}/${DETAIL}`;
      expect(await hold(detail, await explore(detail, false), false, known)).toEqual([]);
    },
    180_000,
  );

  it("is held for every place a write is sent from", () => {
    expect([...met].sort()).toEqual(Object.keys(WRITES).sort());
  });

  it("is held for every write the API client sends, from a place a page offers", async () => {
    const sent = new Set<string>();
    for (const send of Object.values(api)) {
      vi.stubGlobal("fetch", (input: string, init: RequestInit = {}) => {
        if (init.method && init.method !== "GET") sent.add(`${init.method} ${input.replace(/^\/api\//, "")}`);
        return Promise.resolve(new Response("{}"));
      });
      await (send as (argument?: unknown) => Promise<unknown>)().catch(() => undefined);
    }
    expect([...sent].sort()).toEqual([...new Set([...met].map((place) => place.split(" after ")[0]))].sort());
  });
});
