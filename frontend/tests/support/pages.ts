// Every page of the interface as a user opens it, a stand-in server that
// answers all it asks, and what each page asks and sends, found by pressing
// every control it offers: its tabs, its buttons and, in a dialog it opens,
// the buttons there with the phrase its fields ask for typed. The failure
// tests (tests/failures.test.tsx) fail each of these in turn, so a page, a
// request or a control that is new is held to the same rule without anyone
// listing it.
import { act, fireEvent, screen } from "@testing-library/react";

import { PAGE_VIEWS, PAGES as SECTIONS, VIEWS } from "../../src/modules/registry";
import {
  attacks,
  catalog,
  coverage,
  delivery,
  destinations,
  event,
  job,
  metrics,
  observation,
  session,
  smtpSession,
  status,
} from "./fixtures";
import { openApp } from "./render";
import { serve, type Call, type FakeServer, type Route } from "./server";

/** The detail a page is opened with, such as a queue ID. */
export const DETAIL = "0123456789abcdef";

/** What the server answers to every request a page makes, with something to
 * show in each. A request that is not here fails the test that meets it. */
export function answers(): Record<string, Route> {
  const list = <T>(items: T[]) => ({ body: { items, next: null } });
  const checks = Object.keys(VIEWS).map((id) => observation({ id: `${id}.check`, title: `A check of ${id}`, modules: [id] }));
  return {
    "GET session": { body: { session: session({ actions: ["run_monitor"] }) } },
    "GET status": { body: status(checks) },
    "GET metrics": { body: metrics() },
    "GET coverage": { body: coverage() },
    "GET events": list([event()]),
    "GET deliveries": list([delivery()]),
    [`GET deliveries/${DETAIL}`]: { body: { summary: delivery({ queueId: DETAIL }), events: [event()], truncated: false } },
    "GET sessions": list([smtpSession()]),
    [`GET sessions/${DETAIL}`]: { body: { summary: smtpSession({ spanId: DETAIL }), events: [event()], truncated: false } },
    "GET attacks": { body: attacks() },
    "GET destinations": { body: destinations() },
    "GET actions": { body: catalog() },
    [`GET actions/jobs/${job().id}`]: { body: job({ status: "running", message: "Started" }) },
    "POST actions": { status: 202, body: { job: job(), replayed: false } },
    "PUT preferences": (call: Call) => ({ body: call.body }),
    "POST logout": { body: { ok: true } },
  };
}

/** Every page: each module's and each section's, and each module's with a
 * detail, which the pages that show one take (`explore` finds which). */
export const PAGES = [...Object.keys(VIEWS), ...Object.keys(SECTIONS)];

/** Loads the code of every view first, so a page renders at once. */
export async function preload() {
  await Promise.all([...Object.values(VIEWS), ...Object.values(PAGE_VIEWS)].map((view) => ("chunk" in view ? view.chunk : view).preload()));
  await import("../../src/components/Charts");
}

/** The page's clock runs on fake timers from here on, and the page is seen. */
export function fakeTime() {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval"] });
  vi.spyOn(document, "visibilityState", "get").mockReturnValue("visible");
}

/** Until the page asks for nothing more and shows nothing that still loads. */
export async function settled(server: FakeServer) {
  for (let asked = -1, quiet = 0; quiet < 3;) {
    await act(() => vi.advanceTimersByTimeAsync(20));
    const loading = screen.queryAllByText(/Loading/).length > 0;
    quiet = server.calls.length === asked && !loading ? quiet + 1 : 0;
    asked = server.calls.length;
  }
}

/** Time passes on the page; what falls due in it is asked, and answered. */
export async function wait(server: FakeServer, milliseconds: number) {
  await act(() => vi.advanceTimersByTimeAsync(milliseconds));
  await settled(server);
}

/** A control, by where it is and its place among the others there. */
export interface Step {
  /** The frame around every page, the page's own content, or an open dialog. */
  scope: "frame" | "main" | "dialog";
  index: number;
  name: string;
}

function scopeOf(scope: Step["scope"]): Element[] {
  const main = document.querySelector("main");
  if (scope === "dialog") return [...document.querySelectorAll("dialog[open]")];
  if (scope === "main") return main ? [main] : [];
  // The frame is the page without its content: header, menu and dialogs closed.
  return [...document.querySelectorAll("header, aside")];
}

function nameOf(element: Element): string {
  return (element.getAttribute("aria-label") ?? element.textContent ?? "").trim();
}

/** The controls a user can press in `scope`, in the page's order: none in a
 * dialog that is closed. */
export function controls(scope: Step["scope"]): Element[] {
  return scopeOf(scope)
    .flatMap((root) => [...root.querySelectorAll("button, [role=tab]")])
    .filter((element) => !element.closest("dialog:not([open])"));
}

/** Presses the control a step names: a tab as a pointer selects it, any other
 * by a click. In a dialog, each field whose label names a phrase to type gets
 * it first, as the maintenance dialog asks. */
export function press(step: Step) {
  const element = controls(step.scope)[step.index];
  if (!element) throw new Error(`no control ${step.name} (${step.scope} ${step.index})`);
  if (step.scope === "dialog") {
    for (const field of element.closest("dialog")?.querySelectorAll("input") ?? []) {
      const phrase = document.querySelector(`label[for="${field.id}"] code`)?.textContent;
      if (phrase) fireEvent.change(field, { target: { value: phrase } });
    }
  }
  if (element.getAttribute("role") === "tab") fireEvent.mouseDown(element, { button: 0 });
  else fireEvent.click(element);
}

/** Opens `page` with `routes`, presses `steps`, and waits after each: as long
 * as a started job is first looked at, and less than any page refreshes. */
export async function visit(page: string, routes: Record<string, Route>, steps: Step[] = []) {
  const server = serve(routes);
  const view = openApp(`/admin/${page}`);
  await settled(server);
  for (const step of steps) {
    press(step);
    // What the press sends is answered first; its timers start from there.
    await settled(server);
    await wait(server, 4000);
  }
  return { server, view };
}

/** A request the page made, and the steps that led to it first. */
export interface Found {
  key: string;
  steps: Step[];
}

/** What `page` asks and sends: on opening, and behind every control of its
 * own (and, for `frame`, the writes behind every control of the frame around
 * it, whose reads are another page's), with the controls of a dialog that one
 * opens. Each control is pressed on a page opened afresh. */
export async function explore(page: string, frame: boolean): Promise<Found[]> {
  const found = new Map<string, Step[]>();
  const routes = answers();
  const note = (calls: Call[], steps: Step[]) => {
    const own = steps.every((step) => step.scope !== "frame");
    for (const call of calls) {
      const key = `${call.method} ${call.path}`;
      if ((own || call.method !== "GET") && !found.has(key)) found.set(key, steps);
    }
  };
  const first = await visit(page, routes);
  note(first.server.calls, []);
  const scopes: Step["scope"][] = frame ? ["main", "frame"] : ["main"];
  const tried = scopes.flatMap((scope) => controls(scope).map((element, index) => ({ scope, index, name: nameOf(element) })));
  first.view.unmount();
  for (const step of tried) {
    const { server, view } = await visit(page, routes, [step]);
    note(server.calls, [step]);
    const inner = controls("dialog").map((element, index) => ({ scope: "dialog" as const, index, name: nameOf(element) }));
    view.unmount();
    for (const second of inner) {
      const again = await visit(page, routes, [step, second]);
      note(again.server.calls, [step, second]);
      again.view.unmount();
    }
  }
  return [...found].map(([key, steps]) => ({ key, steps }));
}

/** A request as the explorer names it: "METHOD path", and the steps to it. */
export function describeSteps(steps: Step[]): string {
  return steps.length === 0 ? "on opening" : `after ${steps.map((step) => step.name).join(" › ")}`;
}
