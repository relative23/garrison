// The page's clock (src/lib/clock.ts): how long a page has waited, also while
// the computer slept, which the browser's monotonic clock leaves out.
import { act, render, screen } from "@testing-library/react";

import { elapsed, Instant, usePageTime } from "../src/lib/clock";
import { preloadView } from "../src/modules/registry";
import { metrics, observation, session, status } from "./support/fixtures";
import { openApp } from "./support/render";
import { serve } from "./support/server";

const HOUR = 3600_000;

/** A computer that sleeps for `milliseconds`: when it wakes its wall clock
 * is put right, while performance.now() and the timers have not counted the
 * sleep. So it is in Chrome and Firefox on Linux, measured, and on macOS by
 * the browsers' own bug reports. */
function sleep(milliseconds: number) {
  const monotonic = performance.now();
  vi.setSystemTime(Date.now() + milliseconds);
  expect(performance.now()).toBe(monotonic);
}

describe("the page's clock", () => {
  it("counts the time the computer slept", () => {
    vi.useFakeTimers();
    const before = new Instant();
    vi.advanceTimersByTime(5000);
    sleep(HOUR);
    expect(elapsed(before)).toBe(HOUR + 5000);
  });

  it("counts no time back when the wall clock is set back, nor more than the monotonic clock", () => {
    vi.useFakeTimers();
    const before = new Instant();
    vi.advanceTimersByTime(5000);
    vi.setSystemTime(Date.now() - HOUR);
    expect(elapsed(before)).toBe(5000);
  });

  it("is never below zero", () => {
    vi.useFakeTimers();
    const before = new Instant();
    vi.advanceTimersByTime(5000);
    expect(elapsed(new Instant(), before)).toBe(0);
  });

  it("has a view render again at each step, and at the first step after a sleep", async () => {
    vi.useFakeTimers();
    const seen: Instant[] = [];
    function Watch() {
      seen.push(usePageTime());
      return null;
    }
    render(<Watch />);
    // A moment within the step that is current: up to a step before now.
    const first = seen.at(-1) as Instant;
    await act(async () => vi.advanceTimersByTimeAsync(15_000));
    const second = seen.at(-1) as Instant;
    expect(second).not.toBe(first);
    expect(elapsed(first, second)).toBeGreaterThanOrEqual(15_000);
    sleep(HOUR);
    await act(async () => vi.advanceTimersByTimeAsync(15_000));
    expect(elapsed(second, seen.at(-1) as Instant)).toBeGreaterThanOrEqual(HOUR + 15_000);
  });
});

describe("a status that does not change while the computer sleeps", () => {
  it("turns stale on the page at its first look at the time after the sleep", async () => {
    // As the page the build draws has it before the first render (src/start.ts).
    await preloadView("dashboard");
    vi.useFakeTimers();
    vi.spyOn(document, "visibilityState", "get").mockReturnValue("visible");
    // Checked 100 seconds before the answer, current for 300.
    const check = observation({ modules: ["antivirus"], state: "ok", age: 100, maxAge: 300 });
    serve({ "GET session": { body: { session: session() } }, "GET status": { body: status([check]) }, "GET metrics": { body: metrics() } });
    openApp();
    await act(async () => vi.advanceTimersByTimeAsync(100));
    const tile = () => screen.getByRole("link", { name: /^Antivirus/ }).textContent;
    expect(tile()).toContain("OK");
    sleep(HOUR);
    // The page's next look at the time, before the next refresh of the status.
    await act(async () => vi.advanceTimersByTimeAsync(15_000));
    expect(tile()).toContain("1 stale");
  });
});
