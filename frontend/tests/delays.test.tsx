// No number the interface is given becomes a delay that a browser runs at
// once. A timer whose delay is missing, not a finite number, below zero or
// beyond the 2^31 - 1 ms a browser's timer takes runs at once, and armed again
// with each answer it has the page ask back to back. Every place where a
// number becomes a delay, an interval or a count of repeats is held here with
// the same values: none, NaN, a negative, zero and 1e12.
import { act, fireEvent, render, screen } from "@testing-library/react";

import { after, delay, every } from "../src/lib/timers";
import { useResource } from "../src/lib/useResource";
import { Actions } from "../src/modules/Actions";
import { catalog, job, metrics, session, status } from "./support/fixtures";
import { openApp, renderView } from "./support/render";
import { serve } from "./support/server";

const VALUES: [string, unknown][] = [
  ["none", undefined],
  ["NaN", Number.NaN],
  ["a negative", -1],
  ["zero", 0],
  ["1e12", 1e12],
];

/** The least time between two of `times`, in milliseconds. */
function closest(times: number[]): number {
  let least = Number.POSITIVE_INFINITY;
  for (let index = 1; index < times.length; index += 1) least = Math.min(least, (times[index] ?? 0) - (times[index - 1] ?? 0));
  return least;
}

/** Ten minutes of the page's time, in steps, stopped early once `enough` holds. */
async function wait(enough: () => boolean) {
  for (let passed = 0; passed < 600_000 && !enough(); passed += 1000) {
    await act(async () => vi.advanceTimersByTimeAsync(1000));
  }
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.spyOn(document, "visibilityState", "get").mockReturnValue("visible");
});

describe("a number that becomes a delay", () => {
  it.each(VALUES)("is one that a timer can wait, or none: %s", (_, value) => {
    const timeout = vi.spyOn(globalThis, "setTimeout");
    const interval = vi.spyOn(globalThis, "setInterval");
    const called = vi.fn();
    after(value, called)();
    every(value, called)();
    // Zero is a delay a timer waits; as the period of an interval it is none.
    expect(delay(value)).toBe(value === 0 ? 0 : null);
    expect(timeout).toHaveBeenCalledTimes(value === 0 ? 1 : 0);
    expect(interval).not.toHaveBeenCalled();
    expect(delay(2 ** 31 - 1)).toBe(2 ** 31 - 1);
    expect(delay(2 ** 31)).toBeNull();
    expect(delay("1000")).toBeNull();
  });

  it.each(VALUES)("never has the page read its session back to back: a time left of %s", async (_, left) => {
    const reads: number[] = [];
    // NaN goes over the wire as null, as JSON has no NaN.
    serve({
      "GET session": () => {
        reads.push(Date.now());
        return { body: { session: { ...session(), expiresIn: left } } };
      },
      "GET status": { body: status([]) },
      "GET metrics": { body: metrics() },
    });
    openApp();
    await wait(() => reads.length > 100);
    // A read at least a second after the one before, whatever the answer:
    // the status refresh reads it once a minute, and a time left that the
    // page counts down reads it once more at the end, a step after an answer.
    expect(reads.length).toBeLessThan(60);
    expect(closest(reads)).toBeGreaterThanOrEqual(1000);
  });

  it.each(VALUES)("never has a resource asked again and again: a refresh every %s seconds", async (_, seconds) => {
    let loads = 0;
    function Probe() {
      const resource = useResource(
        async () => {
          loads += 1;
          return "data";
        },
        [],
        seconds as number,
      );
      return <output>{resource.data ?? "none"}</output>;
    }
    render(<Probe />);
    await wait(() => loads > 100);
    // Zero and every value no timer can wait mean no refresh at all.
    expect(loads).toBe(1);
  });

  it.each(VALUES)("never has the page ask about a job back to back: a job whose status is %s", async (_, value) => {
    const looks: number[] = [];
    const watched = job({ status: value as never });
    serve({
      "GET actions": { body: catalog() },
      "POST actions": { status: 202, body: { job: watched, replayed: false } },
      [`GET actions/jobs/${watched.id}`]: () => {
        looks.push(Date.now());
        return { body: watched };
      },
    });
    renderView(<Actions />);
    await act(async () => vi.advanceTimersByTimeAsync(0));
    fireEvent.click(screen.getByRole("button", { name: "Run…" }));
    fireEvent.change(screen.getByLabelText(/to confirm/), { target: { value: "RUN HEALTH CHECKS" } });
    fireEvent.click(screen.getByRole("button", { name: "Start" }));
    await wait(() => looks.length > 400);
    // A job this page cannot tell is done is looked at every three seconds.
    expect(closest(looks)).toBeGreaterThanOrEqual(3000);
  });
});

describe("the session at its end, while the server cannot be reached", () => {
  it("is asked about once a step of the page's clock, not back to back", async () => {
    const reads: number[] = [];
    let reached = true;
    const lost = () => {
      throw new TypeError("Failed to fetch");
    };
    serve({
      "GET session": () => {
        reads.push(Date.now());
        return reached ? { body: { session: { ...session(), expiresIn: 1 } } } : lost();
      },
      "GET status": () => (reached ? { body: status([]) } : lost()),
      "GET metrics": { body: metrics() },
    });
    openApp();
    await act(async () => vi.advanceTimersByTimeAsync(500));
    reached = false;
    await wait(() => reads.length > 100);
    expect(reads.length).toBeGreaterThan(10);
    expect(closest(reads)).toBeGreaterThanOrEqual(15_000);
  });
});
