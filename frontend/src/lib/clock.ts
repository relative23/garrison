// The page's own clock, which says only how long the page has waited: since
// an answer arrived, for instance. The browser's time of day may run hours
// ahead of the host's or behind it, and may be set while the page is open, so
// it is never compared with a time the server sent. A check's age and
// staleness, how long ago the last events arrived and how long a session has
// left are the server's figures at its answer plus or minus the time the
// page has waited since (src/lib/staleness.ts, src/components/Events.tsx,
// src/App.tsx).
//
// The wait is the larger of what the browser's two clocks counted. The
// monotonic one, performance.now(), is not set with the wall clock, but on
// Linux and macOS it stops while the computer sleeps, as its timers do; the
// wall clock counts the sleep but may be set back or ahead. The larger misses
// no sleep and no clock set back. A wall clock set ahead counts as time
// waited: a check turns stale sooner, or the page asks for its session
// sooner, never later. eslint.config.js keeps every other file from reading
// the browser's clocks.
import { useSyncExternalStore } from "react";

import { every } from "./timers";

/** How often the views that watch the time look at it again. */
export const STEP = 15_000;

/** A moment on the page's clock. Only the wait between two moments can be
 * read from it, never the browser's time of day. */
export class Instant {
  readonly #monotonic = performance.now();
  readonly #wall = Date.now();

  /** Milliseconds from this moment to `later`, never below zero. */
  until(later: Instant): number {
    return Math.max(0, later.#monotonic - this.#monotonic, later.#wall - this.#wall);
  }
}

/** Milliseconds the page has waited from `since` to `now`. */
export function elapsed(since: Instant, now: Instant = new Instant()): number {
  return since.until(now);
}

const listeners = new Set<() => void>();
let stop: (() => void) | undefined;

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  stop ??= every(STEP, () => listeners.forEach((each) => each()));
  return () => {
    listeners.delete(listener);
    if (listeners.size === 0) {
      stop?.();
      stop = undefined;
    }
  };
}

// Steps are counted on the page's clock, so the first after a sleep counts
// it; the same moment stands until the next step, as a snapshot must.
const ORIGIN = new Instant();
const stepOf = (moment: Instant) => Math.floor(ORIGIN.until(moment) / STEP);
let shown = new Instant();
let shownStep = stepOf(shown);
function snapshot(): Instant {
  const now = new Instant();
  const step = stepOf(now);
  if (step !== shownStep) {
    shown = now;
    shownStep = step;
  }
  return shown;
}

/** The page's clock in steps of 15 seconds; a view that reads it renders
 * again at each step. */
export function usePageTime(): Instant {
  return useSyncExternalStore(subscribe, snapshot, snapshot);
}
