// The page's own clock, which says only how long the page has waited: since
// an answer arrived, for instance. The browser's time of day may run hours
// ahead of the host's or behind it, and may be set while the page is open, so
// a check's staleness is its age at the server's answer plus the time the
// page has waited since (src/lib/staleness.ts).
//
// The wait is the larger of what the browser's two clocks counted. The
// monotonic one, performance.now(), is not set with the wall clock, but on
// Linux and macOS it stops while the computer sleeps, as its timers do; the
// wall clock counts the sleep but may be set back or ahead. The larger misses
// no sleep and no clock set back. A wall clock set ahead counts as time
// waited: a check turns stale sooner, never later.
import { useSyncExternalStore } from "react";

/** How often the views that watch the time look at it again. */
const STEP = 15_000;

/** A moment on the page's clock. Only the wait between two moments can be
 * read from it, never the browser's time of day. */
export class Instant {
  readonly #monotonic = performance.now();
  readonly #wall = Date.now();

  /** Milliseconds from this moment to `later`, never below zero. */
  until(later: Instant): number {
    return Math.max(0, later.#monotonic - this.#monotonic, later.#wall - this.#wall);
  }

  /** Whether `other` lies in the same step of both clocks as this moment. */
  sameStep(other: Instant): boolean {
    const step = (value: number) => Math.floor(value / STEP);
    return step(this.#monotonic) === step(other.#monotonic) && step(this.#wall) === step(other.#wall);
  }
}

/** Milliseconds the page has waited from `since` to `now`. */
export function elapsed(since: Instant, now: Instant = new Instant()): number {
  return since.until(now);
}

const listeners = new Set<() => void>();
let timer: ReturnType<typeof setInterval> | undefined;

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  timer ??= setInterval(() => listeners.forEach((each) => each()), STEP);
  return () => {
    listeners.delete(listener);
    if (listeners.size === 0) {
      clearInterval(timer);
      timer = undefined;
    }
  };
}

// The same moment until either clock reaches its next step, as a store's
// snapshot must be: after a sleep the wall clock's step has moved on.
let shown = new Instant();
function snapshot(): Instant {
  const now = new Instant();
  if (!now.sameStep(shown)) shown = now;
  return shown;
}

/** The page's clock in steps of 15 seconds; a view that reads it renders
 * again at each step. */
export function usePageTime(): Instant {
  return useSyncExternalStore(subscribe, snapshot, snapshot);
}
