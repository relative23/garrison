// Time that passes while a page is open, for views that must notice it
// without a new answer from the server. It is read from the page's monotonic
// clock: the wall clock of a browser may be wrong or may jump, and how long
// the page has waited does not depend on it.
import { useSyncExternalStore } from "react";

/** How often the views that watch the time look at it again. */
const STEP = 15_000;

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

// The same value until the next step, as a store's snapshot must be.
const steps = () => Math.floor(performance.now() / STEP) * STEP;

/** `performance.now()` in steps of 15 seconds; the view renders again at each. */
export function useMonotonic(): number {
  return useSyncExternalStore(subscribe, steps, () => 0);
}
