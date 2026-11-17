// Every timer of the interface is set here. A browser runs a timer at once
// whose delay is no number, below zero or beyond 2^31 - 1 ms; such a delay
// sets none here (eslint.config.js keeps the timers to this file).

/** The longest delay a browser's timer takes; a longer one runs at once. */
const LONGEST = 2 ** 31 - 1;

/** `milliseconds` as a timer's delay; null where it is no time a timer can
 * wait: missing, not a finite number, below zero or beyond what it takes. */
export function delay(milliseconds: unknown): number | null {
  if (typeof milliseconds !== "number" || !Number.isFinite(milliseconds)) return null;
  return milliseconds >= 0 && milliseconds <= LONGEST ? milliseconds : null;
}

/** Calls `callback` once, `milliseconds` from now. The function returned
 * stops it. A delay that is none sets no timer. */
export function after(milliseconds: unknown, callback: () => void): () => void {
  const wait = delay(milliseconds);
  if (wait === null) return () => undefined;
  const timer = setTimeout(callback, wait);
  return () => clearTimeout(timer);
}

/** Calls `callback` every `milliseconds`. The function returned stops it. A
 * period that is none, or zero, which would run as often as the browser
 * lets it, sets no timer. */
export function every(milliseconds: unknown, callback: () => void): () => void {
  const period = delay(milliseconds);
  if (!period) return () => undefined;
  const timer = setInterval(callback, period);
  return () => clearInterval(timer);
}
