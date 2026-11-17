// Load a resource, optionally refresh it on an interval, and cancel requests
// that a newer load or an unmounted view has made obsolete.
import { useCallback, useEffect, useRef, useState } from "react";

import { elapsed, Instant } from "./clock";
import { after, every } from "./timers";

export interface Resource<T> {
  data: T | null;
  error: Error | null;
  loading: boolean;
  /** When `data` arrived, on the page's clock (src/lib/clock.ts); null
   * without data. A failed refresh keeps the data and this moment. */
  receivedAt: Instant | null;
  reload: () => void;
}

interface Settled<T> {
  request: string;
  data: T | null;
  error: Error | null;
  receivedAt: Instant | null;
}

/**
 * `dependencies` must be JSON-serializable (filters, IDs). The latest `load`
 * function is always used; a new request starts when the dependencies change,
 * on `reload()` or on each refresh tick while the page is visible. `initial` is
 * an answer the page already has for the first request: it is shown at once,
 * and that request is not made. A `reload()` within `floorSeconds` of the
 * request before waits, and one request then answers all asked meanwhile.
 */
export function useResource<T>(
  load: (signal: AbortSignal) => Promise<T>,
  dependencies: readonly unknown[],
  refreshSeconds = 0,
  initial?: T,
  floorSeconds = 0,
): Resource<T> {
  const key = JSON.stringify(dependencies);
  const latest = useRef(load);
  const [tick, setTick] = useState(0);
  const request = `${key}#${tick}`;
  const [settled, setSettled] = useState<Settled<T>>(() =>
    initial === undefined
      ? { request: "", data: null, error: null, receivedAt: null }
      : { request, data: initial, error: null, receivedAt: new Instant() },
  );
  const answered = useRef(initial === undefined ? null : request);
  // When the request before started; `initial` was asked for just before.
  const started = useRef(initial === undefined ? null : new Instant());
  const waiting = useRef<(() => void) | null>(null);

  useEffect(() => {
    latest.current = load;
  });

  useEffect(() => {
    if (answered.current === request) {
      answered.current = null;
      return undefined;
    }
    started.current = new Instant();
    const controller = new AbortController();
    latest.current(controller.signal).then(
      (data) => {
        if (!controller.signal.aborted) setSettled({ request, data, error: null, receivedAt: new Instant() });
      },
      (reason: unknown) => {
        if (controller.signal.aborted) return;
        const error = reason instanceof Error ? reason : new Error(String(reason));
        // Keep the data visible while showing the error, but only data that
        // answered these same dependencies: after a failed request for a new
        // filter, the previous filter's rows are not this filter's.
        setSettled((previous) => {
          const kept = previous.request.startsWith(`${key}#`);
          return { request, data: kept ? previous.data : null, error, receivedAt: kept ? previous.receivedAt : null };
        });
      },
    );
    return () => controller.abort();
  }, [key, request]);

  // Background tabs do not poll; the next visible tick refreshes.
  useEffect(
    () =>
      every(refreshSeconds * 1000, () => {
        if (document.visibilityState === "visible") setTick((value) => value + 1);
      }),
    [refreshSeconds],
  );

  const reload = useCallback(() => {
    if (waiting.current) return;
    const left = floorSeconds * 1000 - (started.current ? elapsed(started.current) : Number.POSITIVE_INFINITY);
    if (!(left > 0)) {
      setTick((value) => value + 1);
      return;
    }
    waiting.current = after(left, () => {
      waiting.current = null;
      setTick((value) => value + 1);
    });
  }, [floorSeconds]);
  useEffect(() => () => waiting.current?.(), []);
  // Data from other filters is not shown as if it matched the current ones.
  const sameQuery = settled.request.startsWith(`${key}#`);
  return {
    data: sameQuery ? settled.data : null,
    error: sameQuery ? settled.error : null,
    loading: settled.request !== request,
    receivedAt: sameQuery ? settled.receivedAt : null,
    reload,
  };
}
