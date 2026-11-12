// Load a resource, optionally refresh it on an interval, and cancel requests
// that a newer load or an unmounted view has made obsolete.
import { useCallback, useEffect, useRef, useState } from "react";

export interface Resource<T> {
  data: T | null;
  error: Error | null;
  loading: boolean;
  reload: () => void;
}

interface Settled<T> {
  request: string;
  data: T | null;
  error: Error | null;
}

/**
 * `dependencies` must be JSON-serializable (filters, IDs). The latest `load`
 * function is always used; a new request starts when the dependencies change,
 * on `reload()` or on each refresh tick while the page is visible. `initial` is
 * an answer the page already has for the first request: it is shown at once,
 * and that request is not made.
 */
export function useResource<T>(
  load: (signal: AbortSignal) => Promise<T>,
  dependencies: readonly unknown[],
  refreshSeconds = 0,
  initial?: T,
): Resource<T> {
  const key = JSON.stringify(dependencies);
  const latest = useRef(load);
  const [tick, setTick] = useState(0);
  const request = `${key}#${tick}`;
  const [settled, setSettled] = useState<Settled<T>>(() =>
    initial === undefined ? { request: "", data: null, error: null } : { request, data: initial, error: null },
  );
  const answered = useRef(initial === undefined ? null : request);

  useEffect(() => {
    latest.current = load;
  });

  useEffect(() => {
    if (answered.current === request) {
      answered.current = null;
      return undefined;
    }
    const controller = new AbortController();
    latest.current(controller.signal).then(
      (data) => {
        if (!controller.signal.aborted) setSettled({ request, data, error: null });
      },
      (reason: unknown) => {
        if (controller.signal.aborted) return;
        const error = reason instanceof Error ? reason : new Error(String(reason));
        // Keep the previous data visible while showing the error.
        setSettled((previous) => ({ request, data: previous.data, error }));
      },
    );
    return () => controller.abort();
  }, [request]);

  useEffect(() => {
    if (!refreshSeconds) return undefined;
    // Background tabs do not poll; the next visible tick refreshes.
    const timer = setInterval(() => {
      if (document.visibilityState === "visible") setTick((value) => value + 1);
    }, refreshSeconds * 1000);
    return () => clearInterval(timer);
  }, [refreshSeconds]);

  const reload = useCallback(() => setTick((value) => value + 1), []);
  // Data from other filters is not shown as if it matched the current ones.
  const sameQuery = settled.request.startsWith(`${key}#`);
  return {
    data: sameQuery ? settled.data : null,
    error: sameQuery ? settled.error : null,
    loading: settled.request !== request,
    reload,
  };
}
