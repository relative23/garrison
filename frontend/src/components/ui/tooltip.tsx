// Tooltips whose code (tooltip-content.tsx: Radix and its positioning) loads
// once the first tooltip has rendered, so no page waits for it before it shows.
// Until it is there, the trigger stands on its own.
import { useSyncExternalStore, type ReactNode } from "react";

type Content = typeof import("./tooltip-content");

let content: Content | null = null;
let loading: Promise<void> | null = null;
const waiting = new Set<() => void>();

function subscribe(listener: () => void) {
  waiting.add(listener);
  loading ??= import("./tooltip-content").then((module) => {
    content = module;
    for (const each of waiting) each();
  });
  return () => waiting.delete(listener);
}

export function Tooltip({ content: text, children }: { content: ReactNode; children: ReactNode }) {
  const loaded = useSyncExternalStore(
    subscribe,
    () => content,
    () => null,
  );
  return loaded ? <loaded.Tooltip content={text}>{children}</loaded.Tooltip> : children;
}
