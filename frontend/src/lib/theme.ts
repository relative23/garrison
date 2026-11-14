// Light or dark: the class the interface sets on <html>, `dark` or `light`,
// switches every colour token. Until it is set, as on the pages the build
// draws, the stylesheet follows the system's preference (styles/index.css).
import { useSyncExternalStore } from "react";

export type Theme = "system" | "light" | "dark";

const SYSTEM_DARK = "(prefers-color-scheme: dark)";

/** Whether the system asks for dark colours now. The build draws pages
 * without a browser; there it does not. */
function systemDark(): boolean {
  return typeof matchMedia === "function" && matchMedia(SYSTEM_DARK).matches;
}

function subscribe(listener: () => void): () => void {
  if (typeof matchMedia !== "function") return () => undefined;
  const query = matchMedia(SYSTEM_DARK);
  query.addEventListener("change", listener);
  return () => query.removeEventListener("change", listener);
}

/** Whether the system asks for dark colours; a view that uses it renders
 * again when the system changes its mind. */
export function useSystemDark(): boolean {
  return useSyncExternalStore(subscribe, systemDark, () => false);
}

/** Whether `theme` shows dark colours while the system asks for `system`. */
export function isDark(theme: Theme, system: boolean = systemDark()): boolean {
  return theme === "dark" || (theme === "system" && system);
}

export function applyTheme(theme: Theme, system: boolean = systemDark()): void {
  const dark = isDark(theme, system);
  document.documentElement.classList.toggle("dark", dark);
  document.documentElement.classList.toggle("light", !dark);
}
