// Light or dark: the `dark` class on <html> switches every colour token.
export type Theme = "system" | "light" | "dark";

/** Whether `theme` shows dark colours on this device now. */
export function isDark(theme: Theme): boolean {
  // The build draws pages without a browser; they start light.
  const system = typeof matchMedia === "function" && matchMedia("(prefers-color-scheme: dark)").matches;
  return theme === "dark" || (theme === "system" && system);
}

export function applyTheme(theme: Theme): void {
  document.documentElement.classList.toggle("dark", isDark(theme));
}
