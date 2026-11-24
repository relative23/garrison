// eslint.config.js keeps the browser's clocks to src/lib/clock.ts and its
// timers to src/lib/timers.ts. A rule on syntax holds only the ways it names,
// so each way is listed here and linted as a line of any other file.
import { ESLint } from "eslint";

/** Ways to a time of the browser's own. */
const CLOCKS = [
  "Date.now();",
  "new Date();",
  "Date();",
  "performance.now();",
  "performance.timeOrigin;",
  "window.Date.now();",
  "new window.Date();",
  "globalThis.performance.now();",
  "self.performance.now();",
  'Date["now"]();',
  'window["Date"].now();',
  'globalThis["performance"].now();',
  "const clock = Date; clock.now();",
  "let clock; clock = performance; clock.now();",
  "addEventListener('click', (event) => event.timeStamp);",
  "document.timeline.currentTime;",
  "new Intl.DateTimeFormat().format();",
  "new Intl.DateTimeFormat().formatToParts();",
  "Temporal.Now.instant();",
  "new PerformanceObserver(() => undefined);",
];

/** Ways to a timer, and to the callbacks a browser hands a time. */
const TIMERS = [
  "setTimeout(() => undefined, 1000);",
  "setInterval(() => undefined, 1000);",
  "window.setTimeout(() => undefined, 1000);",
  "requestAnimationFrame((time) => time);",
  "window.requestIdleCallback((deadline) => deadline.timeRemaining());",
];

/** What reads no clock: a time the server sent, formatted or compared. */
const ALLOWED = [
  "new Date(1763373600000).toISOString();",
  'Date.parse("2026-11-17T10:00:00Z");',
  "new Intl.DateTimeFormat().format(new Date(1763373600000));",
  "new Intl.NumberFormat().format(3);",
];

const eslint = new ESLint();

async function named(code: string, file: string, start: string): Promise<boolean> {
  const results = await eslint.lintText(code, { filePath: file });
  expect(results).toHaveLength(1);
  return results.some((result) =>
    result.messages.some((message) => message.ruleId === "no-restricted-syntax" && message.message.startsWith(start)),
  );
}

describe.each(["src/probe.ts", "src/probe.tsx"])("in %s", (file) => {
  it.each(CLOCKS)("a clock read as `%s` is named", async (code) => {
    expect(await named(code, file, "Read the time through")).toBe(true);
  });

  it.each(TIMERS)("a timer set as `%s` is named", async (code) => {
    expect(await named(code, file, "Set timers through")).toBe(true);
  });

  it.each(ALLOWED)("`%s` is left alone", async (code) => {
    expect(await named(code, file, "Read the time through")).toBe(false);
    expect(await named(code, file, "Set timers through")).toBe(false);
  });
});

describe("the two files that may", () => {
  it("src/lib/clock.ts reads the clocks and sets no timer", async () => {
    expect(await named("Date.now(); performance.now();", "src/lib/clock.ts", "Read the time through")).toBe(false);
    expect(await named("setTimeout(() => undefined, 1000);", "src/lib/clock.ts", "Set timers through")).toBe(true);
  });

  it("src/lib/timers.ts sets timers and reads no clock", async () => {
    expect(await named("setTimeout(() => undefined, 1000);", "src/lib/timers.ts", "Set timers through")).toBe(false);
    expect(await named("Date.now();", "src/lib/timers.ts", "Read the time through")).toBe(true);
  });
});
