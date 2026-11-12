import { render, screen } from "@testing-library/react";

import { MetricChart } from "../src/components/Charts";
import { metrics } from "./support/fixtures";

const HOUR = 3600;
const series = [
  { key: "smtp_connections", label: "SMTP" },
  { key: "imap_connections", label: "IMAP" },
];

/** Give each chart a size: jsdom lays nothing out, and Recharts draws nothing at 0 × 0. */
beforeEach(() => {
  vi.spyOn(HTMLElement.prototype, "getBoundingClientRect").mockImplementation(function (this: HTMLElement) {
    const chart = this.classList.contains("recharts-responsive-container");
    return { width: chart ? 600 : 0, height: chart ? 220 : 0 } as DOMRect;
  });
});

function draw(kind: "line" | "bar", from: number, to: number) {
  const step = (to - from) / 4;
  const points = [4, 5, null, 6, 7].map((value, index) => ({
    timestamp: from + index * step,
    smtp_connections: value,
    imap_connections: null,
  }));
  return render(<MetricChart title="Connections" kind={kind} series={series} history={metrics({ from, to, points })} />);
}

/** The time axis labels; Recharts draws labels apart from the axis line. */
function ticks(container: HTMLElement): string[] {
  const selector = ".recharts-cartesian-axis-tick-value[orientation='bottom']";
  const labels = [...container.querySelectorAll(selector)].map((tick) => tick.textContent ?? "");
  expect(labels.length).toBeGreaterThan(1);
  return labels;
}

describe("metric charts", () => {
  it("label a day by time and longer periods by date", () => {
    const from = Date.UTC(2026, 9, 29, 0, 0) / 1000;
    const day = draw("line", from, from + 24 * HOUR);
    expect(ticks(day.container).every((tick) => /^\d{2}:\d{2}/.test(tick))).toBe(true);
    day.unmount();
    const week = draw("bar", from, from + 7 * 24 * HOUR);
    expect(ticks(week.container).every((tick) => /^[A-Z][a-z]{2} \d{1,2}$/.test(tick))).toBe(true);
  });

  it("draw only series that have samples and never join a gap", () => {
    const { container } = draw("line", 0, 24 * HOUR);
    expect(screen.getByText("SMTP")).toBeTruthy();
    expect(screen.queryByText("IMAP")).toBeNull();
    // Samples on both sides of a gap: two separate segments, not one line.
    const path = container.querySelector(".recharts-line-curve")?.getAttribute("d") ?? "";
    expect(path.match(/M/g)).toHaveLength(2);
  });

  it("sum each counted series over the period", () => {
    const totals = { smtp_connections: 1234 };
    const points = [{ timestamp: 0, smtp_connections: 1234, imap_connections: null }];
    render(<MetricChart title="Mail flow" kind="bar" series={series} history={metrics({ points, totals })} />);
    expect(screen.getByText("In this period: SMTP: 1,234")).toBeTruthy();
    // Levels such as memory are not summed.
    render(<MetricChart title="Resources" kind="line" series={series} history={metrics({ points, totals })} />);
    expect(screen.getAllByText(/In this period/)).toHaveLength(1);
  });

  it("stack bars only when asked", () => {
    const points = [{ timestamp: 0, smtp_connections: 4, imap_connections: 2 }];
    const bars = (stacked: boolean) => {
      const { container, unmount } = render(
        <MetricChart title="Flow" kind="bar" stacked={stacked} series={series} history={metrics({ points, to: 3600 })} />,
      );
      const tops = [...container.querySelectorAll(".recharts-bar-rectangle path")].map((bar) => bar.getAttribute("d")?.split(",")[0]);
      unmount();
      expect(tops).toHaveLength(2);
      return tops;
    };
    // Side by side, the two bars start at different x positions; stacked, at the same one.
    const [first, second] = bars(false);
    expect(first).not.toBe(second);
    const [lower, upper] = bars(true);
    expect(lower).toBe(upper);
  });

  it("say when the period has no samples", () => {
    render(<MetricChart title="Queue" kind="line" series={series} history={metrics()} />);
    expect(screen.getByText("No samples were recorded for this period.")).toBeTruthy();
  });
});
