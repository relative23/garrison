import { fireEvent, screen, within } from "@testing-library/react";

import { Logs } from "../src/modules/Logs";
import { coverage, event } from "./support/fixtures";
import { renderView } from "./support/render";
import { serve, type Call } from "./support/server";

/** Two pages: the newest events, and older ones behind the cursor. */
function pages(call: Call) {
  const older = call.query.get("before") === "cursor-1";
  const item = event({ seq: older ? 1 : 2, label: older ? "Older event" : "Newest event" });
  return { body: { items: [item], next: older ? null : "cursor-1" } };
}

const queries = (calls: Call[]) => calls.map((call) => call.query.toString());

describe("event history", () => {
  it("pages back and starts again at the newest for a new filter", async () => {
    const server = serve({ "GET coverage": { body: coverage() }, "GET events": pages });
    renderView(<Logs />);
    await screen.findByText("Newest event");
    fireEvent.click(screen.getByRole("button", { name: "Older" }));
    await screen.findByText("Older event");
    expect(screen.getByRole("button", { name: "Older" })).toHaveProperty("disabled", true);
    fireEvent.change(screen.getByRole("searchbox"), { target: { value: "  alice@example.test " } });
    fireEvent.submit(screen.getByRole("search"));
    await screen.findByText("Newest event");
    fireEvent.change(screen.getByRole("combobox", { name: "Category" }), { target: { value: "auth" } });
    await screen.findByText("Newest event");
    fireEvent.click(screen.getByRole("button", { name: "Older" }));
    await screen.findByText("Older event");
    fireEvent.click(screen.getByRole("button", { name: "Newest" }));
    await screen.findByText("Newest event");
    expect(queries(server.requests("GET events"))).toEqual([
      "limit=50",
      "before=cursor-1&limit=50",
      "search=alice%40example.test&limit=50",
      "search=alice%40example.test&category=auth&limit=50",
      "search=alice%40example.test&category=auth&before=cursor-1&limit=50",
      "search=alice%40example.test&category=auth&limit=50",
    ]);
  });

  it("shows recorded fields and links to the delivery and SMTP session", async () => {
    const smtp = event({
      category: "smtp",
      queueId: "1a2b3c4d5e6f",
      spanId: "abcdef123456",
      fields: { remoteIp: "192.0.2.1", queueId: "1a2b3c4d5e6f", spanId: "abcdef123456" },
    });
    const other = event({ seq: 2, category: "auth", spanId: "777777", fields: {} });
    serve({ "GET coverage": { body: coverage() }, "GET events": { body: { items: [smtp, other], next: null } } });
    renderView(<Logs />);
    const [, first, second] = await screen.findAllByRole("row");
    const row = within(first as HTMLElement);
    expect(row.getByText("remoteIp: 192.0.2.1")).toBeTruthy();
    expect(row.getByRole("link", { name: "Queue 4d5e6f" }).getAttribute("href")).toBe("/admin/deliveries/1a2b3c4d5e6f");
    expect(row.getByRole("link", { name: "Session 123456" }).getAttribute("href")).toBe("/admin/sessions/abcdef123456");
    // Only SMTP spans are sessions the Sessions page can show.
    expect(within(second as HTMLElement).queryByRole("link")).toBeNull();
  });

  it("says when nothing matches", async () => {
    serve({ "GET coverage": { body: coverage() }, "GET events": { body: { items: [], next: null } } });
    renderView(<Logs />);
    expect(await screen.findByText("No recorded events match.")).toBeTruthy();
    expect(screen.getByText("Showing 0 entries, newest first")).toBeTruthy();
  });
});

describe("history coverage", () => {
  it("says when there is no history yet", async () => {
    serve({ "GET coverage": { body: coverage({ available: false }) }, "GET events": { body: { items: [], next: null } } });
    renderView(<Logs />);
    expect(await screen.findByText(/The event history is not available yet/)).toBeTruthy();
  });

  it("warns about recording gaps and a quiet receiver", async () => {
    const gaps = [
      { start: 100, end: 200, reason: "receiver-offline" },
      { start: 300, end: 400, reason: "a-future-reason" },
    ];
    const quiet = Math.floor(Date.now() / 1000) - 3 * 3600;
    const value = coverage({ receiver: "stale", heartbeatAt: quiet, lastBatchAt: quiet, gapCount: 2, gaps, retentionDays: null });
    serve({ "GET coverage": { body: value }, "GET events": { body: { items: [], next: null } } });
    renderView(<Logs />);
    const banner = await screen.findByText(/Recording since/);
    expect(banner.textContent).toContain("1,234 events · last received 3.0 h ago · retention unknown.");
    expect(banner.textContent).toContain("The event receiver has not reported since");
    expect(banner.textContent).toContain("2 recording gaps.");
    expect(screen.getByText(/The event receiver was offline/)).toBeTruthy();
    expect(screen.getByText(/a-future-reason/)).toBeTruthy();
  });

  it("says where a size limit made the history begin, without a warning", async () => {
    const limits: [string, string][] = [
      ["events", "to stay within the event limit"],
      ["bytes", "to stay within the storage budget"],
      ["a-future-limit", "to stay within a size limit"],
    ];
    for (const [limit, wording] of limits) {
      serve({ "GET coverage": { body: coverage({ trimmed: { until: 100, limit } }) }, "GET events": { body: { items: [], next: null } } });
      const view = renderView(<Logs />);
      const banner = await screen.findByText(/Recording since/);
      expect(banner.textContent).toContain(`retention 30 days. Events before `);
      expect(banner.textContent).toContain(`were removed ${wording}, so the history is shorter than its retention.`);
      // Working as configured: no gap, no warning.
      expect(banner.closest("[role]")?.getAttribute("role")).toBe("status");
      expect(screen.queryByText("Recording gaps")).toBeNull();
      view.unmount();
    }
  });

  it("says when the receiver never reported and nothing arrived", async () => {
    serve({ "GET coverage": { body: coverage({ receiver: "stale" }) }, "GET events": { body: { items: [], next: null } } });
    renderView(<Logs />);
    const banner = await screen.findByText(/Recording since/);
    expect(banner.textContent).toContain("nothing received yet");
    expect(banner.textContent).toContain("has not reported recently");
  });

  it("is calm when the history is complete", async () => {
    serve({ "GET coverage": { body: coverage() }, "GET events": { body: { items: [], next: null } } });
    renderView(<Logs />);
    const banner = await screen.findByText(/Recording since/);
    expect(banner.textContent).toContain("retention 30 days.");
    expect(banner.closest("[role]")?.getAttribute("role")).toBe("status");
    expect(screen.queryByText("Recording gaps")).toBeNull();
  });
});
