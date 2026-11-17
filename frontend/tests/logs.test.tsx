import { act, fireEvent, screen, within } from "@testing-library/react";

import { Logs } from "../src/modules/Logs";
import { coverage, event, NOW } from "./support/fixtures";
import { renderView } from "./support/render";
import { serve, type Call } from "./support/server";

/** Two pages: the newest events, and older ones behind the cursor. */
function pages(call: Call) {
  const older = call.query.get("before") === "cursor-1";
  const item = event({ seq: older ? 1 : 2, label: older ? "Older event" : "Newest event" });
  return { body: { items: [item], next: older ? null : "cursor-1" } };
}

const queries = (calls: Call[]) => calls.map((call) => call.query.toString());

/** Whether the pager's button `name` can act: one that cannot stays in the
 * keyboard's reach, since a disabled button drops the focus it holds. */
function available(name: string): boolean {
  const button = screen.getByRole<HTMLButtonElement>("button", { name });
  expect(button.disabled).toBe(false);
  return button.getAttribute("aria-disabled") !== "true";
}

describe("event history", () => {
  it("pages back and starts again at the newest for a new filter", async () => {
    const server = serve({ "GET coverage": { body: coverage() }, "GET events": pages });
    renderView(<Logs />);
    await screen.findByText("Newest event");
    fireEvent.click(screen.getByRole("button", { name: "Older" }));
    await screen.findByText("Older event");
    expect(available("Older")).toBe(false);
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

  it("shows nothing of the previous filter when the new filter's request fails", async () => {
    const server = serve({ "GET coverage": { body: coverage() }, "GET events": pages });
    renderView(<Logs />);
    await screen.findByText("Newest event");
    expect(available("Older")).toBe(true);
    server.answer("GET events", { status: 503, body: { detail: "The event history is busy." } });
    fireEvent.change(screen.getByRole("combobox", { name: "Category" }), { target: { value: "auth" } });
    expect(await screen.findByText("The event history is busy.")).toBeTruthy();
    // Neither the other filter's rows nor its cursor to older pages.
    expect(screen.queryByText("Newest event")).toBeNull();
    expect(screen.queryByRole("table")).toBeNull();
    expect(available("Older")).toBe(false);
    // How many entries this filter has is not known: no count, not zero.
    expect(screen.queryByText(/^Showing/)).toBeNull();
  });

  it("keeps the pager's buttons in the keyboard's reach while they cannot act, and then they do nothing", async () => {
    let answer: () => void = () => undefined;
    const server = serve({
      "GET coverage": { body: coverage() },
      "GET events": async (call) => {
        if (call.query.has("before")) await new Promise<void>((resolve) => (answer = resolve));
        return pages(call);
      },
    });
    renderView(<Logs />);
    await screen.findByText("Newest event");
    // On the newest page, Newest has nowhere to go.
    expect(available("Newest")).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Newest" }));
    // While the older page loads, its cursor to the next one is not known.
    fireEvent.click(screen.getByRole("button", { name: "Older" }));
    await screen.findByText("Loading…");
    expect(available("Older")).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Older" }));
    await act(async () => answer());
    await screen.findByText("Older event");
    expect(available("Newest")).toBe(true);
    expect(queries(server.requests("GET events"))).toEqual(["limit=50", "before=cursor-1&limit=50"]);
  });

  it("gives no count while the list loads", async () => {
    let answer: () => void = () => undefined;
    const arrived = new Promise<void>((resolve) => {
      answer = resolve;
    });
    serve({
      "GET coverage": { body: coverage() },
      "GET events": async (call) => {
        await arrived;
        return pages(call);
      },
    });
    renderView(<Logs />);
    await screen.findByText(/Recording since/);
    expect(screen.getByText("Loading…")).toBeTruthy();
    expect(screen.queryByText(/^Showing/)).toBeNull();
    answer();
    expect(await screen.findByText("Showing 1 entry, newest first")).toBeTruthy();
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
    const quiet = NOW - 3 * 3600;
    const value = coverage({
      receiver: "stale",
      heartbeatAt: quiet,
      lastBatchAt: quiet,
      lastBatchAge: 3 * 3600,
      gapCount: 2,
      gaps,
      retentionDays: null,
    });
    serve({ "GET coverage": { body: value }, "GET events": { body: { items: [], next: null } } });
    renderView(<Logs />);
    const banner = await screen.findByText(/Recording since/);
    expect(banner.textContent).toContain("1,234 events · last received 3.0 h ago · retention unknown.");
    expect(banner.textContent).toContain("The event receiver has not reported since");
    expect(banner.textContent).toContain("2 recording gaps.");
    expect(screen.getByText(/The event receiver was offline/)).toBeTruthy();
    expect(screen.getByText(/a-future-reason/)).toBeTruthy();
  });

  it("says when the last batch arrived by the age the server gave, whatever the browser's clock says", async () => {
    // The browser's clock runs five hours ahead of the server's.
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime((NOW + 5 * 3600) * 1000);
    const value = coverage({ lastBatchAt: NOW - 3 * 3600, lastBatchAge: 3 * 3600 });
    serve({ "GET coverage": { body: value }, "GET events": { body: { items: [], next: null } } });
    renderView(<Logs />);
    const banner = await screen.findByText(/Recording since/);
    expect(banner.textContent).toContain(" · last received 3.0 h ago · ");
  });

  it("says it does not know when the last batch came where the server gives no age for it", async () => {
    // A time the server does not count from: none a clock gives, or one ahead of its clock.
    serve({
      "GET coverage": { body: coverage({ lastBatchAt: NOW + 3600, lastBatchAge: null }) },
      "GET events": { body: { items: [], next: null } },
    });
    renderView(<Logs />);
    const banner = await screen.findByText(/Recording since/);
    expect(banner.textContent).toContain(" · last received Unknown · ");
  });

  it("warns when the receiver runs but stores nothing", async () => {
    const since = Math.floor(Date.now() / 1000) - 7200;
    const gaps = [{ start: 100, end: 200, reason: "batches-refused" }];
    const value = coverage({ receiver: "refusing", failingSince: since, heartbeatAt: since + 7190, gapCount: 1, gaps });
    serve({ "GET coverage": { body: value }, "GET events": { body: { items: [], next: null } } });
    renderView(<Logs />);
    const banner = await screen.findByText(/Recording since/);
    expect(banner.textContent).toContain("The event receiver runs, but has not stored what Stalwart sends since");
    expect(banner.textContent).not.toContain("has not reported since");
    // Part of the page, and read again every minute: no live region, which
    // would read it out each time its "last received" changes.
    expect(banner.closest("[role]")).toBeNull();
    expect(screen.getByText(/refused Stalwart's batches for longer than Stalwart buffers/)).toBeTruthy();
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
      expect(banner.closest("[role]")).toBeNull();
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

  it("says that completeness is unknown, not the coverage it read before, when a refresh fails", async () => {
    vi.useFakeTimers();
    vi.spyOn(document, "visibilityState", "get").mockReturnValue("visible");
    const server = serve({ "GET coverage": { body: coverage() }, "GET events": { body: { items: [], next: null } } });
    renderView(<Logs />);
    await act(async () => vi.advanceTimersByTimeAsync(100));
    expect(screen.getByText(/Recording since/)).toBeTruthy();
    server.answer("GET coverage", { status: 503, body: { detail: "Authorization is temporarily unavailable" } });
    await act(async () => vi.advanceTimersByTimeAsync(60_000));
    // A change the page reports: that is announced.
    expect(
      screen
        .getByText(/Completeness unknown/)
        .closest("[role]")
        ?.getAttribute("role"),
    ).toBe("status");
    expect(screen.getByText("Authorization is temporarily unavailable")).toBeTruthy();
    expect(screen.queryByText(/Recording since/)).toBeNull();
    // The next answer brings the coverage back.
    server.answer("GET coverage", { body: coverage() });
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    await act(async () => vi.advanceTimersByTimeAsync(100));
    expect(screen.getByText(/Recording since/)).toBeTruthy();
    expect(screen.queryByText(/Completeness unknown/)).toBeNull();
  });

  it("is calm when the history is complete", async () => {
    serve({ "GET coverage": { body: coverage() }, "GET events": { body: { items: [], next: null } } });
    renderView(<Logs />);
    const banner = await screen.findByText(/Recording since/);
    expect(banner.textContent).toContain("retention 30 days.");
    expect(banner.closest("[role]")).toBeNull();
    expect(screen.queryByText("Recording gaps")).toBeNull();
  });
});
