import { fireEvent, screen, within } from "@testing-library/react";

import { Dashboard } from "../src/modules/Dashboard";
import { metrics, observation, session, status } from "./support/fixtures";
import { renderView } from "./support/render";
import { serve } from "./support/server";

const observations = [
  observation({ id: "a1", modules: ["antivirus"], state: "ok" }),
  observation({ id: "a2", modules: ["antivirus"], state: "warning" }),
  observation({ id: "s1", modules: ["services"], state: "failed" }),
  observation({ id: "s2", modules: ["services"], state: "ok", stale: true }),
  observation({ id: "d1", modules: ["dashboard"], state: "failed" }),
  observation({ id: "p1", modules: ["spam"], state: "ok", stale: true }),
];

const card = (name: string) => within(screen.getByRole("link", { name: new RegExp(`^${name}`) }));

describe("dashboard", () => {
  it("rates each module by its worst observation", async () => {
    serve({ "GET metrics": { body: metrics() } });
    renderView(<Dashboard />, { status: status(observations) });
    expect(card("Antivirus").getByText("Warning")).toBeTruthy();
    expect(card("Antivirus").getByText("2 checks · 1 need attention")).toBeTruthy();
    expect(card("Services").getByText("Failed")).toBeTruthy();
    expect(card("Services").getByText("2 checks · 1 need attention · 1 stale")).toBeTruthy();
    expect(screen.getByRole("link", { name: /^Services/ }).getAttribute("href")).toBe("/admin/services");
    // An old OK is no current OK.
    expect(card("Spam filter").getByText("Unknown")).toBeTruthy();
    expect(card("Spam filter").getByText("1 check · 1 stale")).toBeTruthy();
    // Modules without observations and the dashboard itself get no card.
    expect(screen.queryByRole("link", { name: /^Backups/ })).toBeNull();
    expect(screen.queryByRole("link", { name: /^Dashboard/ })).toBeNull();
    await screen.findByText(/No samples were recorded in this period/);
  });

  it("shows mailbox storage when the collector reports it", async () => {
    const table = { columns: [{ label: "Account", format: "text" as const }], rows: [["ann@example.test"]] };
    const mailboxes = observation({ id: "stalwart.mailboxes", title: "Mailbox storage", modules: ["dashboard"], table });
    serve({ "GET metrics": { body: metrics() } });
    renderView(<Dashboard />, { status: status([mailboxes]) });
    expect(screen.getByRole("heading", { name: "Mailbox storage" })).toBeTruthy();
    expect(screen.getByText("ann@example.test")).toBeTruthy();
    await screen.findByText("Queued messages");
  });

  it("shows the latest figures and Unknown for what was not measured", async () => {
    const latest = { queue_count: 3, healthy_services: 5, tls_days: 20, signature_age_hours: 1.5 };
    serve({ "GET metrics": { body: metrics({ latest }) } });
    renderView(<Dashboard />, { status: status([]) });
    const figure = (label: string) => screen.getByText(label).nextElementSibling?.textContent;
    await screen.findByText("Queued messages");
    expect(figure("Queued messages")).toBe("3");
    expect(figure("Healthy services")).toBe("5");
    expect(figure("Shortest certificate validity")).toBe("20 days");
    expect(figure("Signature age")).toBe("1.5 h");
    expect(figure("Memory used")).toBe("Unknown");
    expect(figure("Disk free")).toBe("Unknown");
  });

  it("loads the chosen period", async () => {
    const server = serve({ "GET metrics": { body: metrics({ sampledMinutes: 60, counterResets: 2 }) } });
    renderView(<Dashboard />, { status: status([]) });
    expect(await screen.findByText(/2 counter resets \(service restarts\) were accounted for/)).toBeTruthy();
    fireEvent.mouseDown(screen.getByRole("tab", { name: "7 days" }), { button: 0 });
    await screen.findByText(/2 counter resets/);
    expect(server.requests("GET metrics").map((call) => call.query.get("period"))).toEqual(["24h", "7d"]);
  });

  it("draws only series that have samples", async () => {
    const points = [{ timestamp: 1, queue_count: 4, smtp_connections: null }];
    serve({ "GET metrics": { body: metrics({ points, sampledMinutes: 1 }) } });
    renderView(<Dashboard />, { status: status([]) });
    const queue = await screen.findByText("Queue");
    expect(queue.closest("figure")?.textContent).not.toContain("No samples were recorded for this period.");
    expect(screen.getByText("Connections").closest("figure")?.textContent).toContain("No samples were recorded for this period.");
  });

  it("offers a retry when the history cannot be loaded", async () => {
    const server = serve({ "GET metrics": { status: 503, body: { detail: "The status database is not readable" } } });
    renderView(<Dashboard />, { status: status([]) });
    const retry = await screen.findByRole("button", { name: "Try again" });
    server.answer("GET metrics", { body: metrics() });
    fireEvent.click(retry);
    expect(await screen.findByText("Queued messages")).toBeTruthy();
  });

  it("names the reference of an internal error and of no other", async () => {
    const reference = { "x-request-id": "0123456789ab" };
    const server = serve({ "GET metrics": { status: 500, body: { detail: "Internal error" }, headers: reference } });
    renderView(<Dashboard />, { status: status([]) });
    expect(await screen.findByText("Reference 0123456789ab in the journal of garrison-web")).toBeTruthy();
    server.answer("GET metrics", { status: 503, body: { detail: "Metric history is not available yet" }, headers: reference });
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByText("Metric history is not available yet")).toBeTruthy();
    expect(screen.queryByText(/Reference/)).toBeNull();
  });

  it("explains a profile that grants only the dashboard", async () => {
    serve({ "GET metrics": { body: metrics() } });
    renderView(<Dashboard />, { session: session({}, ["dashboard"]), status: status([]) });
    expect(screen.getByText(/Your profile grants only the dashboard/)).toBeTruthy();
    await screen.findByText("Queued messages");
  });
});
