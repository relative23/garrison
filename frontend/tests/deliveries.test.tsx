import { fireEvent, screen, within } from "@testing-library/react";

import { Deliveries } from "../src/modules/Deliveries";
import { coverage, delivery, event } from "./support/fixtures";
import { renderView } from "./support/render";
import { serve } from "./support/server";

const QUEUE = delivery().queueId;

describe("deliveries", () => {
  it("list recipients, status and a link to each queue", async () => {
    const many = delivery({
      queueId: "ffffffff00000001",
      to: ["a@example.test", "b@example.test", "c@example.test", "d@example.test", "e@example.test"],
      status: "deferred",
      recipientEvidenceComplete: false,
    });
    const odd = delivery({ queueId: "ffffffff00000002", status: "rerouted" });
    serve({ "GET coverage": { body: coverage() }, "GET deliveries": { body: { items: [delivery(), many, odd], next: null } } });
    renderView(<Deliveries moduleId="deliveries" detail={null} />);
    const [, first, second, third] = await screen.findAllByRole("row");
    expect(within(first as HTMLElement).getByText("Delivered")).toBeTruthy();
    const link = within(first as HTMLElement).getByRole("link", { name: QUEUE.slice(-8) });
    expect(link.getAttribute("href")).toBe(`/admin/deliveries/${QUEUE}`);
    expect(within(second as HTMLElement).getByText("a@example.test, b@example.test, c@example.test +2")).toBeTruthy();
    expect(within(second as HTMLElement).getByText("Deferred (incomplete)")).toBeTruthy();
    // A status this build does not know is shown as the server named it.
    expect(within(third as HTMLElement).getByText("rerouted")).toBeTruthy();
  });

  it("search from the newest delivery", async () => {
    const server = serve({ "GET coverage": { body: coverage() }, "GET deliveries": { body: { items: [], next: null } } });
    renderView(<Deliveries moduleId="deliveries" detail={null} />);
    expect(await screen.findByText("No recorded deliveries match.")).toBeTruthy();
    fireEvent.change(screen.getByRole("searchbox"), { target: { value: "example.net" } });
    fireEvent.submit(screen.getByRole("search"));
    await screen.findByText("No recorded deliveries match.");
    expect(server.requests("GET deliveries").map((call) => call.query.toString())).toEqual(["limit=25", "search=example.net&limit=25"]);
  });

  it("show one queue with each recipient's recorded outcome", async () => {
    const summary = delivery({
      to: ["bob@example.test", "eve@example.test"],
      status: "partial",
      recipientOutcomes: { "bob@example.test": "delivered" },
    });
    const timeline = [event({ type: "queue.message-queued", label: "Message queued", fields: { elapsed: 1500, queueId: QUEUE } })];
    serve({ [`GET deliveries/${QUEUE}`]: { body: { summary, events: timeline, truncated: true } } });
    renderView(<Deliveries moduleId="deliveries" detail={QUEUE} />);
    expect(await screen.findByText(`Queue ${QUEUE}`)).toBeTruthy();
    const [, bob, eve] = screen.getAllByRole("row");
    expect(within(bob as HTMLElement).getByText("Delivered")).toBeTruthy();
    expect(within(eve as HTMLElement).getByText("Unknown")).toBeTruthy();
    expect(screen.getByText("Only the first events of this queue are shown.")).toBeTruthy();
    expect(screen.getByText("Message queued")).toBeTruthy();
    // Durations are shown readably; correlation IDs are already in the title.
    expect(screen.getByText("1.5 s")).toBeTruthy();
    expect(screen.queryByText("queueId")).toBeNull();
    expect(screen.getByRole("link", { name: "All deliveries" }).getAttribute("href")).toBe("/admin/deliveries");
  });

  it("say when a queue is not in the history", async () => {
    serve({ [`GET deliveries/${QUEUE}`]: { status: 404, body: { detail: "No recorded events for this queue" } } });
    renderView(<Deliveries moduleId="deliveries" detail={QUEUE} />);
    expect(await screen.findByText("No recorded events for this queue")).toBeTruthy();
  });
});
