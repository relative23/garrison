import { fireEvent, screen, within } from "@testing-library/react";

import { Deliveries } from "../src/modules/Deliveries";
import { coverage, destinations } from "./support/fixtures";
import { renderView } from "./support/render";
import { serve } from "./support/server";

function open(body = destinations()) {
  const server = serve({
    "GET coverage": { body: coverage() },
    "GET deliveries": { body: { items: [], next: null } },
    "GET destinations": { body },
  });
  renderView(<Deliveries moduleId="deliveries" detail={null} />);
  return server;
}

async function problems() {
  const tab = await screen.findByRole("tab", { name: "Problems by destination" });
  fireEvent.mouseDown(tab);
  fireEvent.click(tab);
}

describe("Delivery problems", () => {
  it("are a second view beside the messages, asked for only when opened", async () => {
    const server = open();
    expect(await screen.findByText("No recorded deliveries match.")).toBeTruthy();
    expect(server.requests("GET destinations")).toHaveLength(0);
    await problems();
    expect(await screen.findByRole("table", { name: "Destinations with problems" })).toBeTruthy();
    expect(server.requests("GET destinations").map((call) => call.query.toString())).toEqual(["period=24h"]);
  });

  it("sum delays and bounces by destination and by cause", async () => {
    open();
    await problems();
    const byDomain = within(await screen.findByRole("table", { name: "Destinations with problems" }));
    const [, strict, slow] = byDomain.getAllByRole("row");
    expect(within(strict as HTMLElement).getByText("strict.example")).toBeTruthy();
    expect(within(strict as HTMLElement).getByText("mx1.strict.example")).toBeTruthy();
    expect(within(strict as HTMLElement).getByText("550 5.7.1 Sender rejected")).toBeTruthy();
    expect(within(slow as HTMLElement).getByText("Connection timed out")).toBeTruthy();
    const byCause = within(screen.getByRole("table", { name: "Causes" }));
    expect(byCause.getAllByRole("row")).toHaveLength(3);
    expect(screen.getByText("Bounces", { selector: "dt" }).nextElementSibling?.textContent).toBe("12");
    expect(screen.getByText("Delivered", { selector: "dt" }).nextElementSibling?.textContent).toBe("240");
  });

  it("list the messages that wait, oldest first, with a link to each", async () => {
    open();
    await problems();
    const waiting = within(await screen.findByRole("table", { name: "Messages that wait" }));
    expect(waiting.getByRole("link", { name: "89541120" }).getAttribute("href")).toBe("/admin/deliveries/337538776689541120");
    expect(waiting.getByText("2.0 h")).toBeTruthy();
  });

  it("say so when nothing went wrong and when the period is cut", async () => {
    open(
      destinations({
        truncated: true,
        totals: { delivered: 5, delays: 0, bounces: 0, destinations: 0, waiting: 0 },
        destinations: [],
        causes: [],
        waiting: [],
      }),
    );
    await problems();
    expect(await screen.findByText("No destination had a delay or a bounce in this period.")).toBeTruthy();
    expect(screen.getByText("No delay or bounce was recorded in this period.")).toBeTruthy();
    expect(screen.getByText("No message waits.")).toBeTruthy();
    expect(screen.getByText(/More events were recorded in this period/)).toBeTruthy();
  });

  it("ask again for another period", async () => {
    const server = open();
    await problems();
    await screen.findByRole("table", { name: "Causes" });
    const month = screen.getByRole("tab", { name: "30 days" });
    fireEvent.mouseDown(month);
    fireEvent.click(month);
    await screen.findByRole("table", { name: "Causes" });
    expect(server.requests("GET destinations").map((call) => call.query.toString())).toEqual(["period=24h", "period=30d"]);
  });
});
