import { fireEvent, screen, within } from "@testing-library/react";

import { Attacks } from "../src/modules/Attacks";
import { attacks, coverage, observation, status } from "./support/fixtures";
import { renderView } from "./support/render";
import { serve } from "./support/server";

function table(name: string): HTMLElement {
  return screen.getByRole("table", { name });
}

describe("Attacks & bans", () => {
  it("sum the day by address, network and account, and list the bans", async () => {
    serve({ "GET coverage": { body: coverage() }, "GET attacks": { body: attacks() } });
    renderView(<Attacks />);
    const sources = within(await screen.findByRole("table", { name: "Addresses" }));
    const [, first, second] = sources.getAllByRole("row");
    expect(within(first as HTMLElement).getByText("192.0.2.10")).toBeTruthy();
    expect(within(first as HTMLElement).getByText("imaps, submission")).toBeTruthy();
    expect(within(first as HTMLElement).getByText("1,200")).toBeTruthy();
    expect(within(second as HTMLElement).getByText("192.0.2.77")).toBeTruthy();
    // The figures count everything, the lists only their rows.
    expect(screen.getByText("For no existing account").nextElementSibling?.textContent).toBe("1,100");
    expect(screen.getByText("TLS handshake errors").nextElementSibling?.textContent).toBe("3");
    expect(within(table("Networks with several addresses")).getByText("192.0.2.0/24")).toBeTruthy();
    expect(within(table("Accounts under attack")).getByText("anna@example.test")).toBeTruthy();
    expect(within(table("Stalwart's bans")).getByText("Too many failed sign-ins")).toBeTruthy();
    expect(screen.queryByText(/More events were recorded/)).toBeNull();
  });

  it("ask for the period that is chosen", async () => {
    const server = serve({ "GET coverage": { body: coverage() }, "GET attacks": { body: attacks() } });
    renderView(<Attacks />);
    await screen.findByRole("table", { name: "Addresses" });
    const week = screen.getByRole("tab", { name: "7 days" });
    fireEvent.mouseDown(week);
    fireEvent.click(week);
    await screen.findByRole("table", { name: "Addresses" });
    expect(server.requests("GET attacks").map((call) => call.query.toString())).toEqual(["period=24h", "period=7d"]);
  });

  it("say so when a quiet period has nothing and when a busy one is cut", async () => {
    const quiet = attacks({
      truncated: true,
      totals: { failedSignIns: 0, unknownAccounts: 0, tlsErrors: 0, bans: 0, sources: 0 },
      sources: [],
      networks: [],
      accounts: [],
      bans: [],
    });
    serve({ "GET coverage": { body: coverage() }, "GET attacks": { body: quiet } });
    renderView(<Attacks />);
    expect(await screen.findByText("No failed sign-in, ban or TLS error was recorded in this period.")).toBeTruthy();
    expect(screen.getByText("Stalwart banned no address in this period.")).toBeTruthy();
    expect(screen.getByText("No failed sign-in named an existing account.")).toBeTruthy();
    expect(screen.getByText("No network was seen with more than one address.")).toBeTruthy();
    expect(screen.getByText(/More events were recorded in this period/)).toBeTruthy();
  });

  it("show what the collector's checks say of the module", async () => {
    serve({ "GET coverage": { body: coverage() }, "GET attacks": { body: attacks() } });
    const senders = observation({
      id: "senders.accounts",
      title: "Sending accounts",
      modules: ["attacks"],
      state: "warning",
      findings: ["anna@example.test: 300 recipients in 24 hours, where 20 a day is usual."],
    });
    const elsewhere = observation({ id: "host.clock", title: "Clock synchronisation", modules: ["services"] });
    renderView(<Attacks />, { status: status([senders, elsewhere]) });
    expect(await screen.findByText("Sending accounts")).toBeTruthy();
    expect(screen.getByText("anna@example.test: 300 recipients in 24 hours, where 20 a day is usual.")).toBeTruthy();
    expect(screen.queryByText("Clock synchronisation")).toBeNull();
  });

  it("show the error of a summary that cannot be read", async () => {
    serve({
      "GET coverage": { body: coverage() },
      "GET attacks": { status: 503, body: { detail: "The query took too long; narrow the filter" } },
    });
    renderView(<Attacks />);
    expect(await screen.findByText(/The query took too long/)).toBeTruthy();
  });
});
