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
      title: "Sending addresses",
      modules: ["attacks"],
      state: "warning",
      findings: ["anna@example.test: 300 recipients in 24 hours, where 20 a day is usual."],
    });
    const elsewhere = observation({ id: "host.clock", title: "Clock synchronisation", modules: ["services"] });
    renderView(<Attacks />, { status: status([senders, elsewhere]) });
    expect(await screen.findByText("Sending addresses")).toBeTruthy();
    expect(screen.getByText("anna@example.test: 300 recipients in 24 hours, where 20 a day is usual.")).toBeTruthy();
    expect(screen.queryByText("Clock synchronisation")).toBeNull();
    expect(screen.getByText("What the evidence labels mean").tagName).toBe("SUMMARY");
  });

  it("say that the module's checks could not be read when the status cannot be", async () => {
    serve({ "GET coverage": { body: coverage() }, "GET attacks": { body: attacks() } });
    renderView(<Attacks />, { status: new Error("The status database is not readable") });
    await screen.findByRole("table", { name: "Addresses" });
    // Where the collector's checks would be, such as the sending addresses.
    const notice = screen.getByText("The collector's checks of this module could not be read.").closest("[role]");
    expect(notice?.textContent).toContain("The status database is not readable");
    expect(within(notice as HTMLElement).getByRole("button", { name: "Try again" })).toBeTruthy();
  });

  it("say that a refresh of the status failed above the checks they still show", async () => {
    serve({ "GET coverage": { body: coverage() }, "GET attacks": { body: attacks() } });
    const senders = observation({ id: "senders.accounts", title: "Sending addresses", modules: ["attacks"] });
    renderView(<Attacks />, { status: status([senders]), refreshError: new Error("The broker is not reachable") });
    await screen.findByRole("table", { name: "Addresses" });
    const notice = screen.getByText(/The status could not be refreshed/).closest("[role]");
    expect(notice?.textContent).toContain("The broker is not reachable");
    expect(screen.getByText("Sending addresses")).toBeTruthy();
  });

  it("say when the collector has produced no status yet", async () => {
    serve({ "GET coverage": { body: coverage() }, "GET attacks": { body: attacks() } });
    renderView(<Attacks />, { status: status([], { available: false }) });
    await screen.findByRole("table", { name: "Addresses" });
    expect(screen.getByText("The collector has not produced a status snapshot yet.")).toBeTruthy();
  });

  it("say that completeness is unknown when the coverage cannot be read", async () => {
    serve({
      "GET coverage": { status: 403, body: { detail: "This Garrison module is not authorized" } },
      "GET attacks": { body: attacks() },
    });
    renderView(<Attacks />);
    // The numbers are shown, and that nothing tells how complete they are.
    expect(await screen.findByRole("table", { name: "Addresses" })).toBeTruthy();
    expect(screen.getByText(/Completeness unknown/)).toBeTruthy();
    expect(screen.getByText("This Garrison module is not authorized")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Try again" })).toBeTruthy();
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
