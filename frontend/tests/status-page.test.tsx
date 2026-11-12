import { screen, within } from "@testing-library/react";

import { StatusPage } from "../src/modules/StatusPage";
import { observation, status } from "./support/fixtures";
import { renderView } from "./support/render";

// Card titles follow the page title directly, one level below it.
const titles = () => screen.queryAllByRole("heading", { level: 2 }).map((heading) => heading.textContent);

describe("status pages", () => {
  it("list the module's observations, most urgent first", () => {
    const value = status([
      observation({ id: "1", title: "B ok", state: "ok" }),
      observation({ id: "2", title: "Unknown", state: "unknown" }),
      observation({ id: "3", title: "A ok", state: "ok" }),
      observation({ id: "4", title: "Partial", state: "partial" }),
      observation({ id: "5", title: "Failed", state: "failed" }),
      observation({ id: "6", title: "Warning", state: "warning" }),
      observation({ id: "7", title: "Spam only", modules: ["spam"] }),
    ]);
    renderView(<StatusPage moduleId="antivirus" detail={null} />, { status: value });
    expect(titles()).toEqual(["Failed", "Warning", "Partial", "Unknown", "A ok", "B ok"]);
  });

  it("give a table of many columns the page's width", () => {
    const columns = (count: number) => Array.from({ length: count }, (_, index) => ({ label: `Column ${index}`, format: "text" as const }));
    const value = status([
      observation({ id: "wide", title: "Wide", table: { columns: columns(6), rows: [["a", "b", "c", "d", "e", "f"]] } }),
      observation({ id: "narrow", title: "Narrow", table: { columns: columns(3), rows: [["a", "b", "c"]] } }),
    ]);
    renderView(<StatusPage moduleId="antivirus" detail={null} />, { status: value });
    const card = (title: string) => screen.getByRole("region", { name: title });
    expect(card("Wide").className).toContain("xl:col-span-2");
    expect(card("Narrow").className).not.toContain("col-span");
  });

  it("show processes as a table and versions as a list", () => {
    const service = observation({
      id: "unit",
      kind: "service",
      title: "Antivirus daemon",
      state: "ok",
      value: { unit: "clamd@scan.service" },
      fields: [
        { label: "State", value: "active", format: "text" },
        { label: "Memory", value: 1048576, format: "bytes" },
        { label: "Restarts", value: null, format: "number" },
      ],
    });
    const version = observation({ id: "version", kind: "version", evidence: "process", value: { component: "ClamAV", version: "1.4.3" } });
    renderView(<StatusPage moduleId="antivirus" detail={null} />, { status: status([service, version]) });
    const row = within(screen.getByRole("row", { name: /Antivirus daemon/ }));
    expect(row.getByText("clamd@scan.service")).toBeTruthy();
    // The first field is the state badge's; unknown values are left out.
    expect(row.getByText("Memory: 1.0 MiB")).toBeTruthy();
    expect(screen.getByText("ClamAV").nextElementSibling?.textContent).toContain("1.4.3");
  });

  it("name failed providers on the services page only", () => {
    const value = status([observation({ modules: ["services", "antivirus"] })], {
      providerErrors: [{ provider: "clamav", error: "timeout" }],
    });
    const view = renderView(<StatusPage moduleId="services" detail={null} />, { status: value });
    expect(screen.getByText(/Providers failed in the last run: clamav/)).toBeTruthy();
    view.unmount();
    renderView(<StatusPage moduleId="antivirus" detail={null} />, { status: value });
    expect(screen.queryByText(/Providers failed/)).toBeNull();
  });

  it("say when there is no snapshot or no observation yet", () => {
    const view = renderView(<StatusPage moduleId="antivirus" detail={null} />, { status: status([], { available: false }) });
    expect(screen.getByText("The collector has not produced a status snapshot yet.")).toBeTruthy();
    view.unmount();
    renderView(<StatusPage moduleId="backups" detail={null} />, { status: status([observation()]) });
    expect(screen.getByText("No provider reports observations for this module on this host.")).toBeTruthy();
  });

  it("show why the status is missing", () => {
    renderView(<StatusPage moduleId="antivirus" detail={null} />, { status: new Error("The status database is not readable") });
    expect(screen.getByText("The status database is not readable")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Try again" })).toBeTruthy();
  });
});
