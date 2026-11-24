import * as Tooltip from "@radix-ui/react-tooltip";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";

import type { Observation } from "../src/api/client";
import { ObservationCard, ServiceTable } from "../src/components/ObservationCard";

const base: Observation = {
  id: "clamav.configuration",
  provider: "clamav",
  title: "Antivirus configuration",
  modules: ["antivirus"],
  evidence: "configuration",
  state: "warning",
  checkedAt: "2026-10-29T10:00:00+00:00",
  source: "/etc/mail/clamav-milter.conf",
  kind: "details",
  scope: "On-disk configuration; whether the running daemons loaded it is not verified.",
  fields: [
    { label: "Detected malware", value: "Accept", format: "text" },
    { label: "Milter file limit", value: 26214400, format: "bytes" },
    { label: "Archive scanning", value: null, format: "boolean" },
  ],
  table: null,
  findings: ["Detected malware is handled with Accept, not Reject."],
  value: {},
  maxAge: 300,
  age: 0,
  stale: false,
};

function show(observation: Observation) {
  return render(
    <Tooltip.Provider>
      <ObservationCard observation={observation} />
    </Tooltip.Provider>,
  );
}

describe("ObservationCard", () => {
  it("shows findings, formatted values, evidence and scope", () => {
    show(base);
    expect(screen.getByText("Detected malware is handled with Accept, not Reject.")).toBeTruthy();
    expect(screen.getByText("25.0 MiB")).toBeTruthy();
    expect(screen.getByText("Unknown")).toBeTruthy();
    expect(screen.getByText("Configuration")).toBeTruthy();
    expect(screen.getByText(/not verified/)).toBeTruthy();
    expect(screen.getByText("Warning")).toBeTruthy();
  });

  it("says how long ago its source was asked by the age the server gave, not by the browser's clock", () => {
    // Asked two hours before the server's answer; the browser's clock is
    // weeks after `checkedAt`, and may be another than the server's.
    show({ ...base, age: 7200 });
    expect(screen.getByText(/^Checked 2\.0 h ago/)).toBeTruthy();
    cleanup();
    // A check dated ahead of the server's clock, and one whose time cannot be read.
    show({ ...base, age: -300 });
    expect(screen.getByText(/^Checked in 5 min/)).toBeTruthy();
    cleanup();
    show({ ...base, age: null });
    expect(screen.getByText(/^Checked Unknown/)).toBeTruthy();
  });

  it("marks stale observations instead of showing their old state", () => {
    show({ ...base, state: "ok", stale: true, findings: [] });
    expect(screen.getByText("Stale")).toBeTruthy();
    expect(screen.queryByText("OK")).toBeNull();
  });

  it("shows the first rows of a long table and the rest on request", () => {
    const rows = Array.from({ length: 12 }, (_, index) => [`user${index}@example.test`, index * 1024]);
    const table = {
      columns: [
        { label: "Account", format: "text" as const },
        { label: "Used", format: "bytes" as const },
      ],
      rows,
    };
    render(
      <Tooltip.Provider>
        <ObservationCard observation={{ ...base, table }} limit={10} />
      </Tooltip.Provider>,
    );
    expect(screen.getAllByRole("row")).toHaveLength(11);
    const button = screen.getByRole("button", { name: "Show all 12 rows" });
    button.focus();
    fireEvent.click(button);
    expect(screen.getAllByRole("row")).toHaveLength(13);
    expect(screen.getByText("11.0 KiB")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Show all/ })).toBeNull();
    // The button is gone: the keyboard goes on from the first row it showed.
    expect(document.activeElement?.textContent).toBe("user10@example.test10.0 KiB");
  });

  it("leaves the focus where it was when the rows are shown by a pointer that gave the button none", () => {
    const rows = Array.from({ length: 12 }, (_, index) => [`user${index}@example.test`]);
    render(
      <Tooltip.Provider>
        <ObservationCard observation={{ ...base, table: { columns: [{ label: "Account", format: "text" }], rows } }} limit={10} />
      </Tooltip.Provider>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Show all 12 rows" }));
    expect(document.activeElement).toBe(document.body);
  });

  it("lets a long value break inside its cell and leaves short ones alone", () => {
    const key = `v=DKIM1; k=rsa; p=${"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A".repeat(3)}`;
    const table = {
      columns: [
        { label: "Name", format: "text" as const },
        { label: "Stalwart names", format: "text" as const },
      ],
      rows: [["sel._domainkey.example.test", key]],
    };
    show({ ...base, table, source: "https://api.example.test/repos/owner/name/releases/latest" });
    expect(screen.getByText(key).className).toContain("wrap-anywhere");
    expect(screen.getByText("sel._domainkey.example.test").tagName).toBe("TD");
    // The source has no space to break at either.
    expect(screen.getByText(/api\.example\.test/).className).toContain("wrap-anywhere");
  });

  it("names an evidence kind this build does not know as the server does", () => {
    show({ ...base, evidence: "survey" as Observation["evidence"] });
    expect(screen.getByText("survey")).toBeTruthy();
  });

  it("shows a state this build does not know as the server names it, in Unknown's colours", () => {
    // As a page loaded before an upgrade would get it from the newer service.
    const state = "degraded" as Observation["state"];
    show({ ...base, state });
    const badge = screen.getByText("degraded");
    expect(badge.className).toContain("text-unknown");
    expect(badge.getAttribute("title")).toBe("A state this page does not know; reload it");
    expect(screen.queryByText("Warning")).toBeNull();
    cleanup();
    render(
      <Tooltip.Provider>
        <ServiceTable services={[{ ...base, kind: "service", state }]} />
      </Tooltip.Provider>,
    );
    expect(within(screen.getByRole("table")).getByText("degraded").className).toContain("text-unknown");
  });

  it("shows the characters in a finding that hide or reorder text by their code point", () => {
    // A finding may quote what another server sent, such as a certificate's name.
    show({ ...base, findings: ["The certificate names ‮lpmaxe.liam"] });
    expect(screen.getByText("The certificate names [U+202E]lpmaxe.liam")).toBeTruthy();
  });

  it("renders values as text, never as markup", () => {
    show({ ...base, fields: [{ label: "Name", value: "<img src=x onerror=alert(1)>", format: "text" }] });
    expect(screen.getByText("<img src=x onerror=alert(1)>")).toBeTruthy();
    expect(document.querySelector("img")).toBeNull();
  });
});
