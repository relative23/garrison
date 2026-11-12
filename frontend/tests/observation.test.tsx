import * as Tooltip from "@radix-ui/react-tooltip";
import { fireEvent, render, screen } from "@testing-library/react";

import type { Observation } from "../src/api/client";
import { ObservationCard } from "../src/components/ObservationCard";

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
    fireEvent.click(screen.getByRole("button", { name: "Show all 12 rows" }));
    expect(screen.getAllByRole("row")).toHaveLength(13);
    expect(screen.getByText("11.0 KiB")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Show all/ })).toBeNull();
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

  it("renders values as text, never as markup", () => {
    show({ ...base, fields: [{ label: "Name", value: "<img src=x onerror=alert(1)>", format: "text" }] });
    expect(screen.getByText("<img src=x onerror=alert(1)>")).toBeTruthy();
    expect(document.querySelector("img")).toBeNull();
  });
});
