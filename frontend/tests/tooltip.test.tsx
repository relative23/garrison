import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import { EvidenceLabel } from "../src/components/Status";

describe("tooltips", () => {
  it("show their trigger at once, and the explanation once their code has come", async () => {
    render(<EvidenceLabel kind="probe" />);
    const badge = () => screen.getByText("Probe");
    // The first render does not wait for the tooltip's code.
    expect(badge().getAttribute("data-state")).toBeNull();
    await waitFor(() => expect(badge().getAttribute("data-state")).toBe("closed"));
    fireEvent.focus(badge());
    expect((await screen.findByRole("tooltip")).textContent).toBe("The collector performed an active check, such as a TLS handshake.");
  });
});
