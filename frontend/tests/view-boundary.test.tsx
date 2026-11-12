import { render, screen } from "@testing-library/react";

import { ViewBoundary } from "../src/components/ViewBoundary";

function Broken(): never {
  throw new Error("a bug in a view");
}

describe("a failing view", () => {
  it("shows a notice instead of a blank page", () => {
    // React reports the caught error; the test expects it.
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    render(
      <ViewBoundary>
        <Broken />
      </ViewBoundary>,
    );
    expect(screen.getByRole("alert").textContent).toBe("This page could not be shown. Reload the page; the other pages may still work.");
  });

  it("shows a working view as it is", () => {
    render(<ViewBoundary>fine</ViewBoundary>);
    expect(screen.getByText("fine")).toBeTruthy();
  });
});
