import { fireEvent, render, screen, within } from "@testing-library/react";

import { PageSearch } from "../src/components/PageSearch";
import { session } from "./support/fixtures";

const dialog = () => screen.getByRole("dialog", { hidden: true });
const pages = () =>
  within(dialog())
    .queryAllByRole("button", { hidden: true })
    .map((button) => button.querySelector("span span")?.textContent);

function show() {
  render(<PageSearch modules={session({}, ["dashboard", "spam", "logs"]).modules} />);
}

describe("page search", () => {
  it("opens with Ctrl+K and lists the pages the user may open", () => {
    show();
    fireEvent.keyDown(window, { key: "k", ctrlKey: true });
    expect(dialog().hasAttribute("open")).toBe(true);
    expect(pages()).toEqual(["Dashboard", "Spam filter", "Event history", "Settings", "Account"]);
  });

  it("ignores K without Ctrl or Cmd", () => {
    show();
    fireEvent.keyDown(window, { key: "k" });
    expect(dialog().hasAttribute("open")).toBe(false);
  });

  it("filters by name and description and opens the first match on Enter", () => {
    show();
    fireEvent.click(screen.getByRole("button", { name: /Search pages/ }));
    fireEvent.change(within(dialog()).getByRole("textbox", { hidden: true }), { target: { value: " SPAM " } });
    expect(pages()).toEqual(["Spam filter"]);
    fireEvent.submit(within(dialog()).getByRole("textbox", { hidden: true }));
    expect(location.pathname).toBe("/admin/spam");
    expect(dialog().hasAttribute("open")).toBe(false);
  });

  it("opens a page by click", () => {
    show();
    fireEvent.keyDown(window, { key: "K", metaKey: true });
    fireEvent.click(within(dialog()).getByRole("button", { name: /^Settings/, hidden: true }));
    expect(location.pathname).toBe("/admin/preferences");
  });

  it("closes on a press beside it, not on one inside it", () => {
    show();
    fireEvent.keyDown(window, { key: "k", ctrlKey: true });
    // jsdom lays nothing out; give the dialog a box to press inside and beside.
    dialog().getBoundingClientRect = () => ({ left: 100, top: 100, right: 400, bottom: 300 }) as DOMRect;
    fireEvent.pointerDown(within(dialog()).getByRole("textbox", { hidden: true }), { clientX: 200, clientY: 120 });
    fireEvent.pointerDown(dialog(), { clientX: 399, clientY: 299 });
    expect(dialog().hasAttribute("open")).toBe(true);
    fireEvent.pointerDown(dialog(), { clientX: 50, clientY: 200 });
    expect(dialog().hasAttribute("open")).toBe(false);
    expect(location.pathname).toBe("/admin/");
  });

  it("says when no page matches", () => {
    show();
    fireEvent.keyDown(window, { key: "k", ctrlKey: true });
    fireEvent.change(within(dialog()).getByRole("textbox", { hidden: true }), { target: { value: "nothing like this" } });
    expect(within(dialog()).getByText("No page matches.")).toBeTruthy();
    fireEvent.submit(within(dialog()).getByRole("textbox", { hidden: true }));
    expect(location.pathname).toBe("/admin/");
  });
});
