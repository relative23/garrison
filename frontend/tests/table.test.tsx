import { act, render } from "@testing-library/react";

import { Table, TableBody, TableCell, TableRow } from "../src/components/ui/table";

describe("tables", () => {
  it("take keyboard focus only while they scroll sideways", () => {
    const resized: Array<() => void> = [];
    const original = globalThis.ResizeObserver;
    globalThis.ResizeObserver = class {
      constructor(callback: ResizeObserverCallback) {
        resized.push(() => callback([], this));
      }
      observe() {}
      unobserve() {}
      disconnect() {}
    };
    try {
      const { container } = render(
        <Table>
          <TableBody>
            <TableRow>
              <TableCell>wide</TableCell>
            </TableRow>
          </TableBody>
        </Table>,
      );
      const frame = container.querySelector<HTMLElement>(".overflow-x-auto");
      if (!frame) throw new Error("no scrolling frame");
      const measure = (content: number) => {
        Object.defineProperty(frame, "scrollWidth", { configurable: true, value: content });
        Object.defineProperty(frame, "clientWidth", { configurable: true, value: 400 });
        act(() => resized.forEach((notify) => notify()));
      };
      measure(800);
      expect(frame.getAttribute("tabindex")).toBe("0");
      measure(400);
      expect(frame.hasAttribute("tabindex")).toBe(false);
    } finally {
      globalThis.ResizeObserver = original;
    }
  });
});
