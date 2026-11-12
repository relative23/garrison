import { act, fireEvent, render, screen } from "@testing-library/react";

import { useResource } from "../src/lib/useResource";

type Load = (filter: string, signal: AbortSignal) => Promise<string>;

function Probe({ filter, load, refresh = 0, initial }: { filter: string; load: Load; refresh?: number; initial?: string }) {
  const resource = useResource((signal) => load(filter, signal), [filter], refresh, initial);
  return (
    <>
      <output>
        {resource.loading ? "loading" : "settled"} / {resource.data ?? "no data"} / {resource.error?.message ?? "no error"}
      </output>
      <button onClick={resource.reload}>reload</button>
    </>
  );
}

/** A load whose answers the test gives, one per request. */
function controlled() {
  const requests: { filter: string; signal: AbortSignal; resolve: (value: string) => void; reject: (reason: unknown) => void }[] = [];
  const load: Load = (filter, signal) =>
    new Promise((resolve, reject) => {
      requests.push({ filter, signal, resolve, reject });
    });
  return { load, requests };
}

const shown = () => screen.getByRole("status").textContent;

describe("useResource", () => {
  it("never shows the answer of an older filter", async () => {
    const { load, requests } = controlled();
    const view = render(<Probe filter="a" load={load} />);
    view.rerender(<Probe filter="b" load={load} />);
    expect(requests[0]?.signal.aborted).toBe(true);
    await act(async () => requests[1]?.resolve("b-data"));
    await act(async () => requests[0]?.resolve("a-data"));
    expect(shown()).toBe("settled / b-data / no error");
  });

  it("shows no data of another filter while the new one loads", async () => {
    const { load, requests } = controlled();
    const view = render(<Probe filter="a" load={load} />);
    await act(async () => requests[0]?.resolve("a-data"));
    view.rerender(<Probe filter="b" load={load} />);
    expect(shown()).toBe("loading / no data / no error");
  });

  it("keeps the data visible when a reload fails", async () => {
    const { load, requests } = controlled();
    render(<Probe filter="a" load={load} />);
    await act(async () => requests[0]?.resolve("first"));
    fireEvent.click(screen.getByRole("button", { name: "reload" }));
    expect(shown()).toBe("loading / first / no error");
    await act(async () => requests[1]?.reject(new Error("offline")));
    expect(shown()).toBe("settled / first / offline");
  });

  it("turns a rejection that is not an Error into one", async () => {
    const { load, requests } = controlled();
    render(<Probe filter="a" load={load} />);
    await act(async () => requests[0]?.reject("refused"));
    expect(shown()).toBe("settled / no data / refused");
  });

  it("cancels the request of a view that is gone", () => {
    const { load, requests } = controlled();
    render(<Probe filter="a" load={load} />).unmount();
    expect(requests[0]?.signal.aborted).toBe(true);
  });

  it("refreshes on its interval only while the page is visible", async () => {
    vi.useFakeTimers();
    const visibility = vi.spyOn(document, "visibilityState", "get").mockReturnValue("visible");
    const { load, requests } = controlled();
    render(<Probe filter="a" load={load} refresh={60} />);
    await act(async () => vi.advanceTimersByTime(60_000));
    expect(requests).toHaveLength(2);
    visibility.mockReturnValue("hidden");
    await act(async () => vi.advanceTimersByTime(120_000));
    expect(requests).toHaveLength(2);
    visibility.mockReturnValue("visible");
    await act(async () => vi.advanceTimersByTime(60_000));
    expect(requests).toHaveLength(3);
  });

  it("shows an answer the page already has without asking, and asks again on reload", async () => {
    const { load, requests } = controlled();
    render(<Probe filter="a" load={load} initial="drawn" />);
    expect(shown()).toBe("settled / drawn / no error");
    expect(requests).toHaveLength(0);
    fireEvent.click(screen.getByRole("button", { name: "reload" }));
    expect(requests).toHaveLength(1);
    await act(async () => requests[0]?.resolve("fresh"));
    expect(shown()).toBe("settled / fresh / no error");
  });

  it("asks for a new filter even when it started with an answer", async () => {
    const { load, requests } = controlled();
    const view = render(<Probe filter="a" load={load} initial="drawn" />);
    view.rerender(<Probe filter="b" load={load} initial="drawn" />);
    expect(requests.map((request) => request.filter)).toEqual(["b"]);
    expect(shown()).toBe("loading / no data / no error");
  });
});
