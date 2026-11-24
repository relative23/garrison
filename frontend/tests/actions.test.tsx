import { act, fireEvent, screen, within } from "@testing-library/react";

import { configure, type Job } from "../src/api/client";
import { Actions } from "../src/modules/Actions";
import { action, catalog, job } from "./support/fixtures";
import { renderView } from "./support/render";
import { serve } from "./support/server";

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const JOB = `actions/jobs/${job().id}`;

const loaded = () => screen.findByRole("button", { name: "Run…" });

/** Open the action's dialog and type `phrase`; returns the Start button. */
function confirmWith(phrase: string): HTMLButtonElement {
  fireEvent.click(screen.getByRole("button", { name: "Run…" }));
  fireEvent.change(screen.getByLabelText(/to confirm/), { target: { value: phrase } });
  return screen.getByRole<HTMLButtonElement>("button", { name: "Start" });
}

const dialogOpen = () => document.querySelector("dialog")?.hasAttribute("open");

beforeEach(() => configure({ csrf: "csrf-token", onUnauthorized: () => undefined, onRefused: () => undefined }));

describe("maintenance actions", () => {
  it("start only after the exact confirmation phrase", async () => {
    const server = serve({
      "GET actions": { body: catalog() },
      "POST actions": { status: 202, body: { job: job(), replayed: false } },
    });
    renderView(<Actions />);
    await loaded();
    // Start cannot act yet, and stays where the keyboard is: a disabled
    // button would drop the focus it holds.
    const early = confirmWith("run health checks");
    expect(early.disabled).toBe(false);
    expect(early.getAttribute("aria-disabled")).toBe("true");
    fireEvent.click(early);
    fireEvent.submit(early.closest("form") as HTMLFormElement);
    await act(async () => undefined);
    expect(server.requests("POST actions")).toHaveLength(0);
    const start = confirmWith("RUN HEALTH CHECKS");
    expect(start.hasAttribute("aria-disabled")).toBe(false);
    fireEvent.click(start);
    expect(await screen.findByText("Job 01234567: Queued — Waiting to start")).toBeTruthy();
    const [sent] = server.requests("POST actions");
    expect(sent?.body).toEqual({ action: "run_monitor", requestId: expect.stringMatching(UUID_V4), confirmation: "RUN HEALTH CHECKS" });
    expect(sent?.headers.get("x-csrf-token")).toBe("csrf-token");
    expect(dialogOpen()).toBe(false);
  });

  it("replay the same request after a failed attempt, and only then", async () => {
    let fail = true;
    const server = serve({
      "GET actions": { body: catalog() },
      "POST actions": () => {
        if (fail) throw new TypeError("Failed to fetch");
        return { status: 202, body: { job: job(), replayed: false } };
      },
    });
    renderView(<Actions />);
    await loaded();
    fireEvent.click(confirmWith("RUN HEALTH CHECKS"));
    // The request may have reached the broker, which started the job.
    expect(
      await screen.findByText(
        "No readable answer came, so it is not known whether the job started. Start sends the same request again, which does not start a job twice.",
      ),
    ).toBeTruthy();
    expect(screen.queryByText(/could not be sent/)).toBeNull();
    expect(dialogOpen()).toBe(true);
    fail = false;
    fireEvent.click(screen.getByRole("button", { name: "Start" }));
    await screen.findByText(/^Job 01234567/);
    fireEvent.click(confirmWith("RUN HEALTH CHECKS"));
    await act(async () => undefined);
    const ids = server.requests("POST actions").map((call) => (call.body as { requestId: string }).requestId);
    expect(ids).toHaveLength(3);
    expect(ids[1]).toBe(ids[0]);
    expect(ids[2]).not.toBe(ids[0]);
  });

  it("say so when the broker finds that an earlier request started the job", async () => {
    serve({
      "GET actions": { body: catalog() },
      "POST actions": { status: 202, body: { job: job(), replayed: true } },
    });
    renderView(<Actions />);
    await loaded();
    fireEvent.click(confirmWith("RUN HEALTH CHECKS"));
    const notice = (await screen.findByText("Job 01234567: Queued — Waiting to start")).closest("[role]");
    expect(notice?.textContent).toContain("An earlier request had started this job; it was not started again.");
  });

  it("start once while a start is under way, and keep Start focusable meanwhile", async () => {
    let answer: (reply: { status: number; body: unknown }) => void = () => undefined;
    const server = serve({
      "GET actions": { body: catalog() },
      "POST actions": () => new Promise((resolve) => (answer = resolve)),
    });
    renderView(<Actions />);
    await loaded();
    const start = confirmWith("RUN HEALTH CHECKS");
    fireEvent.click(start);
    await screen.findByRole("button", { name: "Starting…" });
    // A disabled button would drop the focus; this one says it is busy instead.
    expect(start.disabled).toBe(false);
    expect(start.getAttribute("aria-disabled")).toBe("true");
    fireEvent.click(start);
    await act(async () => undefined);
    expect(server.requests("POST actions")).toHaveLength(1);
    await act(async () => answer({ status: 202, body: { job: job(), replayed: false } }));
    expect(await screen.findByText(/^Job 01234567/)).toBeTruthy();
  });

  it("show the server's refusal in the dialog", async () => {
    serve({
      "GET actions": { body: catalog() },
      "POST actions": { status: 409, body: { detail: "Allow the previous operation to settle first" } },
    });
    renderView(<Actions />);
    await loaded();
    fireEvent.click(confirmWith("RUN HEALTH CHECKS"));
    expect(await screen.findByText("Allow the previous operation to settle first")).toBeTruthy();
    expect(dialogOpen()).toBe(true);
  });

  it("close without sending on Cancel", async () => {
    const server = serve({ "GET actions": { body: catalog() } });
    renderView(<Actions />);
    await loaded();
    confirmWith("RUN HEALTH CHECKS");
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(dialogOpen()).toBe(false);
    expect(server.requests("POST actions")).toHaveLength(0);
  });

  it("follow a started job until it reaches a final state", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval"] });
    const server = serve({
      "GET actions": { body: catalog() },
      "POST actions": { status: 202, body: { job: job(), replayed: false } },
      [`GET ${JOB}`]: { body: job({ status: "running", message: "Started" }) },
    });
    renderView(<Actions />);
    await act(() => vi.advanceTimersByTimeAsync(0));
    fireEvent.click(confirmWith("RUN HEALTH CHECKS"));
    await act(() => vi.advanceTimersByTimeAsync(0));
    expect(screen.getByText("Job 01234567: Queued — Waiting to start")).toBeTruthy();
    await act(() => vi.advanceTimersByTimeAsync(3000));
    expect(screen.getByText("Job 01234567: Running — Started")).toBeTruthy();
    server.answer(`GET ${JOB}`, { body: job({ status: "failed", message: "Unit failed" }) });
    await act(() => vi.advanceTimersByTimeAsync(3000));
    expect(screen.getByText("Job 01234567: Failed — Unit failed")).toBeTruthy();
    await act(() => vi.advanceTimersByTimeAsync(30_000));
    expect(server.requests(`GET ${JOB}`)).toHaveLength(2);
  });

  it.each([
    ["succeeded", "Succeeded — Done.", "bg-card"],
    ["uncertain", "Result uncertain — The result could not be confirmed. Consult the host journal.", "bg-warning-background"],
    ["failed", "Failed — Unit failed", "bg-failed-background"],
  ] as const)("announce a job that ended %s in the tone of its result", async (result, said, tone) => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval"] });
    const message = said.split(" — ")[1] ?? "";
    serve({
      "GET actions": { body: catalog() },
      "POST actions": { status: 202, body: { job: job(), replayed: false } },
      [`GET ${JOB}`]: { body: job({ status: result, message }) },
    });
    renderView(<Actions />);
    await act(() => vi.advanceTimersByTimeAsync(0));
    fireEvent.click(confirmWith("RUN HEALTH CHECKS"));
    await act(() => vi.advanceTimersByTimeAsync(0));
    expect(screen.getByText("Job 01234567: Queued — Waiting to start")).toBeTruthy();
    await act(() => vi.advanceTimersByTimeAsync(3000));
    const notice = screen.getByText(`Job 01234567: ${said}`).closest("[role]");
    // A result that is not known is no success: it is a warning, as its row says.
    expect(notice?.getAttribute("role")).toBe(result === "failed" ? "alert" : "status");
    expect(notice?.className).toContain(tone);
  });

  it("keep following a job whose status could not be read once, and say so meanwhile", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval"] });
    const server = serve({
      "GET actions": { body: catalog() },
      "POST actions": { status: 202, body: { job: job(), replayed: false } },
      [`GET ${JOB}`]: { status: 503, body: { detail: "Authorization is temporarily unavailable" } },
    });
    renderView(<Actions />);
    await act(() => vi.advanceTimersByTimeAsync(0));
    fireEvent.click(confirmWith("RUN HEALTH CHECKS"));
    await act(() => vi.advanceTimersByTimeAsync(0));
    // The first look at the job fails: the page says so and looks again.
    await act(() => vi.advanceTimersByTimeAsync(3000));
    expect(server.requests(`GET ${JOB}`)).toHaveLength(1);
    const notice = screen.getByText(/The status of job 01234567 could not be read/).closest("[role]");
    expect(notice?.textContent).toContain("Authorization is temporarily unavailable");
    expect(screen.getByText("Job 01234567: Queued — Waiting to start")).toBeTruthy();
    // A second failure, then the broker is back: each time later than before.
    await act(() => vi.advanceTimersByTimeAsync(6000));
    expect(server.requests(`GET ${JOB}`)).toHaveLength(2);
    server.answer(`GET ${JOB}`, { body: job({ status: "succeeded", message: "Done." }) });
    await act(() => vi.advanceTimersByTimeAsync(12_000));
    expect(server.requests(`GET ${JOB}`)).toHaveLength(3);
    expect(screen.getByText("Job 01234567: Succeeded — Done.")).toBeTruthy();
    expect(screen.queryByText(/could not be read/)).toBeNull();
  });

  it("keep the dialog and the list when a refresh in the background fails", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval"] });
    vi.spyOn(document, "visibilityState", "get").mockReturnValue("visible");
    const server = serve({ "GET actions": { body: catalog() } });
    renderView(<Actions />);
    await act(() => vi.advanceTimersByTimeAsync(0));
    confirmWith("RUN HEALTH");
    expect(dialogOpen()).toBe(true);
    // The list is read again every 15 seconds; this time the broker is away.
    server.answer("GET actions", { status: 503, body: { detail: "Authorization is temporarily unavailable" } });
    await act(() => vi.advanceTimersByTimeAsync(15_000));
    expect(dialogOpen()).toBe(true);
    expect(screen.getByLabelText<HTMLInputElement>(/to confirm/).value).toBe("RUN HEALTH");
    const notice = screen.getByText(/This page could not be refreshed/).closest("[role]");
    expect(notice?.textContent).toContain("Authorization is temporarily unavailable");
    // The next refresh works, and the notice goes.
    server.answer("GET actions", { body: catalog() });
    await act(() => vi.advanceTimersByTimeAsync(15_000));
    expect(screen.queryByText(/This page could not be refreshed/)).toBeNull();
    expect(dialogOpen()).toBe(true);
  });

  it("say that a proxy turned the start away, by its status alone", async () => {
    // What a proxy refuses never reached Garrison; its 502 is no answer at
    // all (tests/failures.test.tsx). Over HTTP/2 an answer has no status text.
    serve({
      "GET actions": { body: catalog() },
      "POST actions": { status: 413, raw: "<html>Request Entity Too Large</html>", statusText: "" },
    });
    renderView(<Actions />);
    await loaded();
    fireEvent.click(confirmWith("RUN HEALTH CHECKS"));
    const notice = (await screen.findByText("The job was not started.")).closest("[role]");
    expect(notice?.textContent).toContain("answered with status 413 instead of Garrison.");
    expect(notice?.textContent).not.toContain("Request Entity Too Large");
    expect(dialogOpen()).toBe(true);
  });

  it("list recent jobs with their action and result", async () => {
    const retired = job({
      id: "f".repeat(32),
      actionId: "retired_action",
      actorEmail: "",
      status: "mystery" as Job["status"],
      message: "Old",
    });
    serve({ "GET actions": { body: catalog({ jobs: [job({ status: "uncertain", message: "No answer" }), retired] }) } });
    renderView(<Actions />);
    const rows = await screen.findAllByRole("row");
    expect(within(rows[1] as HTMLElement).getByText("Run health checks")).toBeTruthy();
    expect(within(rows[1] as HTMLElement).getByText("Result uncertain")).toBeTruthy();
    expect(within(rows[1] as HTMLElement).getByText("admin@example.test")).toBeTruthy();
    expect(within(rows[2] as HTMLElement).getByText("42")).toBeTruthy();
    expect(within(rows[2] as HTMLElement).getByText("retired_action")).toBeTruthy();
    expect(within(rows[2] as HTMLElement).getByText("mystery")).toBeTruthy();
  });

  it("say when the profile grants none", async () => {
    serve({ "GET actions": { body: catalog({ actions: [], jobs: [] }) } });
    renderView(<Actions />);
    expect(await screen.findByText("Your profile grants no maintenance actions.")).toBeTruthy();
    expect(screen.getByText("No jobs in the retained audit.")).toBeTruthy();
  });

  it("offer a retry when the catalog cannot be loaded", async () => {
    const server = serve({ "GET actions": { status: 503, body: { detail: "The broker is not running" } } });
    renderView(<Actions />);
    const retry = await screen.findByRole("button", { name: "Try again" });
    server.answer("GET actions", { body: catalog({ actions: [action({ title: "Back up now" })] }) });
    fireEvent.click(retry);
    expect(await screen.findAllByText("Back up now")).not.toHaveLength(0);
  });
});
