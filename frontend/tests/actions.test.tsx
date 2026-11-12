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

beforeEach(() => configure({ csrf: "csrf-token", onUnauthorized: () => undefined }));

describe("maintenance actions", () => {
  it("start only after the exact confirmation phrase", async () => {
    const server = serve({
      "GET actions": { body: catalog() },
      "POST actions": { status: 202, body: { job: job(), replayed: false } },
    });
    renderView(<Actions />);
    await loaded();
    expect(confirmWith("run health checks").disabled).toBe(true);
    const start = confirmWith("RUN HEALTH CHECKS");
    expect(start.disabled).toBe(false);
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
    expect(await screen.findByText("The request could not be sent.")).toBeTruthy();
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
