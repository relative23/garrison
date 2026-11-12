import { fireEvent, screen, within } from "@testing-library/react";

import { Sessions } from "../src/modules/Sessions";
import { coverage, smtpSession } from "./support/fixtures";
import { renderView } from "./support/render";
import { serve } from "./support/server";

const SPAN = smtpSession().spanId;

describe("SMTP sessions", () => {
  it("list the client, route, checks and rejections", async () => {
    const refused = smtpSession({
      spanId: "1111222233334444",
      to: [],
      authentication: { "spf-from": "fail", "x-new-check": "pass" },
      rejections: ["rcpt"],
    });
    const quiet = smtpSession({ spanId: "5555666677778888", authentication: {}, remoteIp: null });
    serve({ "GET coverage": { body: coverage() }, "GET sessions": { body: { items: [smtpSession(), refused, quiet], next: null } } });
    renderView(<Sessions moduleId="sessions" detail={null} />);
    const [, first, second, third] = await screen.findAllByRole("row");
    const row = within(first as HTMLElement);
    expect(row.getByText("192.0.2.10")).toBeTruthy();
    expect(row.getByText("carol@example.net → bob@example.test")).toBeTruthy();
    expect(row.getByRole("link").getAttribute("href")).toBe(`/admin/sessions/${SPAN}`);
    const other = within(second as HTMLElement);
    expect(other.getByText("carol@example.net → none")).toBeTruthy();
    expect(other.getByText("SPF fail")).toBeTruthy();
    // A check this build does not know is shown as the server named it.
    expect(other.getByText("x-new-check pass")).toBeTruthy();
    expect(other.getByText("rcpt")).toBeTruthy();
    expect(within(third as HTMLElement).getByText("None recorded")).toBeTruthy();
    expect(within(third as HTMLElement).getByText("Unknown")).toBeTruthy();
  });

  it("search from the newest session", async () => {
    const server = serve({ "GET coverage": { body: coverage() }, "GET sessions": { body: { items: [], next: null } } });
    renderView(<Sessions moduleId="sessions" detail={null} />);
    expect(await screen.findByText("No recorded sessions match.")).toBeTruthy();
    fireEvent.change(screen.getByRole("searchbox"), { target: { value: "192.0.2.10" } });
    fireEvent.submit(screen.getByRole("search"));
    await screen.findByText("No recorded sessions match.");
    expect(server.requests("GET sessions").map((call) => call.query.toString())).toEqual(["limit=25", "search=192.0.2.10&limit=25"]);
  });

  it("show one session with its queued messages", async () => {
    const summary = smtpSession({ complete: false, queueIds: ["1a2b3c4d5e6f7a8b"], lastSeen: smtpSession().firstSeen + 90 });
    serve({ [`GET sessions/${SPAN}`]: { body: { summary, events: [], truncated: false } } });
    renderView(<Sessions moduleId="sessions" detail={SPAN} />);
    expect(await screen.findByText("SMTP session from 192.0.2.10")).toBeTruthy();
    expect(screen.getByText("Incomplete")).toBeTruthy();
    expect(screen.getByText("2 min")).toBeTruthy();
    expect(screen.getByText("Recorded events").nextElementSibling?.textContent).toBe("6");
    expect(screen.getByRole("link", { name: "1a2b3c4d5e6f7a8b" }).getAttribute("href")).toBe("/admin/deliveries/1a2b3c4d5e6f7a8b");
    expect(screen.queryByText("Only the first events of this session are shown.")).toBeNull();
  });

  it("say when no recipient was accepted", async () => {
    const summary = smtpSession({ to: [], rejections: [] });
    serve({ [`GET sessions/${SPAN}`]: { body: { summary, events: [], truncated: true } } });
    renderView(<Sessions moduleId="sessions" detail={SPAN} />);
    expect(await screen.findByText("None accepted")).toBeTruthy();
    expect(screen.getByText("None")).toBeTruthy();
    expect(screen.getByText("Only the first events of this session are shown.")).toBeTruthy();
    expect(screen.queryByText("Incomplete")).toBeNull();
  });
});
