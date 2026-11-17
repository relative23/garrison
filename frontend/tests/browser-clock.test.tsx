// No age, end or staleness on a page comes from the browser's own clock where
// the server knows it: a browser's clock may run hours ahead of the host's or
// behind it. So every page reads the same, whatever the browser's clock says.
// The pages are those the build draws (src/prerender.tsx), every module's and
// both sections'; eslint.config.js keeps the clocks to src/lib/clock.ts.
import { act, screen } from "@testing-library/react";

import { pages } from "../src/prerender";
import {
  attacks,
  catalog,
  coverage,
  delivery,
  destinations,
  event,
  job,
  metrics,
  NOW,
  observation,
  session,
  smtpSession,
  status,
} from "./support/fixtures";
import { openApp } from "./support/render";
import { serve, type FakeServer } from "./support/server";

const HOUR = 3600_000;

/** A check of each module that shows checks, asked a few minutes before the answer. */
const CHECKS = ["services", "antivirus", "spam", "attacks", "backups", "alerts", "dns_tls"].map((module, index) => {
  const age = 125 + index;
  return observation({
    id: `${module}.check`,
    title: `A check of ${module}`,
    modules: [module],
    checkedAt: new Date((NOW - age) * 1000).toISOString(),
    age,
  });
});

/** What the server answers, each with the times its pages show. */
function answers() {
  const list = <T,>(items: T[]) => ({ body: { items, next: null } });
  const mailboxes = observation({ id: "stalwart.mailboxes", title: "Mailbox storage", modules: ["dashboard"], age: 30 });
  return {
    "GET session": { body: { session: session({ actions: ["run_monitor"] }) } },
    "GET status": { body: status([...CHECKS, mailboxes]) },
    "GET metrics": { body: metrics() },
    "GET coverage": { body: coverage({ lastBatchAt: NOW - 600, lastBatchAge: 600, heartbeatAt: NOW - 5 }) },
    "GET events": list([event()]),
    "GET deliveries": list([delivery()]),
    "GET sessions": list([smtpSession()]),
    "GET attacks": { body: attacks() },
    "GET destinations": { body: destinations() },
    "GET actions": { body: catalog({ jobs: [job({ status: "succeeded", message: "Done." })] }) },
  };
}

/** Until the page asks for nothing more and shows nothing that still loads. */
async function settled(server: FakeServer) {
  for (let asked = -1, quiet = 0; quiet < 3;) {
    await act(() => new Promise((resolve) => setTimeout(resolve, 20)));
    const loading = screen.queryAllByText(/Loading/).length > 0;
    quiet = server.calls.length === asked && !loading ? quiet + 1 : 0;
    asked = server.calls.length;
  }
}

describe("the browser's own clock", () => {
  it.each(pages)("changes nothing on the %s page, hours ahead of the server's or behind it", async (page) => {
    const shown: string[] = [];
    for (const skew of [0, 3 * HOUR, -3 * HOUR]) {
      vi.useFakeTimers({ toFake: ["Date"] });
      vi.setSystemTime(NOW * 1000 + skew);
      const server = serve(answers());
      const view = openApp(`/admin/${page}`);
      await settled(server);
      shown.push(document.body.textContent ?? "");
      view.unmount();
      vi.useRealTimers();
    }
    expect(shown[1]).toBe(shown[0]);
    expect(shown[2]).toBe(shown[0]);
  });
});
