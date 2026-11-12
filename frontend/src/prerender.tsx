// Draws what each page shows before the session is known, for prerender.mjs to
// write into that page's HTML: the frame of every module and section page, and
// the sign-in page. It runs in Node at build time, never in the browser.
import { renderToStaticMarkup } from "react-dom/server";

import "./i18n";
import { Shell } from "./components/Shell";
import { AccountCard } from "./modules/Account";
import { Actions } from "./modules/Actions";
import { PreferencesHead } from "./modules/Preferences";

/** The top of views that needs no data, drawn into their pages: there it shows
 * with the first paint, and it holds each page's largest text. */
const HEADS: Record<string, () => React.ReactElement> = {
  actions: () => <Actions />,
  account: () => <AccountCard session={null} />,
  preferences: () => <PreferencesHead />,
};

/** What each page needs first besides the session: the module of its view and
 * the requests the view makes when it opens. The drawn page starts both with
 * the page; tests/prerender.test.tsx compares them with what the views ask. */
export const FIRST: Record<string, { module: string; requests: string[] }> = {
  dashboard: { module: "Dashboard", requests: ["status", "metrics?period=24h"] },
  services: { module: "StatusPage", requests: ["status"] },
  antivirus: { module: "StatusPage", requests: ["status"] },
  spam: { module: "StatusPage", requests: ["status"] },
  attacks: { module: "Attacks", requests: ["status", "coverage", "attacks?period=24h"] },
  deliveries: { module: "Deliveries", requests: ["status", "coverage", "deliveries?limit=25"] },
  sessions: { module: "Sessions", requests: ["status", "coverage", "sessions?limit=25"] },
  logs: { module: "Logs", requests: ["status", "coverage", "events?limit=50"] },
  backups: { module: "StatusPage", requests: ["status"] },
  alerts: { module: "StatusPage", requests: ["status"] },
  dns_tls: { module: "StatusPage", requests: ["status"] },
  actions: { module: "Actions", requests: ["status", "actions"] },
  preferences: { module: "Preferences", requests: ["status"] },
  account: { module: "Account", requests: ["status"] },
};

export const pages = Object.keys(FIRST);

function draw(element: React.ReactElement): string {
  return renderToStaticMarkup(element);
}

export function frame(view: string): string {
  return draw(<Shell kind="frame" view={view} head={HEADS[view]?.()} />);
}

export function signIn(): string {
  return draw(<Shell kind="sign-in" view="" />);
}
