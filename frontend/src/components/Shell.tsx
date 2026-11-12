// What a page shows before the session is known. The build draws it into each
// page's HTML (src/prerender.tsx) and the app shows the same until the session
// arrives, so the first paint needs no script and the change is not seen.
import type { ReactNode } from "react";

import { pageText } from "../modules/registry";
import { Layout } from "./Layout";
import { SignIn } from "./SignIn";
import { Loading } from "./Status";

export type ShellKind = "frame" | "sign-in";

/** `head` is the top of a view that needs no data, drawn in place of the
 * loading state; the view renders the same at the same place. */
export function Shell({ kind, view, head }: { kind: ShellKind; view: string; head?: ReactNode }) {
  if (kind === "sign-in") return <SignIn />;
  // The server answers the root with the dashboard's page, where it leads.
  const page = view || "dashboard";
  const { title, intro, section } = pageText(page);
  return (
    <Layout current={page} section={section} title={title} intro={intro}>
      {head ?? <Loading />}
    </Layout>
  );
}
