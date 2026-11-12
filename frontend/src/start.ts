// What a page with a drawn frame needs before React renders it once: the
// session and the code of its view. The HTML preloads both (prerender.mjs), so
// waiting for them costs no time, and the frame stays as drawn meanwhile.
import { api, type SessionState } from "./api/client";
import { parse } from "./lib/router";
import { preloadView } from "./modules/registry";

/** The session for the page at `pathname`, its view's code loaded. A failed
 * request leaves the session to the app, which asks again and says what failed. */
export async function prepare(pathname: string): Promise<SessionState | undefined> {
  const [session] = await Promise.allSettled([api.session(), preloadView(parse(pathname).view)]);
  return session.status === "fulfilled" ? session.value : undefined;
}
