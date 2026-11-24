// Session bootstrap, theme and routing.
import { Suspense, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";

import { api, configure, type Preferences, type SessionInfo, type SessionState } from "./api/client";
import { ErrorState } from "./components/Failure";
import { Layout } from "./components/Layout";
import { Shell, type ShellKind } from "./components/Shell";
import { Centered, SignIn } from "./components/SignIn";
import { Loading } from "./components/Status";
import { ViewBoundary } from "./components/ViewBoundary";
import { useTranslation } from "./i18n";
import { elapsed, Instant, STEP, usePageTime } from "./lib/clock";
import { AppContext, type AppState } from "./lib/context";
import { redirect, useRoute } from "./lib/router";
import { useCurrentStatus } from "./lib/staleness";
import { announce, listen } from "./lib/tabs";
import { applyTheme, useSystemDark } from "./lib/theme";
import { after, delay } from "./lib/timers";
import { useResource } from "./lib/useResource";
import { ChunkView, isPage, moduleText, PAGE_VIEWS, PAGES, VIEWS } from "./modules/registry";

/** The least time between two reads of the session, in seconds, whatever
 * asks for them. */
const SESSION_FLOOR = 1;

/** A signed-in page's session as it was read, and how that read stands. */
interface Reads {
  current: SessionInfo;
  /** When `current` arrived, on the page's clock. */
  receivedAt: Instant | null;
  /** Whether `current` answers the read asked last, not one asked before it. */
  latest: boolean;
  /** Whether the read asked last failed; `current` is then the one before. */
  failed: boolean;
  /** Ask the server for the session again. */
  again: () => void;
}

/** Preferences this tab saved, and whether the read of the session that
 * follows the save is on its way. */
interface Saved {
  preferences: Preferences;
  asked: boolean;
}

function SignedIn({ reads, onEnded }: { reads: Reads; onEnded: (csrf: string) => void }) {
  const { t } = useTranslation();
  const { current, latest, failed, again } = reads;
  const route = useRoute();
  const status = useCurrentStatus(useResource((signal) => api.status(signal), [], 60));
  const system = useSystemDark();

  // What this tab saved shows at once and stands until a read of the session
  // asked after the save has answered: a read asked before it may still
  // arrive, and would bring back what the save replaced.
  const [saved, setSaved] = useState<Saved | null>(null);
  if (saved && !saved.asked && !latest) setSaved({ ...saved, asked: true });
  if (saved?.asked && latest && !failed) setSaved(null);
  const session = useMemo(() => (saved ? { ...current, preferences: saved.preferences } : current), [current, saved]);

  // Again when the system changes its own, which "system" follows.
  useEffect(() => applyTheme(session.preferences.theme, system), [session.preferences.theme, system]);
  // The server ends the session by its own clock: the page counts down the
  // time left it gave and then asks; the answer says whether it has ended.
  const now = usePageTime();
  const { receivedAt } = reads;
  const asked = useRef<Instant | null>(null);
  useEffect(() => {
    // Without a time left that a timer can count, the read after each refresh
    // of the status finds the end.
    const given = delay(typeof session.expiresIn === "number" ? session.expiresIn * 1000 : null);
    if (given === null || !receivedAt) return undefined;
    const left = given - elapsed(receivedAt);
    if (left > STEP) return undefined;
    // At most once a step, so that no answer makes it ask again and again.
    const since = (moment: Instant | null) => (moment ? elapsed(moment) : Number.POSITIVE_INFINITY);
    return after(Math.max(0, left, STEP - since(receivedAt), STEP - since(asked.current)), () => {
      asked.current = new Instant();
      again();
    });
  }, [receivedAt, session.expiresIn, again, now]);

  // Each refresh of the status had the user's rights checked a moment ago.
  // The session read right after it is answered from that same check, which
  // the web service keeps for five seconds, and asks the broker nothing
  // more: so a change of rights reaches the menu with the next refresh.
  const refreshed = status.receivedAt;
  const answered = useRef(refreshed);
  useEffect(() => {
    if (refreshed === null || refreshed === answered.current) return;
    // The first answer came with the session that was just read.
    if (answered.current !== null) again();
    answered.current = refreshed;
  }, [refreshed, again]);

  const [saving, setSaving] = useState(false);
  const updatePreferences = useCallback(
    async (preferences: Preferences) => {
      setSaving(true);
      try {
        const stored = await api.savePreferences(preferences);
        setSaved({ preferences: stored, asked: false });
        again();
        // The other tabs read the session again and take the change.
        announce();
      } finally {
        setSaving(false);
      }
    },
    [again],
  );
  const state: AppState = useMemo(() => ({ session, status, saving, updatePreferences }), [session, status, saving, updatePreferences]);

  const granted = session.modules.find((module) => module.id === route.view);
  useEffect(() => {
    // An unknown or ungranted view falls back to the first granted module.
    if (!granted && !isPage(route.view) && session.modules[0]) redirect(session.modules[0].id);
  }, [granted, route.view, session.modules]);

  // The page that says so appears only after the server ended the session:
  // when the request fails, the browser is still signed in. The other tabs
  // say so at once.
  const logout = async () => {
    await api.logout();
    announce();
    onEnded(session.csrf);
  };

  const view = granted ? VIEWS[granted.id] : undefined;
  const page = isPage(route.view) ? t(PAGES[route.view]) : null;
  let content;
  if (route.view === "preferences") content = <ChunkView chunk={PAGE_VIEWS.preferences} props={{}} />;
  else if (route.view === "account") content = <ChunkView chunk={PAGE_VIEWS.account} props={{ onLogout: logout }} />;
  else if (view && granted)
    content = <ChunkView key={granted.id} chunk={view.chunk} props={{ moduleId: granted.id, detail: route.detail }} />;
  else content = <Loading />;
  return (
    <AppContext.Provider value={state}>
      <Layout
        current={route.view}
        section={page ? route.view : ""}
        title={page ?? (granted ? moduleText(granted, "label") : "")}
        intro={page || !granted ? "" : moduleText(granted, "intro")}
      >
        <ViewBoundary key={`${route.view}/${route.detail ?? ""}`}>
          <Suspense fallback={<Loading />}>{content}</Suspense>
        </ViewBoundary>
      </Layout>
    </AppContext.Provider>
  );
}

/** `shell` names what the server drew into the page (see Shell); the app
 * shows the same until the session is known. `initial` is the session when
 * the page already has it (src/start.ts). */
export function App({ shell, initial }: { shell?: ShellKind; initial?: SessionState }) {
  const { t } = useTranslation();
  const route = useRoute();
  const session = useResource((signal) => api.session(signal), [], 0, initial, SESSION_FLOOR);
  const again = session.reload;
  const signedIn = session.data?.session ?? null;
  // The session that ended in this tab, by its CSRF token, and whether this
  // tab has shown a session at all.
  const [ended, setEnded] = useState<string | null>(null);
  const current = signedIn && signedIn.csrf !== ended ? signedIn : null;
  const [hadSession, setHadSession] = useState(current !== null);
  if (current && !hadSession) setHadSession(true);

  // A session ends here when the server answers 401, or 403 to the session's
  // own question, and at a sign-out; at the end of its time the server's
  // answer says so (SignedIn). The session is read again then, once for each
  // session: another tab may have signed in since, which this one then
  // takes, and a session the server keeps refusing is not asked again.
  const asked = useRef<string | null>(null);
  const end = useCallback(
    (csrf: string) => {
      setEnded(csrf);
      if (asked.current === csrf) return;
      asked.current = csrf;
      again();
    },
    [again],
  );

  // Before the views' first requests, which run as effects after this one. A
  // refused request reads the session again.
  useLayoutEffect(() => {
    if (current) configure({ csrf: current.csrf, onUnauthorized: () => end(current.csrf), onRefused: again });
  }, [current, end, again]);

  // The browser's cookie is the same in every tab: a sign-in or sign-out in
  // another one changes the session this tab works with, its token and maybe
  // its account. The session is read again whenever this tab is shown, and
  // whenever another tab says that it signed in or out or saved its settings.
  useEffect(() => {
    const shown = () => {
      if (document.visibilityState === "visible") again();
    };
    document.addEventListener("visibilitychange", shown);
    return () => document.removeEventListener("visibilitychange", shown);
  }, [again]);
  useEffect(() => listen(again), [again]);
  // A page that starts with a session says so: another tab may be the one
  // that says the session has ended.
  const told = useRef(false);
  useEffect(() => {
    if (!current || told.current) return;
    told.current = true;
    announce();
  }, [current]);

  // Without a session the page follows the system, as the server sent it.
  // While the session is on its way the page keeps the theme the server sent
  // it in, the one its user chose (routes/files.rs), and so does a page whose
  // session has ended.
  const system = useSystemDark();
  const signedOut = session.data !== null && !current && !hadSession;
  useEffect(() => {
    if (signedOut) applyTheme("system", system);
  }, [signedOut, system]);

  let content;
  // Another session, with its own token, gets a page of its own; the same
  // session read again keeps the page and takes what changed in it.
  if (current) {
    const reads = { current, receivedAt: session.receivedAt, latest: !session.loading, failed: session.error !== null, again };
    content = <SignedIn key={current.csrf} reads={reads} onEnded={end} />;
  }
  // The session this tab showed has ended, here or in another tab.
  else if (hadSession) content = <SignIn expired />;
  // A session read again that fails leaves the page as it is.
  else if (session.error && !session.data)
    content = (
      <Centered>
        <ErrorState error={session.error} retry={session.reload} />
      </Centered>
    );
  else if (!session.data)
    content = shell ? (
      <Shell kind={shell} view={route.view} />
    ) : (
      <Centered>
        <Loading label={t("app.loading")} />
      </Centered>
    );
  else content = <SignIn />;
  return content;
}
