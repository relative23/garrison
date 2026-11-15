// Session bootstrap, theme and routing.
import { Suspense, useCallback, useEffect, useLayoutEffect, useMemo, useState } from "react";

import { api, configure, type SessionInfo, type SessionState } from "./api/client";
import { Layout } from "./components/Layout";
import { Shell, type ShellKind } from "./components/Shell";
import { Centered, SignIn } from "./components/SignIn";
import { ErrorState, Loading } from "./components/Status";
import { ViewBoundary } from "./components/ViewBoundary";
import { useTranslation } from "./i18n";
import { AppContext, type AppState } from "./lib/context";
import { redirect, useRoute } from "./lib/router";
import { useCurrentStatus } from "./lib/staleness";
import { applyTheme, useSystemDark } from "./lib/theme";
import { useResource } from "./lib/useResource";
import { ChunkView, isPage, moduleText, PAGE_VIEWS, PAGES, VIEWS } from "./modules/registry";

function SignedIn({ initial, onSignedOut }: { initial: SessionInfo; onSignedOut: () => void }) {
  const { t } = useTranslation();
  const [session, setSession] = useState(initial);
  const route = useRoute();
  const status = useCurrentStatus(useResource((signal) => api.status(signal), [], 60));
  const system = useSystemDark();

  // Again when the system changes its own, which "system" follows.
  useEffect(() => applyTheme(session.preferences.theme, system), [session.preferences.theme, system]);
  useEffect(() => {
    // The server ends the session at expiresAt; show the sign-in page then.
    const remaining = session.expiresAt * 1000 - Date.now();
    const timer = setTimeout(onSignedOut, Math.max(0, remaining));
    return () => clearTimeout(timer);
  }, [session.expiresAt, onSignedOut]);

  const [saving, setSaving] = useState(false);
  const updatePreferences = useCallback(async (preferences: SessionInfo["preferences"]) => {
    setSaving(true);
    try {
      const saved = await api.savePreferences(preferences);
      setSession((current) => ({ ...current, preferences: saved }));
    } finally {
      setSaving(false);
    }
  }, []);
  const state: AppState = useMemo(() => ({ session, status, saving, updatePreferences }), [session, status, saving, updatePreferences]);

  const granted = session.modules.find((module) => module.id === route.view);
  useEffect(() => {
    // An unknown or ungranted view falls back to the first granted module.
    if (!granted && !isPage(route.view) && session.modules[0]) redirect(session.modules[0].id);
  }, [granted, route.view, session.modules]);

  // The sign-in page appears only after the server ended the session: when
  // the request fails, the browser is still signed in.
  const logout = async () => {
    await api.logout();
    onSignedOut();
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
  const [ended, setEnded] = useState(false);
  const signOut = useCallback(() => setEnded(true), []);
  const session = useResource((signal) => api.session(signal), [], 0, initial);
  const signedIn = session.data?.session;
  const readAgain = session.reload;

  // Before the views' first requests, which run as effects after this one. A
  // refused write reads the session again.
  useLayoutEffect(() => {
    if (signedIn) configure({ csrf: signedIn.csrf, onUnauthorized: signOut, onRefused: readAgain });
  }, [signedIn, signOut, readAgain]);

  // The browser's cookie is the same in every tab: a sign-in or sign-out in
  // another one changes the session this tab works with, its token and maybe
  // its account. The session is read again whenever this tab is shown.
  useEffect(() => {
    const shown = () => {
      if (document.visibilityState === "visible") readAgain();
    };
    document.addEventListener("visibilitychange", shown);
    return () => document.removeEventListener("visibilitychange", shown);
  }, [readAgain]);

  // Without a session the page follows the system, as the server sent it.
  // While the session is on its way the page keeps the theme the server sent
  // it in, which is the one its user chose (routes/files.rs).
  const system = useSystemDark();
  const signedOut = session.data !== null && !signedIn;
  useEffect(() => {
    if (signedOut) applyTheme("system", system);
  }, [signedOut, system]);

  let content;
  if (ended) content = <SignIn expired />;
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
  else if (!signedIn) content = <SignIn />;
  // Another session, with its own token, gets a page of its own; the same
  // session read again keeps the page as it is.
  else content = <SignedIn key={signedIn.csrf} initial={signedIn} onSignedOut={signOut} />;
  return content;
}
