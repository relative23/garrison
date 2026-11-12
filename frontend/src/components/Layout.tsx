// Page frame in the layout of the Stalwart WebUI: a sticky header without a
// rule, the menu as a tile floating at the left, and the content beside it on
// the same background, under the page title.
import { ExternalLink, Menu, Moon, Sun, User } from "lucide-react";
import { useContext, useState, type ReactNode } from "react";

import { useTranslation } from "../i18n";
import { AppContext } from "../lib/context";
import { safeUrl } from "../lib/format";
import { follow, href } from "../lib/router";
import { applyTheme, isDark, type Theme } from "../lib/theme";
import { Brand } from "./Brand";
import { PageSearch } from "./PageSearch";
import { Sidebar } from "./Sidebar";
import { Button } from "./ui/button";

const LINK_LABELS: Record<string, "layout.link.webmail" | "layout.link.alarms"> = {
  webmail: "layout.link.webmail",
  alarms: "layout.link.alarms",
};

export function Layout({
  current,
  section,
  title,
  intro,
  children,
}: {
  current: string;
  section: string;
  title: string;
  intro: string;
  children: ReactNode;
}) {
  const { t } = useTranslation();
  // Without a session (the page the build draws, shown until the session
  // arrives) the frame is the same but shows no one's menu, links or name.
  const app = useContext(AppContext);
  const session = app?.session;
  const [open, setOpen] = useState(false);
  // The theme being saved, shown at once; then the saved one, also when the
  // Settings page changed it.
  const [pending, setPending] = useState<Theme | null>(null);
  const dark = isDark(pending ?? session?.preferences.theme ?? "system");
  const hidden = new Set(session?.preferences.hiddenModules);
  const visible = (session?.modules ?? []).filter((module) => !hidden.has(module.id) || module.id === current);
  const home = visible[0]?.id ?? "dashboard";
  const toggleTheme = () => {
    if (!app) return;
    const { preferences } = app.session;
    const theme = dark ? "light" : "dark";
    applyTheme(theme);
    setPending(theme);
    // Saved like the setting on the Settings page; a failure restores the old look.
    app
      .updatePreferences({ ...preferences, theme })
      .catch(() => applyTheme(preferences.theme))
      .finally(() => setPending(null));
  };
  return (
    <div className="min-h-screen bg-content-background">
      <a
        href="#content"
        className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50 focus:rounded-md focus:bg-background focus:px-3 focus:py-2"
      >
        {t("layout.skip")}
      </a>
      {/* Opaque, unlike Stalwart's translucent bar: what scrolls beneath must not change the contrast of the text on it. */}
      <header className="sticky top-0 z-40 flex h-16 items-center gap-4 bg-content-background px-4 sm:px-5">
        <Button
          variant="ghost"
          size="icon"
          className="md:hidden"
          aria-label={t("layout.openMenu")}
          aria-expanded={open}
          onClick={() => setOpen(!open)}
        >
          <Menu aria-hidden />
        </Button>
        {/* As wide as the menu below, so the search starts where the content does. */}
        <a href={href(home)} className="flex shrink-0 items-center md:w-[228px]" onClick={(event) => follow(event, home)}>
          <Brand />
        </a>
        <div className="hidden min-w-0 flex-1 items-center md:flex">
          <PageSearch modules={visible} />
        </div>
        <div className="ml-auto flex items-center gap-1.5">
          {Object.entries(session?.links.other ?? {}).map(([name, url]) => {
            const target = safeUrl(url);
            const label = LINK_LABELS[name];
            return (
              target && (
                <Button key={name} asChild variant="ghost" size="sm" className="hidden lg:inline-flex">
                  <a href={target} rel="noreferrer">
                    {label ? t(label) : name} <ExternalLink aria-hidden />
                  </a>
                </Button>
              )
            );
          })}
          <Button variant="ghost" size="icon" aria-label={dark ? t("layout.lightTheme") : t("layout.darkTheme")} onClick={toggleTheme}>
            {dark ? <Sun aria-hidden /> : <Moon aria-hidden />}
          </Button>
          <Button asChild variant="ghost" size="icon">
            <a href={href("account")} aria-label={t("layout.account")} title={session?.email} onClick={(event) => follow(event, "account")}>
              <User aria-hidden />
            </a>
          </Button>
        </div>
      </header>
      {open && (
        <button
          type="button"
          aria-label={t("layout.closeMenu")}
          className="fixed inset-0 top-16 z-20 bg-black/40 md:hidden"
          onClick={() => setOpen(false)}
        />
      )}
      <Sidebar
        modules={visible}
        current={current}
        section={section}
        admin={session?.preferences.showSwitch ? safeUrl(session.links.admin) : null}
        open={open}
        onNavigate={() => setOpen(false)}
      />
      <main id="content" tabIndex={-1} className="min-h-[calc(100vh-4rem)] min-w-0 px-3 pb-10 pt-2 sm:px-5 md:ml-[252px]">
        <div className="relative space-y-4">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0 pt-1">
              <h1 className="break-words text-[1.3125rem] font-bold leading-tight tracking-tight sm:text-[1.625rem]">{title}</h1>
              {intro && <p className="mt-1 text-sm text-muted-foreground">{intro}</p>}
            </div>
          </div>
          {children}
        </div>
      </main>
    </div>
  );
}
