// Settings: personal interface preferences. They change the presentation only:
// hiding a module from the menu neither revokes access nor stops any service.
import { useState, type FormEvent, type ReactNode } from "react";

import type { Preferences as Saved } from "../api/client";
import { WriteFailure } from "../components/Failure";
import { Notice } from "../components/Status";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../components/ui/card";
import { useTranslation } from "../i18n";
import { useApp } from "../lib/context";
import { applyTheme, type Theme } from "../lib/theme";
import { moduleText } from "./registry";

function Choice({
  type,
  name,
  checked,
  onChange,
  children,
}: {
  type: "radio" | "checkbox";
  name: string;
  checked: boolean;
  onChange: () => void;
  children: ReactNode;
}) {
  return (
    <label className="flex cursor-pointer items-center gap-3 rounded-md px-2 py-1.5 text-sm hover:bg-accent">
      <input type={type} name={name} checked={checked} onChange={onChange} className="h-4 w-4 accent-primary" />
      {children}
    </label>
  );
}

const FORM = "max-w-3xl space-y-4";

function ThemeCard({ theme, onChange }: { theme: Theme | null; onChange: (theme: Theme) => void }) {
  const { t } = useTranslation();
  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("preferences.appearance")}</CardTitle>
        <CardDescription>{t("preferences.appearanceHint")}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-1">
        {(["system", "light", "dark"] as const).map((value) => (
          <Choice key={value} type="radio" name="theme" checked={theme === value} onChange={() => onChange(value)}>
            {t(`preferences.theme.${value}`)}
          </Choice>
        ))}
      </CardContent>
    </Card>
  );
}

/** What the page the build draws shows before the session is known
 * (src/prerender.tsx): the form with its first card, no theme chosen yet. The
 * other cards follow below it, so nothing above them moves. */
export function PreferencesHead() {
  return (
    <form className={FORM}>
      <ThemeCard theme={null} onChange={() => undefined} />
    </form>
  );
}

/** What the form shows, and the saved settings it last followed. */
interface Form {
  followed: Saved;
  theme: Theme;
  hidden: Set<string>;
  showSwitch: boolean;
}

function formOf(saved: Saved): Form {
  return { followed: saved, theme: saved.theme, hidden: new Set(saved.hiddenModules), showSwitch: saved.showSwitch };
}

function same(a: Saved, b: Saved): boolean {
  return a.theme === b.theme && a.showSwitch === b.showSwitch && [...a.hiddenModules].sort().join() === [...b.hiddenModules].sort().join();
}

/** `form` once the saved settings changed from those it followed to `saved`,
 * as another tab or the header's theme button saves them: a setting the user
 * has not changed here takes the saved value, one they changed stays theirs. */
function follow(form: Form, saved: Saved): Form {
  const before = form.followed;
  const pick = <T,>(mine: T, was: T, now: T) => (mine === was ? now : mine);
  const ids = new Set([...before.hiddenModules, ...saved.hiddenModules, ...form.hidden]);
  const hidden = [...ids].filter((id) => pick(form.hidden.has(id), before.hiddenModules.includes(id), saved.hiddenModules.includes(id)));
  return {
    followed: saved,
    theme: pick(form.theme, before.theme, saved.theme),
    hidden: new Set(hidden),
    showSwitch: pick(form.showSwitch, before.showSwitch, saved.showSwitch),
  };
}

export function Preferences() {
  const { t } = useTranslation();
  const { session, saving, updatePreferences } = useApp();
  const [form, setForm] = useState(() => formOf(session.preferences));
  if (!same(form.followed, session.preferences)) setForm(follow(form, session.preferences));
  const { theme, hidden, showSwitch } = form;
  // The settings were saved, or why the last save failed.
  const [result, setResult] = useState<{ error: Error | null } | null>(null);
  const toggle = (id: string) => {
    const next = new Set(hidden);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setForm({ ...form, hidden: next });
  };
  const save = async (event: FormEvent) => {
    event.preventDefault();
    // One save at a time, this page's or the header's theme button's.
    if (saving) return;
    setResult(null);
    try {
      await updatePreferences({ theme, hiddenModules: [...hidden].sort(), showSwitch });
      applyTheme(theme);
      setResult({ error: null });
    } catch (reason) {
      setResult({ error: reason instanceof Error ? reason : new Error(String(reason)) });
    }
  };
  return (
    <form className={FORM} onSubmit={save}>
      <ThemeCard theme={theme} onChange={(chosen) => setForm({ ...form, theme: chosen })} />
      <Card>
        <CardHeader>
          <CardTitle>{t("preferences.menu")}</CardTitle>
          <CardDescription>{t("preferences.menuHint")}</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-1 sm:grid-cols-2">
          {session.modules.map((module) => (
            <Choice key={module.id} type="checkbox" name={module.id} checked={!hidden.has(module.id)} onChange={() => toggle(module.id)}>
              {moduleText(module, "label")}
            </Choice>
          ))}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>{t("preferences.switch")}</CardTitle>
          <CardDescription>{t("preferences.switchHint")}</CardDescription>
        </CardHeader>
        <CardContent>
          <Choice type="checkbox" name="showSwitch" checked={showSwitch} onChange={() => setForm({ ...form, showSwitch: !showSwitch })}>
            {t("preferences.showSwitch")}
          </Choice>
        </CardContent>
      </Card>
      {result?.error === null && <Notice live>{t("preferences.saved")}</Notice>}
      {result?.error && <WriteFailure error={result.error} refused={t("preferences.notSaved")} unanswered={t("preferences.unanswered")} />}
      {/* aria-disabled, not disabled: a disabled button would drop the focus. */}
      <Button type="submit" aria-disabled={saving || undefined}>
        {saving ? t("preferences.saving") : t("preferences.save")}
      </Button>
    </form>
  );
}
