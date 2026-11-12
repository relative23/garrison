// Settings: personal interface preferences. They change the presentation only:
// hiding a module from the menu neither revokes access nor stops any service.
import { useState, type FormEvent, type ReactNode } from "react";

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

export function Preferences() {
  const { t } = useTranslation();
  const { session, updatePreferences } = useApp();
  const [theme, setTheme] = useState<Theme>(session.preferences.theme);
  // The header button saves a theme too; the choice here follows it.
  const [savedTheme, setSavedTheme] = useState(session.preferences.theme);
  if (savedTheme !== session.preferences.theme) {
    setSavedTheme(session.preferences.theme);
    setTheme(session.preferences.theme);
  }
  const [hidden, setHidden] = useState(new Set(session.preferences.hiddenModules));
  const [showSwitch, setShowSwitch] = useState(session.preferences.showSwitch);
  const [message, setMessage] = useState<{ tone: "info" | "error"; text: string } | null>(null);
  const toggle = (id: string) => {
    const next = new Set(hidden);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setHidden(next);
  };
  const save = async (event: FormEvent) => {
    event.preventDefault();
    try {
      await updatePreferences({ theme, hiddenModules: [...hidden].sort(), showSwitch });
      applyTheme(theme);
      setMessage({ tone: "info", text: t("preferences.saved") });
    } catch {
      setMessage({ tone: "error", text: t("preferences.notSaved") });
    }
  };
  return (
    <form className={FORM} onSubmit={save}>
      <ThemeCard theme={theme} onChange={setTheme} />
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
          <Choice type="checkbox" name="showSwitch" checked={showSwitch} onChange={() => setShowSwitch(!showSwitch)}>
            {t("preferences.showSwitch")}
          </Choice>
        </CardContent>
      </Card>
      {message && <Notice tone={message.tone}>{message.text}</Notice>}
      <Button type="submit">{t("preferences.save")}</Button>
    </form>
  );
}
