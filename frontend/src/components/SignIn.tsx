import { useTranslation } from "../i18n";
import { BrandLarge } from "./Brand";
import { Notice } from "./Status";
import { Button } from "./ui/button";

// Shown when there is no valid session. Sign-in always happens at Stalwart.
// The page sends someone to an administrator only where their access may be
// why: not after an outage, a rate limit, rights that could not be checked
// just then, a fault of Garrison's own, or a sign-in that did not start here.
const MESSAGES = {
  "1": { text: "signIn.error.failed", access: true },
  busy: { text: "signIn.error.busy", access: false },
  "cross-site": { text: "signIn.error.crossSite", access: false },
  internal: { text: "signIn.error.internal", access: false },
  limited: { text: "signIn.error.limited", access: false },
  rate: { text: "signIn.error.rate", access: false },
  unavailable: { text: "signIn.error.unavailable", access: false },
  unchecked: { text: "signIn.error.unchecked", access: false },
} as const;

function message(error: string) {
  return Object.hasOwn(MESSAGES, error) ? MESSAGES[error as keyof typeof MESSAGES] : MESSAGES["1"];
}

/** The reference under which the web service's journal names a fault of its
 * own. The address may carry anything; only such a reference is shown. */
const REFERENCE = /^[0-9a-f]{12}$/;

/** Centered page for sign-in, loading and errors before a session exists. */
export function Centered({ children }: { children: React.ReactNode }) {
  return <main className="grid min-h-screen place-items-center bg-content-background p-4">{children}</main>;
}

export function SignIn({ expired = false }: { expired?: boolean }) {
  const { t } = useTranslation();
  // The build draws this page without a browser, and so without an error.
  const query = typeof location === "undefined" ? null : new URLSearchParams(location.search);
  const error = query?.get("login_error");
  const shown = error ? message(error) : null;
  const reference = error === "internal" ? (query?.get("reference") ?? "") : "";
  return (
    <Centered>
      <div className="grid w-full max-w-md justify-items-center gap-5 rounded-2xl bg-card p-8 text-center text-card-foreground shadow-tile">
        <BrandLarge />
        <p className="text-sm text-muted-foreground">{t("signIn.intro")}</p>
        {expired && <Notice live>{t("signIn.expired")}</Notice>}
        {shown && (
          <Notice tone="error">
            {t(shown.text)}
            {shown.access && <> {t("signIn.askAdministrator")}</>}
            {REFERENCE.test(reference) && <p className="mt-1 text-xs opacity-80">{t("common.reference", { reference })}</p>}
          </Notice>
        )}
        <Button asChild>
          <a href="/auth/login">{t("signIn.button")}</a>
        </Button>
      </div>
    </Centered>
  );
}
