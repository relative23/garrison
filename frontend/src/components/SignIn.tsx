import { useTranslation } from "../i18n";
import { BrandLarge } from "./Brand";
import { Notice } from "./Status";
import { Button } from "./ui/button";

// Shown when there is no valid session. Sign-in always happens at Stalwart.
const MESSAGES = {
  "1": "signIn.error.failed",
  "cross-site": "signIn.error.crossSite",
  rate: "signIn.error.rate",
} as const;

function message(error: string) {
  return Object.hasOwn(MESSAGES, error) ? MESSAGES[error as keyof typeof MESSAGES] : MESSAGES["1"];
}

/** Centered page for sign-in, loading and errors before a session exists. */
export function Centered({ children }: { children: React.ReactNode }) {
  return <main className="grid min-h-screen place-items-center bg-content-background p-4">{children}</main>;
}

export function SignIn({ expired = false }: { expired?: boolean }) {
  const { t } = useTranslation();
  // The build draws this page without a browser, and so without an error.
  const error = typeof location === "undefined" ? null : new URLSearchParams(location.search).get("login_error");
  return (
    <Centered>
      <div className="grid w-full max-w-md justify-items-center gap-5 rounded-2xl bg-card p-8 text-center text-card-foreground shadow-tile">
        <BrandLarge />
        <p className="text-sm text-muted-foreground">{t("signIn.intro")}</p>
        {expired && <Notice>{t("signIn.expired")}</Notice>}
        {error && (
          <Notice tone="error">
            {t(message(error))} {t("signIn.askAdministrator")}
          </Notice>
        )}
        <Button asChild>
          <a href="/auth/login">{t("signIn.button")}</a>
        </Button>
      </div>
    </Centered>
  );
}
