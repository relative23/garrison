// Account: who is signed in, what the profile grants, and sign-out.
import { LogOut } from "lucide-react";
import { useState } from "react";

import type { SessionInfo } from "../api/client";
import { Fields } from "../components/ObservationCard";
import { Notice } from "../components/Status";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from "../components/ui/card";
import { Trans, useTranslation } from "../i18n";
import { useApp } from "../lib/context";
import { dateTime } from "../lib/format";

export function Account({ onLogout }: { onLogout: () => Promise<void> }) {
  const { session } = useApp();
  const [failed, setFailed] = useState(false);
  const signOut = () => {
    setFailed(false);
    onLogout().catch(() => setFailed(true));
  };
  return <AccountCard session={session} onSignOut={signOut} failed={failed} />;
}

/** The page the build draws shows this card before the session is known
 * (src/prerender.tsx): its values are blank but keep their lines, so nothing
 * moves when they arrive. */
export function AccountCard({
  session,
  onSignOut,
  failed = false,
}: {
  session: SessionInfo | null;
  onSignOut?: () => void;
  failed?: boolean;
}) {
  const { t } = useTranslation();
  const blank = "\u00a0";
  return (
    <Card className="max-w-3xl">
      <CardHeader>
        <CardTitle>{t("account.title")}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <Fields
          items={[
            { label: t("account.account"), value: session ? session.email : blank },
            { label: t("account.profiles"), value: session ? session.profiles.join(", ") || t("account.none") : blank },
            { label: t("account.sessionEnds"), value: session ? dateTime(session.expiresAt) : blank },
            { label: t("account.version"), value: session ? session.version : blank },
          ]}
        />
        <p className="text-sm text-muted-foreground">
          <Trans i18nKey="account.access" components={{ code: <code className="rounded bg-muted px-1 py-0.5" /> }} />
        </p>
        {failed && <Notice tone="error">{t("account.signOutFailed")}</Notice>}
      </CardContent>
      <CardFooter>
        <Button variant="outline" onClick={onSignOut}>
          <LogOut aria-hidden /> {t("account.signOut")}
        </Button>
      </CardFooter>
    </Card>
  );
}
