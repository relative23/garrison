// State and evidence labels. Colors are never the only signal: every badge
// has an icon and a word, so it reads the same for color-blind users.
import { CircleAlert, CircleCheck, CircleDashed, CircleHelp, CircleX, Clock, LoaderCircle } from "lucide-react";
import type { ReactNode } from "react";

import { ApiError } from "../api/client";
import { useTranslation } from "../i18n";
import { Alert } from "./ui/alert";
import { Badge, type BadgeTone } from "./ui/badge";
import { Button } from "./ui/button";
import { Tooltip } from "./ui/tooltip";

export type StateName = "ok" | "warning" | "failed" | "partial" | "unknown";

const STATES: Record<StateName, { icon: typeof CircleCheck; tone: BadgeTone }> = {
  ok: { icon: CircleCheck, tone: "ok" },
  warning: { icon: CircleAlert, tone: "warning" },
  failed: { icon: CircleX, tone: "failed" },
  partial: { icon: CircleDashed, tone: "warning" },
  unknown: { icon: CircleHelp, tone: "unknown" },
};

export function StateBadge({ state, stale = false }: { state: StateName; stale?: boolean }) {
  const { t } = useTranslation();
  if (stale) {
    return (
      <Badge tone="unknown" title={t("state.staleHint")}>
        <Clock aria-hidden /> {t("state.stale")}
      </Badge>
    );
  }
  const { icon: Icon, tone } = STATES[state];
  return (
    <Badge tone={tone}>
      <Icon aria-hidden /> {t(`state.${state}`)}
    </Badge>
  );
}

const EVIDENCE = ["configuration", "process", "probe", "receipt", "inventory", "metric"] as const;

function isEvidence(kind: string): kind is (typeof EVIDENCE)[number] {
  return (EVIDENCE as readonly string[]).includes(kind);
}

export function EvidenceLabel({ kind }: { kind: string }) {
  const { t } = useTranslation();
  // An evidence kind this build does not know is shown as the server named it.
  const known = isEvidence(kind);
  return (
    <Tooltip content={known ? t(`evidence.${kind}.explanation`) : ""}>
      <span tabIndex={0} className="cursor-help rounded-full border border-dashed px-2.5 py-0.5 text-xs text-muted-foreground">
        {known ? t(`evidence.${kind}.label`) : kind}
      </span>
    </Tooltip>
  );
}

export function Notice({ tone = "info", children }: { tone?: "info" | "warning" | "error"; children: ReactNode }) {
  return <Alert tone={tone}>{children}</Alert>;
}

export function Loading({ label }: { label?: string }) {
  const { t } = useTranslation();
  return (
    <p className="flex items-center gap-2 py-6 text-sm text-muted-foreground" aria-live="polite">
      <LoaderCircle aria-hidden className="h-4 w-4 animate-spin" /> {label ?? t("common.loading")}
    </p>
  );
}

export function ErrorState({ error, retry }: { error: Error; retry?: () => void }) {
  const { t } = useTranslation();
  // Only an internal error is in the journal under its reference.
  const reference = error instanceof ApiError && error.status === 500 ? error.reference : null;
  return (
    <Notice tone="error">
      <div className="flex items-center justify-between gap-4">
        <div>
          <p>{error.message || t("common.requestFailed")}</p>
          {reference && <p className="mt-1 text-xs opacity-80">{t("common.reference", { reference })}</p>}
        </div>
        {retry && (
          <Button variant="outline" size="sm" onClick={retry}>
            {t("common.tryAgain")}
          </Button>
        )}
      </div>
    </Notice>
  );
}

/** Small grey line for dates, sources and other context. */
export function Meta({ children }: { children: ReactNode }) {
  return <p className="text-xs text-muted-foreground">{children}</p>;
}
