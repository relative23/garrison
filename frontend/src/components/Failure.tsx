// What a failed request says, in one place for every view and every write
// (tests/failures.test.tsx holds each to it). The reason is Garrison's own
// answer as it gave it, with the reference under which the journal names an
// internal error; an answer that something between the browser and Garrison
// gave, such as a proxy's page, is named by its status alone; and anything
// else, a request that got no answer or one that could not be read, is said
// to be so. Never the browser's or a proxy's own words, which are neither
// Garrison's nor in the page's language.
import { ApiError } from "../api/client";
import { i18n, useTranslation } from "../i18n";
import type { Resource } from "../lib/useResource";
import { Notice } from "./Status";
import { Button } from "./ui/button";

function reasonOf(error: Error): { text: string; reference: string | null } {
  if (!(error instanceof ApiError)) return { text: i18n.t("failure.unanswered"), reference: null };
  if (!error.own) return { text: i18n.t("failure.foreign", { status: error.status }), reference: null };
  // Only an internal error is in the journal under its reference.
  return { text: error.message, reference: error.status === 500 ? error.reference : null };
}

function Reason({ error }: { error: Error }) {
  const { t } = useTranslation();
  const { text, reference } = reasonOf(error);
  return (
    <>
      <p>{text}</p>
      {reference && <p className="mt-1 text-xs opacity-80">{t("common.reference", { reference })}</p>}
    </>
  );
}

/** Why a request failed, with a way to try again. `lead` says what the
 * failure means for what is still on the page; with data still in view the
 * caller makes it a warning. */
export function ErrorState({
  error,
  retry,
  lead,
  tone = "error",
}: {
  error: Error;
  retry?: () => void;
  lead?: string;
  tone?: "warning" | "error";
}) {
  const { t } = useTranslation();
  return (
    <Notice tone={tone} live>
      <div className="flex items-center justify-between gap-4">
        <div>
          {lead && <p>{lead}</p>}
          <Reason error={error} />
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

/** A read of `resource` that failed. Where the view still shows an earlier
 * answer of it, a warning whose lead, `kept`, says so; where it has none, an
 * error, led by `unread` where the page shows other things. */
export function ReadFailure({ resource, kept, unread }: { resource: Resource<unknown>; kept: string; unread?: string }) {
  if (!resource.error) return null;
  if (resource.data !== null) return <ErrorState tone="warning" lead={kept} error={resource.error} retry={resource.reload} />;
  return <ErrorState lead={unread} error={resource.error} retry={resource.reload} />;
}

/** A write that failed: what was not done, `refused`, with the reason and an
 * internal error's reference, as a failed read gives them. Without an answer
 * of Garrison's the write may have been done all the same: `unanswered` says
 * that this is not known, and what to do. */
export function WriteFailure({ error, refused, unanswered }: { error: Error; refused: string; unanswered: string }) {
  if (!(error instanceof ApiError)) return <Notice tone="error">{unanswered}</Notice>;
  return (
    <Notice tone="error">
      <p>{refused}</p>
      <Reason error={error} />
    </Notice>
  );
}
