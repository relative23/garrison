// What a view that shows the collector's checks says about the status
// itself: why there is none, that the collector has not produced one yet, or
// that a refresh failed and the page shows the last status it got. Every such
// view shows it (tests/status-views.test.tsx): a check that is missing or old
// never reads as a quiet one.
import { useTranslation } from "../i18n";
import { useApp } from "../lib/context";
import { dateTime } from "../lib/format";
import { ErrorState, Notice } from "./Status";

/** `unread` says what could not be read, where the page shows more than
 * the status, such as the summary above the checks of Attacks & bans. */
export function StatusNotice({ unread }: { unread?: string }) {
  const { t } = useTranslation();
  const { status } = useApp();
  if (status.error && !status.data) return <ErrorState lead={unread} error={status.error} retry={status.reload} />;
  if (status.data && !status.data.available) return <Notice>{t("statusPage.noSnapshot")}</Notice>;
  if (status.error && status.data) {
    return (
      <ErrorState
        tone="warning"
        lead={t("statusPage.refreshFailed", { date: dateTime(status.data.collectedAt) })}
        error={status.error}
        retry={status.reload}
      />
    );
  }
  return null;
}
