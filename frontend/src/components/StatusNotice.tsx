// What a status view says about the status itself: why there is none, that
// the collector has not produced one yet, or that a refresh failed and the
// page shows the last status it got.
import { useTranslation } from "../i18n";
import { useApp } from "../lib/context";
import { dateTime } from "../lib/format";
import { ErrorState, Notice } from "./Status";

export function StatusNotice() {
  const { t } = useTranslation();
  const { status } = useApp();
  if (status.error && !status.data) return <ErrorState error={status.error} retry={status.reload} />;
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
