// Maintenance actions: typed confirmation, idempotent submission, job status.
import { Play } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent } from "react";

import { api, ApiError, type ActionInfo, type Job } from "../api/client";
import { ErrorState, Loading, Notice } from "../components/Status";
import { Badge, type BadgeTone } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "../components/ui/card";
import { Input } from "../components/ui/input";
import { Table, TableBody, TableCell, TableEmpty, TableHead, TableHeader, TableHeadRow, TableRow } from "../components/ui/table";
import { Trans, useTranslation } from "../i18n";
import { dateTime, duration } from "../lib/format";
import { useResource } from "../lib/useResource";

const TERMINAL = new Set(["succeeded", "failed", "uncertain"]);
const STATUS = ["queued", "running", "succeeded", "failed", "uncertain"] as const;

function isStatus(status: string): status is (typeof STATUS)[number] {
  return (STATUS as readonly string[]).includes(status);
}
const TONES: Record<string, BadgeTone> = { succeeded: "ok", failed: "failed", uncertain: "warning" };

function Confirm({ action, onDone }: { action: ActionInfo; onDone: (job: Job) => void }) {
  // The native <dialog> traps focus and closes on Escape without injecting
  // styles, so the strict Content-Security-Policy stays intact.
  const { t } = useTranslation();
  const dialog = useRef<HTMLDialogElement>(null);
  const [typed, setTyped] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // One request ID per dialog: a retried click after a network error replays
  // the same request instead of starting the job twice.
  const requestId = useRef("");
  const open = () => {
    requestId.current = crypto.randomUUID();
    setTyped("");
    setError(null);
    dialog.current?.showModal();
  };
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = await api.submitAction({ action: action.id, requestId: requestId.current, confirmation: typed });
      onDone(result.job);
      dialog.current?.close();
    } catch (reason) {
      setError(reason instanceof ApiError ? reason.message : t("actions.notSent"));
    } finally {
      setBusy(false);
    }
  };
  const titleId = `action-${action.id}-title`;
  return (
    <>
      <Button size="sm" onClick={open}>
        <Play aria-hidden /> {t("actions.run")}
      </Button>
      <dialog
        ref={dialog}
        aria-labelledby={titleId}
        className="m-auto w-full max-w-lg rounded-2xl bg-card p-6 text-card-foreground shadow-lg"
      >
        <h2 id={titleId} className="text-lg font-semibold">
          {action.title}
        </h2>
        <p className="mt-2 text-sm text-muted-foreground">{action.description}</p>
        <form onSubmit={submit} className="mt-4 space-y-3">
          <label htmlFor={`${titleId}-input`} className="block text-sm">
            <Trans
              i18nKey="actions.confirm"
              components={{ phrase: <code className="rounded bg-muted px-1 py-0.5">{action.confirmation}</code> }}
            />
          </label>
          <Input
            id={`${titleId}-input`}
            value={typed}
            onChange={(event) => setTyped(event.target.value)}
            autoComplete="off"
            spellCheck={false}
          />
          {error && <Notice tone="error">{error}</Notice>}
          <div className="flex justify-end gap-2 pt-2">
            <Button variant="outline" onClick={() => dialog.current?.close()}>
              {t("actions.cancel")}
            </Button>
            <Button type="submit" disabled={busy || typed !== action.confirmation}>
              {busy ? t("actions.starting") : t("actions.start")}
            </Button>
          </div>
        </form>
      </dialog>
    </>
  );
}

export function Actions() {
  const { t } = useTranslation();
  // A status this build does not know is shown as the server named it.
  const label = (status: string) => (isStatus(status) ? t(`actions.status.${status}`) : status);
  const catalog = useResource((signal) => api.actions(signal), [], 15);
  const reloadCatalog = catalog.reload;
  const [watched, setWatched] = useState<Job | null>(null);

  // Follow a started job until it reaches a final state.
  useEffect(() => {
    if (!watched || TERMINAL.has(watched.status)) return undefined;
    const timer = setTimeout(() => {
      api.job(watched.id).then(setWatched, () => undefined);
      reloadCatalog();
    }, 3000);
    return () => clearTimeout(timer);
  }, [watched, reloadCatalog]);

  // The notice needs no data: it stands first while the catalog loads, and the
  // page the build draws carries it (src/prerender.tsx).
  const intro = <Notice>{t("actions.intro")}</Notice>;
  if (catalog.error)
    return (
      <>
        {intro}
        <ErrorState error={catalog.error} retry={catalog.reload} />
      </>
    );
  if (!catalog.data)
    return (
      <>
        {intro}
        <Loading />
      </>
    );
  const { actions, jobs } = catalog.data;
  return (
    <>
      {intro}
      {watched && (
        <Notice tone={watched.status === "failed" ? "error" : "info"}>
          {t("actions.job", { id: watched.id.slice(0, 8), status: label(watched.status), message: watched.message })}
        </Notice>
      )}
      {actions.length === 0 && <Notice>{t("actions.noActions")}</Notice>}
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {actions.map((action) => (
          <Card key={action.id} className="flex flex-col">
            <CardHeader>
              <CardTitle>{action.title}</CardTitle>
              <CardDescription>{action.description}</CardDescription>
            </CardHeader>
            <CardContent className="flex-1" />
            <CardFooter className="justify-between">
              <span className="text-xs text-muted-foreground">{t("actions.cooldown", { duration: duration(action.cooldownSeconds) })}</span>
              <Confirm action={action} onDone={setWatched} />
            </CardFooter>
          </Card>
        ))}
      </div>
      <h2 className="pt-2 text-lg font-semibold tracking-tight">{t("actions.recentJobs")}</h2>
      <Table>
        <TableHeader>
          <TableHeadRow>
            <TableHead>{t("actions.column.started")}</TableHead>
            <TableHead>{t("actions.column.action")}</TableHead>
            <TableHead>{t("actions.column.requestedBy")}</TableHead>
            <TableHead>{t("actions.column.result")}</TableHead>
            <TableHead>{t("actions.column.message")}</TableHead>
          </TableHeadRow>
        </TableHeader>
        <TableBody>
          {jobs.length === 0 && <TableEmpty columns={5}>{t("actions.empty")}</TableEmpty>}
          {jobs.map((job) => (
            <TableRow key={job.id}>
              <TableCell className="whitespace-nowrap">{dateTime(job.createdAt)}</TableCell>
              <TableCell>{actions.find((a) => a.id === job.actionId)?.title ?? job.actionId}</TableCell>
              {/* A job whose subject had no address names the subject. */}
              <TableCell>{job.actorEmail || job.actor}</TableCell>
              <TableCell>
                <Badge tone={TONES[job.status] ?? "unknown"}>{label(job.status)}</Badge>
              </TableCell>
              <TableCell>{job.message}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </>
  );
}
