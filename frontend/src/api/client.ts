// Typed access to Garrison API. Types come from schema.gen.ts, which is
// generated from the server's OpenAPI document (`npm run api`).
import type { components, operations } from "./schema.gen";

type Schemas = components["schemas"];
/** The query parameters of an operation, as the OpenAPI document states them. */
type QueryOf<Operation extends keyof operations> = NonNullable<operations[Operation]["parameters"]["query"]>;
/** A period of the summaries; the tabs of a page offer some of them. */
type Period = Schemas["Period"];
export type SessionInfo = Schemas["SessionInfo"];
export type SessionState = Schemas["SessionState"];
export type ModuleInfo = Schemas["ModuleInfo"];
export type Preferences = Schemas["Preferences"];
export type StatusResponse = Schemas["StatusResponse"];
export type Observation = Schemas["Observation"];

export type MetricsResponse = Schemas["MetricsResponse"];
export type EventItem = Schemas["EventItem"];
export type EventsPage = Schemas["EventsPage"];
export type DeliverySummary = Schemas["DeliverySummary"];
export type DeliveriesPage = Schemas["DeliveriesPage"];
export type DeliveryDetail = Schemas["DeliveryDetail"];
export type SessionSummary = Schemas["SessionSummary"];
export type SessionsPage = Schemas["SessionsPage"];
export type Attacks = Schemas["Attacks"];
export type Destinations = Schemas["Destinations"];
export type SessionDetail = Schemas["SessionDetail"];
export type Coverage = Schemas["Coverage"];
export type ActionsResponse = Schemas["ActionsResponse"];
export type ActionInfo = Schemas["ActionInfo"];
export type Job = Schemas["Job"];
export type SubmitResponse = Schemas["SubmitResponse"];

const API = "/api/";

/** An error answer. Garrison's own carries its reason as the message; one
 * that something between the browser and Garrison gave, such as a proxy's
 * error page, carries only its status. Any other failure of a request is no
 * readable answer (src/components/Failure.tsx words each). */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    /** The answer's reference; the journal names it for an internal error. */
    readonly reference: string | null = null,
    /** Whether Garrison gave the answer. */
    readonly own = true,
  ) {
    super(message);
  }
}

let csrfToken = "";
let onUnauthorized: () => void = () => undefined;
let onRefused: () => void = () => undefined;

/** The CSRF token comes from /api/session; every write sends it back.
 * `onRefused` hears of a request the server refused (403): its token may
 * belong to a session that a sign-in in another tab has replaced, or the
 * user's rights may have changed. */
export function configure(options: { csrf: string; onUnauthorized: () => void; onRefused: () => void }): void {
  csrfToken = options.csrf;
  onUnauthorized = options.onUnauthorized;
  onRefused = options.onRefused;
}

type Query = Record<string, string | number | undefined | null>;

function withQuery(path: string, query?: Query): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value !== undefined && value !== null && value !== "") search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `${path}?${text}` : path;
}

async function request<T>(path: string, init: RequestInit = {}, signal?: AbortSignal): Promise<T> {
  const write = init.method && init.method !== "GET";
  // In the modes of the page's preloads (prerender.mjs), so that a first
  // request takes the answer already on its way. No cache mode of its own:
  // every answer says Cache-Control: no-store, and Firefox hands a preloaded
  // answer only to a fetch in the default mode.
  const response = await fetch(API + path, {
    ...init,
    credentials: "same-origin",
    signal: signal ?? null,
    headers: {
      Accept: "application/json",
      ...(write ? { "Content-Type": "application/json", "X-CSRF-Token": csrfToken } : {}),
      ...init.headers,
    },
  });
  if (!response.ok) {
    let detail: string | null = null;
    try {
      // The service's own errors are ErrorDetail; a proxy's need not be.
      const body = (await response.json()) as Partial<Record<keyof Schemas["ErrorDetail"], unknown>>;
      if (typeof body.detail === "string" && body.detail) detail = body.detail;
    } catch {
      // An error body that is no JSON is not the service's.
    }
    // A server error that is not the service's own, such as nginx's 502 while
    // the service restarts, says nothing of what became of a write: it may
    // have been done before the service went away. That is no answer, as a
    // lost connection is none, and no ApiError.
    if (write && detail === null && response.status >= 500) throw new Error(`No answer of the service's own: status ${response.status}.`);
    if (response.status === 401) onUnauthorized();
    // A refusal of the session's own question ended the session: the web
    // service answers it so only where the policy refuses the user, and ends
    // that session then (docs/architecture/security.md, failure behavior).
    // Any other refusal has the session read again; the session's own does
    // not, as that would ask again and again.
    if (response.status === 403) {
      if (path === "session") onUnauthorized();
      else onRefused();
    }
    // A proxy's own page and its status text (none over HTTP/2) are never
    // shown: they are not Garrison's words, nor in the page's language.
    if (detail === null) throw new ApiError(response.status, `Status ${response.status} not from the service`, null, false);
    throw new ApiError(response.status, detail, response.headers.get("x-request-id"));
  }
  return (await response.json()) as T;
}

const get = <T>(path: string, query?: Query, signal?: AbortSignal) =>
  request<T>(withQuery(path, query), {}, signal);

export const api = {
  /** The signed-in user, or `session: null` before a sign-in. */
  session: (signal?: AbortSignal) => get<SessionState>("session", undefined, signal),
  status: (signal?: AbortSignal) => get<StatusResponse>("status", undefined, signal),
  metrics: (query: QueryOf<"getMetrics">, signal?: AbortSignal) => get<MetricsResponse>("metrics", query, signal),
  coverage: (signal?: AbortSignal) => get<Coverage>("coverage", undefined, signal),
  events: (filter: QueryOf<"listEvents">, signal?: AbortSignal) => get<EventsPage>("events", filter, signal),
  deliveries: (filter: QueryOf<"listDeliveries">, signal?: AbortSignal) =>
    get<DeliveriesPage>("deliveries", filter, signal),
  delivery: (queueId: string, signal?: AbortSignal) =>
    get<DeliveryDetail>(`deliveries/${encodeURIComponent(queueId)}`, undefined, signal),
  sessions: (filter: QueryOf<"listSmtpSessions">, signal?: AbortSignal) =>
    get<SessionsPage>("sessions", filter, signal),
  sessionDetail: (spanId: string, signal?: AbortSignal) =>
    get<SessionDetail>(`sessions/${encodeURIComponent(spanId)}`, undefined, signal),
  attacks: (period: Period, signal?: AbortSignal) => get<Attacks>("attacks", { period }, signal),
  destinations: (period: Period, signal?: AbortSignal) => get<Destinations>("destinations", { period }, signal),
  actions: (signal?: AbortSignal) => get<ActionsResponse>("actions", undefined, signal),
  job: (id: string, signal?: AbortSignal) =>
    get<Job>(`actions/jobs/${encodeURIComponent(id)}`, undefined, signal),
  submitAction: (body: Schemas["SubmitRequest"]) =>
    request<SubmitResponse>("actions", { method: "POST", body: JSON.stringify(body) }),
  savePreferences: (preferences: Preferences) =>
    request<Preferences>("preferences", { method: "PUT", body: JSON.stringify(preferences) }),
  logout: () => request<Schemas["LogoutResponse"]>("logout", { method: "POST", body: "{}" }),
};
