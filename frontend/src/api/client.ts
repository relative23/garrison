// Typed access to Garrison API. Types come from schema.gen.ts, which is
// generated from the server's OpenAPI document (`npm run api`).
import type { components } from "./schema.gen";

type Schemas = components["schemas"];
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

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    /** The answer's reference; the journal names it for an internal error. */
    readonly reference: string | null = null,
  ) {
    super(message);
  }
}

let csrfToken = "";
let onUnauthorized: () => void = () => undefined;

/** The CSRF token comes from /api/session; every write sends it back. */
export function configure(options: { csrf: string; onUnauthorized: () => void }): void {
  csrfToken = options.csrf;
  onUnauthorized = options.onUnauthorized;
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
  const response = await fetch(API + path, {
    ...init,
    credentials: "same-origin",
    cache: "no-store",
    signal: signal ?? null,
    headers: {
      Accept: "application/json",
      ...(write ? { "Content-Type": "application/json", "X-CSRF-Token": csrfToken } : {}),
      ...init.headers,
    },
  });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = (await response.json()) as { detail?: unknown };
      if (typeof body.detail === "string") detail = body.detail;
    } catch {
      // A non-JSON error body keeps the status text.
    }
    if (response.status === 401) onUnauthorized();
    throw new ApiError(response.status, detail, response.headers.get("x-request-id"));
  }
  return (await response.json()) as T;
}

const get = <T>(path: string, query?: Query, signal?: AbortSignal) =>
  request<T>(withQuery(path, query), {}, signal);

export interface EventFilter {
  search?: string;
  category?: string;
  type?: string;
  since?: number;
  until?: number;
  before?: string | null;
  limit?: number;
}

export const api = {
  /** The signed-in user, or `session: null` before a sign-in. */
  session: (signal?: AbortSignal) => get<SessionState>("session", undefined, signal),
  status: (signal?: AbortSignal) => get<StatusResponse>("status", undefined, signal),
  metrics: (query: { period: string; from?: number; to?: number }, signal?: AbortSignal) =>
    get<MetricsResponse>("metrics", query, signal),
  coverage: (signal?: AbortSignal) => get<Coverage>("coverage", undefined, signal),
  events: (filter: EventFilter, signal?: AbortSignal) =>
    get<EventsPage>("events", { ...filter }, signal),
  deliveries: (filter: EventFilter, signal?: AbortSignal) =>
    get<DeliveriesPage>("deliveries", { ...filter }, signal),
  delivery: (queueId: string, signal?: AbortSignal) =>
    get<DeliveryDetail>(`deliveries/${encodeURIComponent(queueId)}`, undefined, signal),
  sessions: (filter: EventFilter, signal?: AbortSignal) =>
    get<SessionsPage>("sessions", { ...filter }, signal),
  sessionDetail: (spanId: string, signal?: AbortSignal) =>
    get<SessionDetail>(`sessions/${encodeURIComponent(spanId)}`, undefined, signal),
  attacks: (period: "24h" | "7d" | "30d", signal?: AbortSignal) => get<Attacks>("attacks", { period }, signal),
  destinations: (period: "24h" | "7d" | "30d", signal?: AbortSignal) => get<Destinations>("destinations", { period }, signal),
  actions: (signal?: AbortSignal) => get<ActionsResponse>("actions", undefined, signal),
  job: (id: string, signal?: AbortSignal) =>
    get<Job>(`actions/jobs/${encodeURIComponent(id)}`, undefined, signal),
  submitAction: (body: { action: string; requestId: string; confirmation: string }) =>
    request<SubmitResponse>("actions", { method: "POST", body: JSON.stringify(body) }),
  savePreferences: (preferences: Preferences) =>
    request<Preferences>("preferences", { method: "PUT", body: JSON.stringify(preferences) }),
  logout: () => request<{ ok: boolean }>("logout", { method: "POST", body: "{}" }),
};
