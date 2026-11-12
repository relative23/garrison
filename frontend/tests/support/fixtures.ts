// Sample answers of the web service, typed by the generated API schema, so a
// contract change that the views must follow also fails these tests.
import type {
  ActionInfo,
  ActionsResponse,
  Attacks,
  Coverage,
  DeliverySummary,
  Destinations,
  EventItem,
  Job,
  MetricsResponse,
  Observation,
  SessionInfo,
  SessionSummary,
  StatusResponse,
} from "../../src/api/client";

const NOW = Math.floor(Date.now() / 1000);

/** Every module, in the server's order. */
const MODULES = [
  "dashboard",
  "services",
  "antivirus",
  "spam",
  "attacks",
  "deliveries",
  "sessions",
  "logs",
  "backups",
  "alerts",
  "dns_tls",
  "actions",
];

// The server's module names are replaced by the catalog's (src/i18n/en.json),
// so the fixture names them by ID and the views must still show "Antivirus".
export function session(overrides: Partial<SessionInfo> = {}, modules: string[] = MODULES): SessionInfo {
  return {
    version: "0.1.0",
    email: "admin@example.test",
    csrf: "csrf-token",
    expiresAt: NOW + 3600,
    modules: modules.map((id) => ({ id, label: id, description: "" })),
    actions: [],
    profiles: ["administrator"],
    preferences: { theme: "light", hiddenModules: [], showSwitch: true },
    links: { admin: "https://mail.example.test/admin/", other: {} },
    ...overrides,
  };
}

export function observation(overrides: Partial<Observation> = {}): Observation {
  return {
    id: "clamav.configuration",
    provider: "clamav",
    title: "Antivirus configuration",
    modules: ["antivirus"],
    evidence: "configuration",
    state: "ok",
    checkedAt: new Date(NOW * 1000).toISOString(),
    source: "/etc/mail/clamav-milter.conf",
    kind: "details",
    scope: "On-disk configuration.",
    fields: [],
    table: null,
    findings: [],
    value: {},
    maxAge: 300,
    stale: false,
    ...overrides,
  };
}

export function status(observations: Observation[], overrides: Partial<StatusResponse> = {}): StatusResponse {
  return {
    available: true,
    collectedAt: new Date(NOW * 1000).toISOString(),
    observations,
    providerErrors: [],
    ...overrides,
  };
}

export function metrics(overrides: Partial<MetricsResponse> = {}): MetricsResponse {
  return {
    from: NOW - 86400,
    to: NOW,
    points: [],
    totals: {},
    latest: {},
    coverageFrom: null,
    coverageTo: null,
    sampledMinutes: 0,
    counterResets: 0,
    ...overrides,
  };
}

export function coverage(overrides: Partial<Coverage> = {}): Coverage {
  return {
    available: true,
    receiver: "running",
    recordingSince: NOW - 7 * 86400,
    retentionDays: 30,
    eventCount: 1234,
    gapCount: 0,
    gaps: [],
    limitations: ["Only events Stalwart sends to the receiver are recorded."],
    ...overrides,
  };
}

export function event(overrides: Partial<EventItem> = {}): EventItem {
  return {
    seq: 1,
    id: "event-1",
    createdAt: NOW - 60,
    type: "auth.failed",
    label: "Authentication failed",
    category: "auth",
    spanId: null,
    queueId: null,
    fields: {},
    ...overrides,
  };
}

export function delivery(overrides: Partial<DeliverySummary> = {}): DeliverySummary {
  return {
    queueId: "1a2b3c4d5e6f7a8b",
    firstSeen: NOW - 120,
    lastSeen: NOW - 60,
    eventCount: 4,
    from: "alice@example.test",
    to: ["bob@example.test"],
    status: "delivered",
    recipientOutcomes: { "bob@example.test": "delivered" },
    recipientEvidenceComplete: true,
    ...overrides,
  };
}

export function smtpSession(overrides: Partial<SessionSummary> = {}): SessionSummary {
  return {
    spanId: "9f8e7d6c5b4a3921",
    firstSeen: NOW - 120,
    lastSeen: NOW - 115,
    eventCount: 6,
    listener: "smtp",
    remoteIp: "192.0.2.10",
    ehlo: "mail.example.net",
    from: "carol@example.net",
    to: ["bob@example.test"],
    authentication: { "spf-from": "pass", dkim: "pass" },
    rejections: [],
    queueIds: [],
    complete: true,
    ...overrides,
  };
}

/** A day with one address that was banned and a second one in its network. */
export function attacks(overrides: Partial<Attacks> = {}): Attacks {
  return {
    since: NOW - 86400,
    until: NOW,
    truncated: false,
    totals: { failedSignIns: 1205, unknownAccounts: 1100, tlsErrors: 3, bans: 1, sources: 2 },
    sources: [
      {
        address: "192.0.2.10",
        network: "192.0.2.0/24",
        failedSignIns: 1200,
        accounts: 2,
        tlsErrors: 0,
        bans: 1,
        firstSeen: NOW - 7200,
        lastSeen: NOW - 600,
        listeners: ["imaps", "submission"],
      },
      {
        address: "192.0.2.77",
        network: "192.0.2.0/24",
        failedSignIns: 5,
        accounts: 1,
        tlsErrors: 3,
        bans: 0,
        firstSeen: NOW - 3600,
        lastSeen: NOW - 300,
        listeners: ["submission"],
      },
    ],
    networks: [{ network: "192.0.2.0/24", sources: 2, failedSignIns: 1205, tlsErrors: 3, bans: 1, lastSeen: NOW - 300 }],
    accounts: [{ name: "anna@example.test", failedSignIns: 105, sources: 2, lastSeen: NOW - 300 }],
    bans: [{ at: NOW - 600, address: "192.0.2.10", reason: "authentication" }],
    ...overrides,
  };
}

/** A day in which one domain refuses mail and another answers slowly. */
export function destinations(overrides: Partial<Destinations> = {}): Destinations {
  return {
    since: NOW - 86400,
    until: NOW,
    truncated: false,
    totals: { delivered: 240, delays: 6, bounces: 12, destinations: 2, waiting: 1 },
    destinations: [
      {
        domain: "strict.example",
        delivered: 1,
        delays: 0,
        bounces: 12,
        lastProblem: NOW - 900,
        cause: "550 5.7.1 Sender rejected",
        hosts: ["mx1.strict.example"],
      },
      {
        domain: "slow.example",
        delivered: 3,
        delays: 6,
        bounces: 0,
        lastProblem: NOW - 300,
        cause: "Connection timed out",
        hosts: ["mx.slow.example"],
      },
    ],
    causes: [
      { cause: "550 5.7.1 Sender rejected", delays: 0, bounces: 12, domains: 1, lastSeen: NOW - 900 },
      { cause: "Connection timed out", delays: 6, bounces: 0, domains: 1, lastSeen: NOW - 300 },
    ],
    waiting: [{ queueId: "337538776689541120", queuedAt: NOW - 7200, lastEvent: NOW - 300 }],
    ...overrides,
  };
}

export function action(overrides: Partial<ActionInfo> = {}): ActionInfo {
  return {
    id: "run_monitor",
    title: "Run health checks",
    description: "Starts the monitor service once.",
    confirmation: "RUN HEALTH CHECKS",
    cooldownSeconds: 300,
    ...overrides,
  };
}

export function job(overrides: Partial<Job> = {}): Job {
  return {
    id: "0123456789abcdef0123456789abcdef",
    actionId: "run_monitor",
    requestId: "0b3f1a6e-4f9d-4c1e-9a2b-1c3d5e7f9a0b",
    actor: "42",
    actorEmail: "admin@example.test",
    status: "queued",
    message: "Waiting to start",
    createdAt: new Date(NOW * 1000).toISOString(),
    startedAt: null,
    finishedAt: null,
    ...overrides,
  };
}

export function catalog(overrides: Partial<ActionsResponse> = {}): ActionsResponse {
  return { actions: [action()], jobs: [], ...overrides };
}
