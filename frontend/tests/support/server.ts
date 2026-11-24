// A stand-in for the web service. A test lists the answers by "METHOD path",
// the path relative to /api/ and without the query. Every
// request is recorded, so a test checks what the interface sends as well as
// what it shows.

export interface Call {
  method: string;
  path: string;
  query: URLSearchParams;
  headers: Headers;
  body: unknown;
  /** The fetch's mode, cache and credentials modes, as the interface set them. */
  mode: RequestMode | undefined;
  cache: RequestCache | undefined;
  credentials: RequestCredentials | undefined;
}

interface Reply {
  status?: number;
  /** Sent as JSON. */
  body?: unknown;
  /** Sent as it is, for answers that are not JSON. */
  raw?: string;
  headers?: Record<string, string>;
  /** The status line's text; HTTP/2 has none (""). */
  statusText?: string;
}

/** A fixed reply, or a function of the request; a thrown error is a network failure. */
export type Route = Reply | ((call: Call) => Reply | Promise<Reply>);

const PREFIX = "/api/";

export class FakeServer {
  readonly calls: Call[] = [];

  constructor(private readonly routes: Record<string, Route>) {}

  /** Change or add an answer while the test runs. */
  answer(key: string, route: Route): void {
    this.routes[key] = route;
  }

  /** The recorded requests for one "METHOD path". */
  requests(key: string): Call[] {
    return this.calls.filter((call) => `${call.method} ${call.path}` === key);
  }

  async fetch(input: string, init: RequestInit): Promise<Response> {
    const url = new URL(input, "https://garrison.example.test");
    const call: Call = {
      method: init.method ?? "GET",
      path: url.pathname.startsWith(PREFIX) ? url.pathname.slice(PREFIX.length) : url.pathname,
      query: url.searchParams,
      headers: new Headers(init.headers),
      body: typeof init.body === "string" ? JSON.parse(init.body) : undefined,
      mode: init.mode,
      cache: init.cache,
      credentials: init.credentials,
    };
    this.calls.push(call);
    const key = `${call.method} ${call.path}`;
    const route = this.routes[key] ?? { status: 404, body: { detail: `Not in the test fixture: ${key}` } };
    const reply = typeof route === "function" ? await route(call) : route;
    if (init.signal?.aborted) throw new DOMException("The request was aborted.", "AbortError");
    const status = reply.status ?? 200;
    const text = reply.raw ?? JSON.stringify(reply.body ?? null);
    const statusText = reply.statusText ?? (status === 200 ? "OK" : "Error");
    return new Response(text, { status, statusText, headers: reply.headers ?? {} });
  }
}

/** Answer every fetch() from `routes` until the test ends. */
export function serve(routes: Record<string, Route>): FakeServer {
  const server = new FakeServer(routes);
  vi.stubGlobal("fetch", (input: string, init: RequestInit = {}) => server.fetch(input, init));
  return server;
}
