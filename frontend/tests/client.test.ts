import { api, ApiError, configure } from "../src/api/client";
import { serve } from "./support/server";

describe("API client", () => {
  it("sends the CSRF token with writes and never with reads", async () => {
    const server = serve({
      "GET status": { body: {} },
      "PUT preferences": { body: { theme: "dark", hiddenModules: [], showSwitch: true } },
    });
    configure({ csrf: "token-1", onUnauthorized: () => undefined, onRefused: () => undefined });
    await api.status();
    await api.savePreferences({ theme: "dark", hiddenModules: [], showSwitch: true });
    const [read, write] = server.calls;
    expect(read?.headers.get("x-csrf-token")).toBeNull();
    expect(write?.headers.get("x-csrf-token")).toBe("token-1");
    expect(write?.headers.get("content-type")).toBe("application/json");
    expect(write?.body).toEqual({ theme: "dark", hiddenModules: [], showSwitch: true });
  });

  // A page the build drew preloads its first answers (prerender.mjs) with
  // crossorigin="anonymous". A browser hands such an answer only to a fetch
  // in the same credentials mode, and Firefox only to one in the default cache
  // mode; with cache: "no-store" it asks the server again.
  it("reads as the page's preloads ask, so that their answers are taken", async () => {
    const server = serve({ "GET status": { body: {} }, "GET session": { body: { session: null } } });
    await api.session();
    await api.status();
    for (const call of server.calls) {
      expect(call.credentials).toBe("same-origin");
      expect(call.cache ?? "default").toBe("default");
    }
    expect(server.calls).toHaveLength(2);
  });

  it("leaves unset filters out of the query", async () => {
    const server = serve({ "GET events": { body: { items: [], next: null } } });
    await api.events({ search: "", category: "auth", type: undefined, before: null, limit: 50 });
    expect(server.calls[0]?.query.toString()).toBe("category=auth&limit=50");
  });

  it("encodes identifiers as one path segment", async () => {
    const server = serve({});
    await api.delivery("a/b c?").catch(() => undefined);
    expect(server.calls[0]?.path).toBe("deliveries/a%2Fb%20c%3F");
  });

  it("reports the server's reason for a refusal", async () => {
    serve({ "POST actions": { status: 409, body: { detail: "Another maintenance operation is in progress" } } });
    const error = await api.submitAction({ action: "a", requestId: "r", confirmation: "c" }).catch((reason: unknown) => reason);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 409, message: "Another maintenance operation is in progress" });
  });

  it("keeps the reference that names an internal error in the journal", async () => {
    serve({ "GET status": { status: 500, body: { detail: "Internal error" }, headers: { "x-request-id": "0123456789ab" } } });
    await expect(api.status()).rejects.toMatchObject({ status: 500, reference: "0123456789ab" });
    serve({ "GET status": { status: 502, raw: "<html>Bad gateway</html>" } });
    await expect(api.status()).rejects.toMatchObject({ status: 502, reference: null });
  });

  it("keeps the status text when an error is not JSON", async () => {
    serve({ "GET status": { status: 502, raw: "<html>Bad gateway</html>" } });
    await expect(api.status()).rejects.toMatchObject({ status: 502, message: "Error" });
  });

  it("takes a server error that is not the service's own as no answer to a write, and to nothing else", async () => {
    const write = () => api.savePreferences({ theme: "dark", hiddenModules: [], showSwitch: true }).catch((reason: unknown) => reason);
    // nginx's page while the web service restarts: the write may have been done.
    serve({ "PUT preferences": { status: 502, raw: "<html>Bad gateway</html>" } });
    expect(await write()).not.toBeInstanceOf(ApiError);
    // The service's own error says the write was not done.
    serve({ "PUT preferences": { status: 503, body: { detail: "Busy" } } });
    expect(await write()).toMatchObject({ status: 503, message: "Busy" });
    // What a proxy refuses never reached the service.
    serve({ "PUT preferences": { status: 413, raw: "<html>Too large</html>" } });
    expect(await write()).toBeInstanceOf(ApiError);
    // A read changes nothing, so its error stays an answer.
    serve({ "GET status": { status: 502, raw: "<html>Bad gateway</html>" } });
    await expect(api.status()).rejects.toBeInstanceOf(ApiError);
  });

  it("signs out once when the server ends the session", async () => {
    serve({ "GET status": { status: 401, body: { detail: "Sign in again" } } });
    const signedOut = vi.fn();
    configure({ csrf: "", onUnauthorized: signedOut, onRefused: () => undefined });
    await expect(api.status()).rejects.toMatchObject({ status: 401 });
    expect(signedOut).toHaveBeenCalledTimes(1);
  });

  it("does not sign out on other refusals, and says when a read is refused", async () => {
    serve({ "GET actions": { status: 403, body: { detail: "Not permitted" } } });
    const signedOut = vi.fn();
    const refused = vi.fn();
    configure({ csrf: "", onUnauthorized: signedOut, onRefused: refused });
    await expect(api.actions()).rejects.toMatchObject({ status: 403, message: "Not permitted" });
    expect(signedOut).not.toHaveBeenCalled();
    // The user's rights may have changed since the session was read.
    expect(refused).toHaveBeenCalledTimes(1);
  });

  it("signs out when the session's own question is refused, which ended the session", async () => {
    // The web service answers it 403 only where the policy refuses the user,
    // and it ends that session then (docs/architecture/security.md).
    serve({ "GET session": { status: 403, body: { detail: "Garrison access is not authorized" } } });
    const signedOut = vi.fn();
    const refused = vi.fn();
    configure({ csrf: "", onUnauthorized: signedOut, onRefused: refused });
    await expect(api.session()).rejects.toMatchObject({ status: 403 });
    expect(signedOut).toHaveBeenCalledTimes(1);
    // Not followed by the same question again, as a refused read is.
    expect(refused).not.toHaveBeenCalled();
  });

  it("says when a write is refused, whose token may be another session's", async () => {
    serve({ "PUT preferences": { status: 403, body: { detail: "Origin or CSRF validation failed" } } });
    const refused = vi.fn();
    configure({ csrf: "old", onUnauthorized: () => undefined, onRefused: refused });
    await expect(api.savePreferences({ theme: "dark", hiddenModules: [], showSwitch: true })).rejects.toMatchObject({ status: 403 });
    expect(refused).toHaveBeenCalledTimes(1);
  });
});
