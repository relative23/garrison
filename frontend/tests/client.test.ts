import { api, ApiError, configure } from "../src/api/client";
import { serve } from "./support/server";

describe("API client", () => {
  it("sends the CSRF token with writes and never with reads", async () => {
    const server = serve({
      "GET status": { body: {} },
      "PUT preferences": { body: { theme: "dark", hiddenModules: [], showSwitch: true } },
    });
    configure({ csrf: "token-1", onUnauthorized: () => undefined });
    await api.status();
    await api.savePreferences({ theme: "dark", hiddenModules: [], showSwitch: true });
    const [read, write] = server.calls;
    expect(read?.headers.get("x-csrf-token")).toBeNull();
    expect(write?.headers.get("x-csrf-token")).toBe("token-1");
    expect(write?.headers.get("content-type")).toBe("application/json");
    expect(write?.body).toEqual({ theme: "dark", hiddenModules: [], showSwitch: true });
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

  it("signs out once when the server ends the session", async () => {
    serve({ "GET status": { status: 401, body: { detail: "Sign in again" } } });
    const signedOut = vi.fn();
    configure({ csrf: "", onUnauthorized: signedOut });
    await expect(api.status()).rejects.toMatchObject({ status: 401 });
    expect(signedOut).toHaveBeenCalledTimes(1);
  });

  it("does not sign out on other refusals", async () => {
    serve({ "GET actions": { status: 403, body: { detail: "Not permitted" } } });
    const signedOut = vi.fn();
    configure({ csrf: "", onUnauthorized: signedOut });
    await expect(api.actions()).rejects.toMatchObject({ status: 403, message: "Not permitted" });
    expect(signedOut).not.toHaveBeenCalled();
  });
});
