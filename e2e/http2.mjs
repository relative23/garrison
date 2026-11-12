// HTTP/2 with TLS in front of the preview, as nginx serves Garrison in
// production: the browser multiplexes every request over one connection
// instead of opening at most six HTTP/1.1 connections. The certificate is made
// for this run with openssl and removed afterwards.
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import http from "node:http";
import http2 from "node:http2";
import { tmpdir } from "node:os";
import { join } from "node:path";

const HOP_BY_HOP = new Set(["connection", "keep-alive", "transfer-encoding", "upgrade", "proxy-connection"]);

/** Starts the proxy for `target` (an http://localhost origin) on `port`. */
export async function startHttp2(target, port = 18443) {
  const upstream = new URL(target);
  const folder = mkdtempSync(join(tmpdir(), "garrison-e2e-"));
  const key = join(folder, "key.pem");
  const cert = join(folder, "cert.pem");
  execFileSync(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      key,
      "-out",
      cert,
      "-days",
      "1",
      "-subj",
      "/CN=localhost",
      "-addext",
      "subjectAltName=DNS:localhost",
    ],
    { stdio: "ignore" },
  );
  const server = http2.createSecureServer({ key: readFileSync(key), cert: readFileSync(cert) });
  server.on("stream", (stream, headers) => {
    const forward = {};
    for (const [name, value] of Object.entries(headers)) if (!name.startsWith(":")) forward[name] = value;
    // The preview checks the host it was configured for.
    forward.host = upstream.host;
    const request = http.request(
      { host: upstream.hostname, port: upstream.port, method: headers[":method"], path: headers[":path"], headers: forward },
      (response) => {
        const back = { ":status": response.statusCode };
        for (const [name, value] of Object.entries(response.headers)) if (!HOP_BY_HOP.has(name)) back[name] = value;
        stream.respond(back);
        response.pipe(stream);
      },
    );
    request.on("error", () => {
      if (!stream.headersSent) stream.respond({ ":status": 502 });
      stream.end();
    });
    stream.on("error", () => request.destroy());
    stream.pipe(request);
  });
  await new Promise((resolve) => server.listen(port, "127.0.0.1", resolve));
  return {
    origin: `https://localhost:${port}`,
    close: () => {
      server.close();
      rmSync(folder, { recursive: true, force: true });
    },
  };
}
