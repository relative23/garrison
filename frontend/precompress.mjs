// A Brotli and a gzip copy beside each hashed asset and each page of the build:
// the web service sends the best one a browser accepts, so no request waits for
// compression. The same input gives the same bytes, as release builds need.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { brotliCompressSync, constants, gzipSync } from "node:zlib";

const dist = join(import.meta.dirname, "dist");
const files = [
  ...["assets", "pages"].flatMap((folder) => readdirSync(join(dist, folder)).map((name) => join(dist, folder, name))),
  // index.html and its copy for each theme (prerender.mjs).
  ...readdirSync(dist)
    .filter((name) => name.endsWith(".html"))
    .map((name) => join(dist, name)),
];
for (const path of files.filter((file) => !/\.(br|gz)$/.test(file))) {
  const data = readFileSync(path);
  const params = { [constants.BROTLI_PARAM_QUALITY]: constants.BROTLI_MAX_QUALITY, [constants.BROTLI_PARAM_SIZE_HINT]: data.length };
  writeFileSync(`${path}.br`, brotliCompressSync(data, { params }));
  writeFileSync(`${path}.gz`, gzipSync(data, { level: 9 }));
}
