// Writes one HTML file per page into dist/pages: the built index.html with what
// the page shows before the session is known already drawn into it
// (src/prerender.tsx), so the first paint needs no script, its stylesheet
// inline, so it needs no second request either, and with its view's chunk and
// first requests started at once. The web service picks the file by path and by
// whether the visitor has a session, and allows the stylesheet by its hash.
//
// Each page of a signed-in user, and the index, is written once more for each
// theme a user can choose (`logs.dark.html` beside `logs.html`), with <html>
// marked as the interface marks it (src/lib/theme.ts): the web service sends
// the one of the user's theme, so the first paint has it; the plain page
// follows the system. The sign-in page knows nobody's choice and has none.
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const dist = join(import.meta.dirname, "dist");
const bundle = join(import.meta.dirname, "node_modules", ".prerender");
const { FIRST, frame, pages, signIn } = await import(pathToFileURL(join(bundle, "prerender.js")).href);
const manifest = JSON.parse(readFileSync(join(dist, ".vite", "manifest.json"), "utf8"));
const index = readFileSync(join(dist, "index.html"), "utf8");
const root = '<div id="root"></div>';
if (!index.includes(root)) throw new Error("dist/index.html has no empty root element");
const sheet = index.match(/<link rel="stylesheet" crossorigin href="\/admin\/(assets\/[^"]+\.css)">/);
if (!sheet) throw new Error("dist/index.html links no stylesheet");
const css = readFileSync(join(dist, sheet[1]), "utf8");
if (css.includes("</style")) throw new Error("the stylesheet cannot stand inside <style>");

/** The files a view's chunk loads, without those index.html loads already. */
function chunks(module) {
  const entry = Object.values(manifest).find((item) => item.isDynamicEntry && item.name === module);
  if (!entry) throw new Error(`no chunk for ${module}`);
  const files = new Set();
  const add = (item) => {
    if (item.isEntry || files.has(item.file) || index.includes(item.file)) return;
    files.add(item.file);
    for (const key of item.imports ?? []) add(manifest[key]);
  };
  add(entry);
  return [...files];
}

function page(shell, markup, first) {
  const links = first
    ? [
        ...chunks(first.module).map((file) => `<link rel="modulepreload" crossorigin href="/admin/${file}">`),
        ...first.requests.map((path) => `<link rel="preload" href="/api/${path}" as="fetch">`),
      ]
    : [];
  // Functions as replacements: a "$" in the stylesheet or the markup stays as it is.
  return index
    .replace(sheet[0], () => `<style>${css}</style>`)
    .replace("</head>", () => `${links.join("")}</head>`)
    .replace(root, () => `<div id="root" data-shell="${shell}">${markup}</div>`);
}

const THEMES = ["light", "dark"];
const html = '<html lang="en">';
if (index.split(html).length !== 2) throw new Error(`dist/index.html has no single ${html}`);
/** `text` with <html> marked for `theme`. */
const themed = (text, theme) => text.replace(html, () => `<html lang="en" class="${theme}">`);

mkdirSync(join(dist, "pages"), { recursive: true });
for (const view of pages) {
  const drawn = page("frame", frame(view), FIRST[view]);
  writeFileSync(join(dist, "pages", `${view}.html`), drawn);
  for (const theme of THEMES) writeFileSync(join(dist, "pages", `${view}.${theme}.html`), themed(drawn, theme));
}
writeFileSync(join(dist, "pages", "sign-in.html"), page("sign-in", signIn(), null));
for (const theme of THEMES) writeFileSync(join(dist, `index.${theme}.html`), themed(index, theme));
rmSync(bundle, { recursive: true, force: true });
rmSync(join(dist, ".vite"), { recursive: true, force: true });
