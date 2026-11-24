// A name the server sends from a set it may grow, such as a check's state,
// its evidence or a ban's reason, may be one this build does not know: on a
// page loaded before an upgrade, or with a newer service. It is shown as the
// server named it, or as Unknown, and never as the catalog's key. The sets are
// the API document's enums, and every page gets every answer with a name
// this build does not know in each of them, so a new set or a new page that
// shows one is held to the same.
import doc from "../api/openapi.json";
import en from "../src/i18n/en.json";
import { answers, DETAIL, fakeTime, PAGES, preload, visit } from "./support/pages";
import type { Call, Route } from "./support/server";

const NEWER = "newer-name";

type Schema = {
  $ref?: string;
  enum?: unknown[];
  type?: string | string[];
  properties?: Record<string, Schema>;
  items?: Schema;
  oneOf?: Schema[];
  additionalProperties?: Schema | boolean;
};

const SCHEMAS = doc.components.schemas as Record<string, Schema>;

function resolve(schema: Schema): Schema {
  return schema.$ref ? resolve(SCHEMAS[schema.$ref.split("/").at(-1) ?? ""] ?? {}) : schema;
}

/** `value` with every name from one of the document's sets replaced by one this build does not know. */
function renamed(value: unknown, given: Schema): unknown {
  const schema = resolve(given);
  if (schema.enum && typeof value === "string") return NEWER;
  if (schema.oneOf) {
    const fits = schema.oneOf.map(resolve).find((each) => (value === null ? each.type === "null" : each.type !== "null"));
    return fits ? renamed(value, fits) : value;
  }
  if (Array.isArray(value)) return value.map((item) => renamed(item, schema.items ?? {}));
  if (value !== null && typeof value === "object") {
    const extra = typeof schema.additionalProperties === "object" ? schema.additionalProperties : {};
    return Object.fromEntries(Object.entries(value).map(([key, inner]) => [key, renamed(inner, schema.properties?.[key] ?? extra)]));
  }
  return value;
}

type Operation = { responses: Record<string, { content?: Record<string, { schema: Schema }> }> };

/** The schema of the answer to "METHOD path", from the document's paths. */
function answerSchema(key: string): Schema | null {
  const [method = "", path = ""] = key.split(" ");
  for (const [template, item] of Object.entries(doc.paths as Record<string, Record<string, Operation>>)) {
    const pattern = new RegExp(`^${template.replace(/\{[^}]+\}/g, "[^/]+")}$`);
    if (!pattern.test(`/api/${path}`)) continue;
    const operation = item[method.toLowerCase()];
    const answered = Object.entries(operation?.responses ?? {}).find(([status]) => status.startsWith("2"));
    return answered?.[1].content?.["application/json"]?.schema ?? null;
  }
  return null;
}

/** Every answer of `answers()`, each with names this build does not know. */
function withNewerNames(): Record<string, Route> {
  const renamedRoutes: Record<string, Route> = {};
  for (const [key, route] of Object.entries(answers())) {
    const schema = answerSchema(key);
    renamedRoutes[key] = async (call: Call) => {
      const reply = typeof route === "function" ? await route(call) : route;
      return schema ? { ...reply, body: renamed(reply.body, schema) } : reply;
    };
  }
  return renamedRoutes;
}

/** Text as `t` gives it for a key the catalog lacks: the key itself, which
 * may follow a cell's text without a space. */
const KEY = new RegExp(`(?<![A-Za-z])(${Object.keys(en).join("|")})\\.[\\w.-]*${NEWER}`);

beforeAll(preload);
beforeEach(fakeTime);

describe("a name the server sends that this build does not know", () => {
  it("is in every set the API document names", () => {
    const sets = Object.keys(SCHEMAS).filter((name) => JSON.stringify(SCHEMAS[name]).includes('"enum"'));
    expect(sets.length).toBeGreaterThan(0);
  });

  // The checks a page shows, by their cards (tests/support/pages.ts gives each module one).
  const checks = () => [...document.querySelectorAll("[id^=obs-]")].map((card) => card.id).sort();

  it.each(PAGES)("leaves no check out of the %s page that shows it", async (page) => {
    const known = await visit(page, answers());
    const shown = checks();
    known.view.unmount();
    const newer = await visit(page, withNewerNames());
    expect(checks()).toEqual(shown);
    newer.view.unmount();
  });

  it.each([...PAGES, ...PAGES.map((page) => `${page}/${DETAIL}`)])("is never shown as a catalog key on the %s page", async (page) => {
    const { view } = await visit(page, withNewerNames());
    const text = document.body.textContent ?? "";
    view.unmount();
    expect(text.match(KEY)?.[0] ?? null).toBeNull();
  });
});
