// The interface side of crates/core/src/modules.rs: one icon and one view per module, and
// the menu that groups them like the Stalwart WebUI does. Names, descriptions
// and intros are in i18n/en.json under modules.<id>.
// tests/registry.test.ts fails if these lists and the server's registry differ.
import {
  BellRing,
  DatabaseBackup,
  Globe,
  LayoutDashboard,
  Mails,
  MailWarning,
  Network,
  ScrollText,
  Send,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Wrench,
  type LucideIcon,
} from "lucide-react";
import { lazy, type ComponentType } from "react";

import type { ModuleInfo } from "../api/client";
import { i18n } from "../i18n";
import en from "../i18n/en.json";

/** A view in a chunk of its own, so a page loads its code and not every page's.
 * `preload` fetches the chunk before the first render: the page that opens with
 * the view then renders it at once. Through Suspense it would show a fallback
 * first, and React holds content that replaces a fallback back for a moment. */
export interface Chunk<P> {
  lazy: ComponentType<P>;
  loaded: ComponentType<P> | null;
  preload: () => Promise<void>;
}

function chunk<P extends object>(load: () => Promise<ComponentType<P>>): Chunk<P> {
  const entry: Chunk<P> = {
    lazy: lazy(async () => ({ default: await load() })),
    loaded: null,
    preload: async () => {
      entry.loaded = await load();
    },
  };
  return entry;
}

/** A chunk's view: rendered directly once preloaded, else through Suspense. */
export function ChunkView<P extends object>({ chunk: view, props }: { chunk: Chunk<P>; props: P }) {
  const View = view.loaded ?? view.lazy;
  return <View {...props} />;
}

export interface ViewProps {
  moduleId: string;
  detail: string | null;
}

const actions = chunk<ViewProps>(() => import("./Actions").then((m) => m.Actions));
const attacks = chunk<ViewProps>(() => import("./Attacks").then((m) => m.Attacks));
const dashboard = chunk<ViewProps>(() => import("./Dashboard").then((m) => m.Dashboard));
const deliveries = chunk<ViewProps>(() => import("./Deliveries").then((m) => m.Deliveries));
const logs = chunk<ViewProps>(() => import("./Logs").then((m) => m.Logs));
const sessions = chunk<ViewProps>(() => import("./Sessions").then((m) => m.Sessions));
const statusPage = chunk<ViewProps>(() => import("./StatusPage").then((m) => m.StatusPage));

export interface ModuleView {
  icon: LucideIcon;
  chunk: Chunk<ViewProps>;
}

export const VIEWS: Record<string, ModuleView> = {
  dashboard: { icon: LayoutDashboard, chunk: dashboard },
  services: { icon: Server, chunk: statusPage },
  antivirus: { icon: ShieldCheck, chunk: statusPage },
  spam: { icon: MailWarning, chunk: statusPage },
  attacks: { icon: ShieldAlert, chunk: attacks },
  deliveries: { icon: Send, chunk: deliveries },
  sessions: { icon: Network, chunk: sessions },
  logs: { icon: ScrollText, chunk: logs },
  backups: { icon: DatabaseBackup, chunk: statusPage },
  alerts: { icon: BellRing, chunk: statusPage },
  dns_tls: { icon: Globe, chunk: statusPage },
  actions: { icon: Wrench, chunk: actions },
};

/** The views of the Settings and Account sections. */
export const PAGE_VIEWS = {
  preferences: chunk(() => import("./Preferences").then((m) => m.Preferences)),
  account: chunk(() => import("./Account").then((m) => m.Account)),
};

/** Loads the code of the view at `view`, a module or a section page. */
export function preloadView(view: string): Promise<void> {
  if (isPage(view)) return PAGE_VIEWS[view].preload();
  return VIEWS[view]?.chunk.preload() ?? Promise.resolve();
}

type ModuleId = keyof typeof en.modules;

function known(id: string): id is ModuleId {
  return Object.hasOwn(en.modules, id);
}

/** A module's name, description or intro (shown under the page title) in the
 * interface language. A module this build does not know keeps the server's text. */
export function moduleText(module: ModuleInfo, part: "label" | "description" | "intro"): string {
  if (known(module.id)) return i18n.t(`modules.${module.id}.${part}`);
  return part === "intro" ? "" : module[part];
}

/** Pages that are not modules: the Settings and Account sections. */
export const PAGES = { preferences: "sections.settings", account: "sections.account" } as const;

export function isPage(view: string): view is keyof typeof PAGES {
  return Object.hasOwn(PAGES, view);
}

/** A page's title and intro as its frame shows them before the session is
 * known; the session's own texts for the same page are the same. */
export function pageText(view: string): { title: string; intro: string; section: string } {
  if (isPage(view)) return { title: i18n.t(PAGES[view]), intro: "", section: view };
  if (known(view)) return { title: i18n.t(`modules.${view}.label`), intro: i18n.t(`modules.${view}.intro`), section: "" };
  return { title: "", intro: "", section: "" };
}

export type GroupLabel = "nav.protection" | "nav.mailFlow";

export type NavEntry = { kind: "module"; id: string } | { kind: "group"; label: GroupLabel; icon: LucideIcon; modules: string[] };

/** The menu. Groups open like Stalwart's; their entries carry no icon. */
export const NAV: NavEntry[] = [
  { kind: "module", id: "dashboard" },
  { kind: "module", id: "services" },
  { kind: "group", label: "nav.protection", icon: Shield, modules: ["antivirus", "spam", "attacks"] },
  { kind: "group", label: "nav.mailFlow", icon: Mails, modules: ["deliveries", "sessions", "logs"] },
  { kind: "module", id: "backups" },
  { kind: "module", id: "alerts" },
  { kind: "module", id: "dns_tls" },
  { kind: "module", id: "actions" },
];
