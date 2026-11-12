// The left menu, laid out like the Stalwart WebUI's: a tile floating beside
// the content, entries with rounded highlights, groups whose members hang on a
// rule, a row that switches to the Stalwart WebUI, and the sections as one
// rounded bar at the bottom.
import * as Collapsible from "@radix-ui/react-collapsible";
import { ArrowLeftRight, ChevronRight, Monitor, SlidersHorizontal, UserCircle } from "lucide-react";
import { useState } from "react";

import type { ModuleInfo } from "../api/client";
import { useTranslation } from "../i18n";
import { follow, href } from "../lib/router";
import { cn } from "../lib/utils";
import { moduleText, NAV, VIEWS, type GroupLabel } from "../modules/registry";
import { PRODUCT } from "./Brand";

const ITEM =
  "flex w-full items-center gap-2.5 whitespace-nowrap rounded-[10px] px-2.5 text-left font-medium text-muted-foreground transition-colors hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0";
/** An entry of the menu itself, and one inside a group. */
const TOP = "h-9 text-sm";
const NESTED = "h-8 text-[13px]";
const ACTIVE = "bg-accent font-semibold text-accent-foreground hover:bg-accent hover:text-accent-foreground";

const SECTIONS = [
  { view: "", label: "sections.management", icon: Monitor },
  { view: "preferences", label: "sections.settings", icon: SlidersHorizontal },
  { view: "account", label: "sections.account", icon: UserCircle },
] as const;

function ModuleLink({
  module,
  current,
  nested,
  onNavigate,
}: {
  module: ModuleInfo;
  current: string;
  nested: boolean;
  onNavigate: () => void;
}) {
  const Icon = VIEWS[module.id]?.icon;
  return (
    <a
      href={href(module.id)}
      aria-current={current === module.id ? "page" : undefined}
      className={cn(ITEM, nested ? NESTED : TOP, current === module.id && ACTIVE)}
      onClick={(event) => {
        follow(event, module.id);
        onNavigate();
      }}
    >
      {!nested && Icon && <Icon aria-hidden />}
      <span className="truncate">{moduleText(module, "label")}</span>
    </a>
  );
}

function Group({
  label,
  icon: Icon,
  modules,
  current,
  onNavigate,
}: {
  label: GroupLabel;
  icon: typeof Monitor;
  modules: ModuleInfo[];
  current: string;
  onNavigate: () => void;
}) {
  const { t } = useTranslation();
  const holds = modules.some((module) => module.id === current);
  const [open, setOpen] = useState(holds);
  // The menu stays mounted while pages change: a page opened from elsewhere,
  // such as a dashboard card or the page search, opens its group. The user
  // may close it again.
  const [shown, setShown] = useState(current);
  if (shown !== current) {
    setShown(current);
    if (holds) setOpen(true);
  }
  return (
    <Collapsible.Root open={open} onOpenChange={setOpen}>
      <Collapsible.Trigger className={cn(ITEM, TOP)}>
        <Icon aria-hidden className="h-4 w-4 shrink-0" />
        <span className="truncate">{t(label)}</span>
        <ChevronRight aria-hidden className={cn("ml-auto !size-3.5 opacity-60 transition-transform duration-200", open && "rotate-90")} />
      </Collapsible.Trigger>
      <Collapsible.Content className="my-0.5 ml-[18px] flex flex-col gap-0.5 border-l border-input pl-2">
        {modules.map((module) => (
          <ModuleLink key={module.id} module={module} current={current} nested onNavigate={onNavigate} />
        ))}
      </Collapsible.Content>
    </Collapsible.Root>
  );
}

export function Sidebar({
  modules,
  current,
  section,
  admin,
  open,
  onNavigate,
}: {
  modules: ModuleInfo[];
  current: string;
  section: string;
  admin: string | null;
  open: boolean;
  onNavigate: () => void;
}) {
  const { t } = useTranslation();
  const byId = new Map(modules.map((module) => [module.id, module]));
  return (
    <aside
      className={cn(
        "fixed bottom-3 left-3 top-16 z-30 flex w-60 flex-col overflow-hidden rounded-2xl bg-card text-card-foreground shadow-tile transition-transform md:translate-x-0",
        // Closed on a small screen it leaves with its margin.
        open ? "translate-x-0" : "-translate-x-[calc(100%+0.75rem)]",
      )}
    >
      <div className="flex-1 overflow-y-auto py-2.5 [scrollbar-width:thin]">
        <nav aria-label={PRODUCT} className="flex flex-col gap-0.5 px-2.5">
          {NAV.map((entry) => {
            if (entry.kind === "module") {
              const module = byId.get(entry.id);
              return module && <ModuleLink key={module.id} module={module} current={current} nested={false} onNavigate={onNavigate} />;
            }
            const members = entry.modules.flatMap((id) => byId.get(id) ?? []);
            return (
              members.length > 0 && (
                <Group
                  key={entry.label}
                  label={entry.label}
                  icon={entry.icon}
                  modules={members}
                  current={current}
                  onNavigate={onNavigate}
                />
              )
            );
          })}
        </nav>
      </div>
      {admin && (
        // Same tab on purpose: the Stalwart WebUI keeps its sign-in per tab.
        <div className="border-t px-2.5 py-2">
          <a href={admin} className={cn(ITEM, TOP)}>
            <ArrowLeftRight aria-hidden />
            <span className="truncate">{t("nav.switchToStalwart")}</span>
          </a>
        </div>
      )}
      <div className={cn("m-2.5 flex items-center gap-0.5 rounded-full bg-muted p-1", admin && "mt-0")}>
        {SECTIONS.map((item) => (
          <a
            key={item.label}
            href={href(item.view || modules[0]?.id || "dashboard")}
            title={t(item.label)}
            aria-label={t(item.label)}
            aria-current={section === item.view ? "page" : undefined}
            className={cn(
              "flex h-8 flex-1 items-center justify-center rounded-full text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring [&_svg]:size-4",
              section === item.view && "bg-card text-foreground shadow-tile",
            )}
            onClick={(event) => {
              follow(event, item.view || modules[0]?.id || "dashboard");
              onNavigate();
            }}
          >
            <item.icon aria-hidden />
          </a>
        ))}
      </div>
    </aside>
  );
}
