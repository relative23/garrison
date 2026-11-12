// "Search pages" in the header, like the Stalwart WebUI: Ctrl+K opens a list of
// the pages you may open, filtered as you type. A native <dialog> keeps focus
// handling in the browser and needs no injected styles. Escape closes it, and
// so does a press beside it.
import { Search } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent, type PointerEvent } from "react";

import type { ModuleInfo } from "../api/client";
import { useTranslation } from "../i18n";
import { navigate } from "../lib/router";
import { moduleText, VIEWS } from "../modules/registry";
import { Input } from "./ui/input";

export function PageSearch({ modules }: { modules: ModuleInfo[] }) {
  const { t } = useTranslation();
  const dialog = useRef<HTMLDialogElement>(null);
  const [query, setQuery] = useState("");
  const open = () => {
    setQuery("");
    dialog.current?.showModal();
  };
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        open();
      }
    };
    addEventListener("keydown", onKey);
    return () => removeEventListener("keydown", onKey);
  }, []);
  const needle = query.trim().toLowerCase();
  const pages = [
    ...modules.map((module) => ({ id: module.id, label: moduleText(module, "label"), description: moduleText(module, "description") })),
    { id: "preferences", label: t("sections.settings"), description: t("pageSearch.settingsDescription") },
    { id: "account", label: t("sections.account"), description: t("pageSearch.accountDescription") },
  ].filter((page) => !needle || `${page.label} ${page.description}`.toLowerCase().includes(needle));
  const go = (id: string) => {
    dialog.current?.close();
    navigate(id);
  };
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (pages[0]) go(pages[0].id);
  };
  // A press on the backdrop reaches the dialog itself, outside its box.
  const dismiss = (event: PointerEvent<HTMLDialogElement>) => {
    const box = event.currentTarget.getBoundingClientRect();
    const outside = event.clientX < box.left || event.clientX > box.right || event.clientY < box.top || event.clientY > box.bottom;
    if (event.target === event.currentTarget && outside) event.currentTarget.close();
  };
  return (
    <>
      <button
        type="button"
        onClick={open}
        className="flex h-10 w-full max-w-md items-center gap-2.5 rounded-full bg-card pl-4 pr-2 text-sm text-muted-foreground shadow-tile transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
      >
        <Search aria-hidden className="h-4 w-4" />
        <span className="flex-1 text-left">{t("pageSearch.button")}</span>
        <kbd className="flex h-6 items-center rounded-full bg-muted px-2.5 font-mono text-[11px] font-medium">
          {t("pageSearch.shortcut")}
        </kbd>
      </button>
      <dialog
        ref={dialog}
        aria-label={t("pageSearch.title")}
        onPointerDown={dismiss}
        className="m-auto mt-24 w-full max-w-lg rounded-2xl bg-popover p-0 text-popover-foreground shadow-lg"
      >
        <form onSubmit={submit} className="border-b p-3">
          <Input
            autoFocus
            value={query}
            placeholder={t("pageSearch.placeholder")}
            aria-label={t("pageSearch.input")}
            onChange={(event) => setQuery(event.target.value)}
          />
        </form>
        <ul className="max-h-80 overflow-y-auto p-1">
          {pages.length === 0 && <li className="px-3 py-6 text-center text-sm text-muted-foreground">{t("pageSearch.empty")}</li>}
          {pages.map((page) => {
            const Icon = VIEWS[page.id]?.icon;
            return (
              <li key={page.id}>
                <button
                  type="button"
                  onClick={() => go(page.id)}
                  className="flex w-full items-start gap-3 rounded-md px-3 py-2 text-left text-sm hover:bg-accent focus-visible:bg-accent focus-visible:outline-none"
                >
                  {Icon ? <Icon aria-hidden className="mt-0.5 h-4 w-4 shrink-0" /> : <span className="w-4" />}
                  <span>
                    <span className="block font-medium">{page.label}</span>
                    <span className="block text-xs text-muted-foreground">{page.description}</span>
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      </dialog>
    </>
  );
}
