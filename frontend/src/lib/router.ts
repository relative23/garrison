// A small path router: /admin/<view>/<detail>. The web service
// answers every such path with the same page, so links can be bookmarked.
import { useEffect, useState } from "react";

const BASE = "/admin/";

export interface Route {
  view: string;
  detail: string | null;
}

export function parse(pathname: string): Route {
  const rest = pathname.startsWith(BASE) ? pathname.slice(BASE.length) : "";
  const [view = "", detail = ""] = rest.split("/").filter(Boolean).map(decodeURIComponent);
  return { view: view || "dashboard", detail: detail || null };
}

export function href(view: string, detail?: string | null): string {
  return BASE + encodeURIComponent(view) + (detail ? `/${encodeURIComponent(detail)}` : "");
}

export function navigate(view: string, detail?: string | null): void {
  const target = href(view, detail);
  if (target !== location.pathname) history.pushState(null, "", target);
  dispatchEvent(new PopStateEvent("popstate"));
}

export function useRoute(): Route {
  const [route, setRoute] = useState(() => parse(location.pathname));
  useEffect(() => {
    const update = () => setRoute(parse(location.pathname));
    addEventListener("popstate", update);
    return () => removeEventListener("popstate", update);
  }, []);
  return route;
}

/** Handle plain left clicks on internal links without a full page load. */
export function follow(event: React.MouseEvent<HTMLAnchorElement>, view: string, detail?: string | null) {
  if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
  event.preventDefault();
  navigate(view, detail);
}
