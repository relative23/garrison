// Render the whole interface at a path, or one view inside a signed-in page.
import { render } from "@testing-library/react";
import type { ReactNode } from "react";

import type { SessionInfo, StatusResponse } from "../../src/api/client";
import { App } from "../../src/App";
import type { ShellKind } from "../../src/components/Shell";
import { AppContext, type AppState } from "../../src/lib/context";
import { session } from "./fixtures";

/** The application as a browser opens it at `path`. */
export function openApp(path = "/admin/dashboard", shell?: ShellKind) {
  history.replaceState(null, "", path);
  return render(<App shell={shell} />);
}

/** A view with a fixed session and status, outside the session bootstrap. */
export function renderView(view: ReactNode, state: { session?: SessionInfo; status?: StatusResponse | Error | null } = {}) {
  const status = state.status ?? null;
  const value: AppState = {
    session: state.session ?? session(),
    status: {
      data: status instanceof Error ? null : status,
      error: status instanceof Error ? status : null,
      loading: false,
      reload: () => undefined,
    },
    updatePreferences: async () => undefined,
  };
  return render(<AppContext.Provider value={value}>{view}</AppContext.Provider>);
}
