// Session and status shared by all views of one signed-in page.
import { createContext, useContext } from "react";

import type { SessionInfo, StatusResponse } from "../api/client";
import type { Resource } from "./useResource";

export interface AppState {
  session: SessionInfo;
  status: Resource<StatusResponse>;
  updatePreferences: (preferences: SessionInfo["preferences"]) => Promise<void>;
}

export const AppContext = createContext<AppState | null>(null);

export function useApp(): AppState {
  const value = useContext(AppContext);
  if (!value) throw new Error("useApp outside of a signed-in page");
  return value;
}
