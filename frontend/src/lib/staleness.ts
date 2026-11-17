// The status as it reads now. The server gives each observation its age when
// it answers, and marks it stale; while no newer answer arrives (the broker
// is away, the network is down, the computer sleeps), what it called current
// grows old on the page. Its age at the answer plus the time the page has
// waited since, on the page's clock, is its age now.
import { useMemo } from "react";

import type { StatusResponse } from "../api/client";
import { elapsed, usePageTime } from "./clock";
import type { Resource } from "./useResource";

/** `status` with each observation's age as it is now, and every observation
 * marked stale that has outlived its `maxAge` since the answer arrived. */
export function useCurrentStatus(status: Resource<StatusResponse>): Resource<StatusResponse> {
  const now = usePageTime();
  const { data, receivedAt } = status;
  const current = useMemo(() => {
    if (!data || receivedAt === null) return data;
    const waited = elapsed(receivedAt, now) / 1000;
    return {
      ...data,
      observations: data.observations.map((item) => {
        // One whose time cannot be read has no age, and is stale already.
        if (item.age === null) return item;
        const age = item.age + waited;
        return { ...item, age, stale: item.stale || age > item.maxAge };
      }),
    };
  }, [data, receivedAt, now]);
  return current === data ? status : { ...status, data: current };
}
