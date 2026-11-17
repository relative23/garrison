// The status as it reads now. The server marks an observation stale when it
// answers; while no newer answer arrives (the broker is away, the network is
// down, the computer sleeps), what it called current grows old on the page.
// Its age at the answer plus the time the page has waited since, on the
// page's clock, tells when that happens.
import { useMemo } from "react";

import type { StatusResponse } from "../api/client";
import { elapsed, usePageTime } from "./clock";
import type { Resource } from "./useResource";

/** `status` with every observation marked stale that has outlived its
 * `maxAge` since the answer arrived. */
export function useCurrentStatus(status: Resource<StatusResponse>): Resource<StatusResponse> {
  const now = usePageTime();
  const { data, receivedAt } = status;
  const current = useMemo(() => {
    if (!data || receivedAt === null) return data;
    const waited = elapsed(receivedAt, now) / 1000;
    const outlived = (age: number | null, maxAge: number) => age !== null && age + waited > maxAge;
    if (!data.observations.some((item) => !item.stale && outlived(item.age, item.maxAge))) return data;
    return {
      ...data,
      observations: data.observations.map((item) => (outlived(item.age, item.maxAge) ? { ...item, stale: true } : item)),
    };
  }, [data, receivedAt, now]);
  return current === data ? status : { ...status, data: current };
}
