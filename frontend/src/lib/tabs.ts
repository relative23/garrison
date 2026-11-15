// The tabs of one browser share its session cookie. A tab that signs in, signs
// out or saves settings tells the others, which then read the session again.
// The message carries nothing: what a tab shows comes from the server alone.
const CHANNEL = "garrison-session";

let channel: BroadcastChannel | null = null;
let listeners = 0;

/** Tell the other tabs that the session may have changed, through the
 * channel this tab listens on, which the interface holds open while it runs.
 * A channel delivers to the others, so this tab does not hear itself. */
export function announce(): void {
  channel?.postMessage("changed");
}

/** Call `heard` whenever another tab announces a change, until the returned
 * function is called. A browser without channels hears nothing; its tabs
 * still read the session again when they are shown. */
export function listen(heard: () => void): () => void {
  if (typeof BroadcastChannel !== "function") return () => undefined;
  channel ??= new BroadcastChannel(CHANNEL);
  const open = channel;
  const handler = () => heard();
  open.addEventListener("message", handler);
  listeners += 1;
  return () => {
    open.removeEventListener("message", handler);
    listeners -= 1;
    if (listeners === 0) {
      open.close();
      channel = null;
    }
  };
}
