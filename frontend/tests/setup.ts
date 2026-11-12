// Browser features jsdom leaves out but the interface uses: the native
// <dialog>, matchMedia for the system theme, and ResizeObserver and
// IntersectionObserver for the charts and tables.
HTMLDialogElement.prototype.showModal = function showModal() {
  this.setAttribute("open", "");
};
HTMLDialogElement.prototype.close = function close() {
  this.removeAttribute("open");
};

globalThis.matchMedia = (query: string) =>
  ({
    matches: false,
    media: query,
    onchange: null,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    addListener: () => undefined,
    removeListener: () => undefined,
    dispatchEvent: () => false,
  }) satisfies MediaQueryList;

globalThis.ResizeObserver = class {
  observe() {}
  unobserve() {}
  disconnect() {}
};

// Everything is on screen: a chart draws as soon as it is observed.
globalThis.IntersectionObserver = class {
  constructor(private readonly callback: IntersectionObserverCallback) {}
  observe(target: Element) {
    this.callback([{ isIntersecting: true, target } as IntersectionObserverEntry], this as unknown as IntersectionObserver);
  }
  unobserve() {}
  disconnect() {}
} as unknown as typeof IntersectionObserver;

afterEach(() => {
  vi.useRealTimers();
  history.replaceState(null, "", "/admin/");
  document.documentElement.className = "";
});
