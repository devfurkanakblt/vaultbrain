import "@testing-library/jest-dom/vitest";

// Node 22/jsdom can disable its origin-backed storage when no persistent
// localstorage file is configured. Desktop tests only need the Web Storage
// contract, so provide a small in-memory implementation in that environment.
if (typeof globalThis.localStorage === "undefined") {
  const values = new Map<string, string>();
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: {
      get length() { return values.size; },
      clear() { values.clear(); },
      getItem(key: string) { return values.has(String(key)) ? values.get(String(key))! : null; },
      key(index: number) { return [...values.keys()][index] ?? null; },
      removeItem(key: string) { values.delete(String(key)); },
      setItem(key: string, value: string) { values.set(String(key), String(value)); },
    },
  });
}

class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}

Object.defineProperty(globalThis, "ResizeObserver", {
  configurable: true,
  value: ResizeObserverStub,
});

// jsdom performs no layout, so windowed lists would measure a zero-height
// viewport and render nothing. Give every element a realistic scroll height.
Object.defineProperty(HTMLElement.prototype, "clientHeight", {
  configurable: true,
  get() {
    return 600;
  },
});
