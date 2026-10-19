import { test as base, expect } from "@playwright/test";

// Page-specific routes supply synthetic API responses. Anything they do not
// handle reaches this context guard, which cannot contact a backend or device.
export const test = base.extend({
  context: async ({ context, baseURL }, use) => {
    const origin = new URL(baseURL).origin;
    const unexpectedRequests = [];
    await context.route("**/*", async route => {
      const url = new URL(route.request().url());
      if (url.origin === origin && !/^\/api(?:\/|$)/.test(url.pathname)) {
        return route.continue();
      }
      unexpectedRequests.push(`${route.request().method()} ${url.href}`);
      await route.abort("blockedbyclient");
    });
    // Vite HMR is unnecessary in regression runs; no WebSocket may escape.
    await context.routeWebSocket("**/*", socket => socket.close());
    await use(context);
    expect(unexpectedRequests, "Browser requests must use explicit API fixtures and the local frontend").toEqual([]);
  }
});

export { expect };
