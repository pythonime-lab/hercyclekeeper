/*
 * Your Cycle Keeper — Service Worker
 * ─────────────────────────────────────────────────────────────
 * Strategy: Cache-first for app shell, network-only for nothing
 * (Your Cycle Keeper has no network calls at all — everything is local).
 *
 * Versioned cache: bump CACHE_VERSION when deploying updates
 * so stale caches are automatically purged on activation.
 *
 * Security notes:
 *   • No external URLs are ever fetched or cached
 *   • Cache is scoped to this origin only
 *   • fetch handler only responds to same-origin requests
 */

"use strict";

const CACHE_VERSION = "v20260308c";
const CACHE_NAME = `yourcyclekeeper-${CACHE_VERSION}`;

self.addEventListener("install", (event) => {
  self.skipWaiting(); // activate new SW immediately
  // Delete all old caches on install
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.map((k) => caches.delete(k))))
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))
        )
      )
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  // Only handle GET requests to same origin — no external requests
  if (event.request.method !== "GET") return;
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return;

  // Network-first strategy for HTML to ensure updates
  if (
    event.request.headers.get("accept")?.includes("text/html") ||
    url.pathname === "/" ||
    url.pathname === "/index.html"
  ) {
    event.respondWith(
      fetch(event.request)
        .then((response) => {
          if (
            response &&
            response.status === 200 &&
            response.type === "basic"
          ) {
            const cloned = response.clone();
            caches
              .open(CACHE_NAME)
              .then((cache) => cache.put(event.request, cloned));
          }
          return response;
        })
        .catch(() => {
          // Fallback to cache if network fails
          return caches.match(event.request);
        })
    );
    return;
  }

  // Cache-first for other assets (CSS, JS, images)
  event.respondWith(
    caches.match(event.request).then((cached) => {
      if (cached) return cached;
      // Not in cache: fetch and cache for future use
      return fetch(event.request).then((response) => {
        if (!response || response.status !== 200 || response.type !== "basic") {
          return response;
        }
        const cloned = response.clone();
        caches
          .open(CACHE_NAME)
          .then((cache) => cache.put(event.request, cloned));
        return response;
      });
    })
  );
});

// Handle notification clicks
self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil(
    clients.matchAll({ type: "window" }).then((clientList) => {
      // Focus existing window if open
      for (let client of clientList) {
        if (client.url === "/" || client.url.includes("yourcyclekeeper"))
          return client.focus();
      }
      // Open new window if not already open
      if (clients.openWindow) {
        return clients.openWindow("/");
      }
    })
  );
});
