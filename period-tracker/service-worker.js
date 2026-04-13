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

const IS_DEV =
  self.location.hostname === "localhost" ||
  self.location.hostname === "127.0.0.1";

const CACHE_VERSION = "v20260413";
const CACHE_NAME = `yourcyclekeeper-${CACHE_VERSION}`;

const ASSETS_TO_CACHE = [
  "/period-tracker/",
  "/period-tracker/index.html",
  "/period-tracker/style.css",
  "/period-tracker/style-desktop.css",
  "/period-tracker/manifest.json",
  "/period-tracker/js/script.js",
  "/period-tracker/js/indexeddb-storage.js",
  "/period-tracker/js/crypto.js",
  "/period-tracker/js/cycles.js",
  "/period-tracker/js/dateUtils.js",
  "/period-tracker/js/i18n.js",
  "/period-tracker/js/navigation.js",
  "/period-tracker/js/periodMarking.js",
  "/period-tracker/js/session.js",
  "/period-tracker/js/validators.js",
  "/icons/favicon-16x16.png",
  "/icons/favicon-32x32.png",
  "/icons/favicon-48x48.png",
  "/icons/favicon-64x64.png",
  "/icons/favicon-96x96.png",
  "/icons/favicon-128x128.png",
  "/icons/favicon-144x144.png",
  "/icons/favicon-152x152.png",
  "/icons/favicon-180x180.png",
  "/icons/favicon-192x192.png",
  "/icons/favicon-256x256.png",
  "/icons/favicon-512x512.png",
  "/icons/your_cycle_keeper_logo.png",
  "/icons/yourcyclekeeper_background.png",
  "/icons/yourcyclekeeper_calendar.svg",
  "/icons/yourcyclekeeper_pinscreen.svg",
];

self.addEventListener("install", (event) => {
  self.skipWaiting();
  if (IS_DEV) return;
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) =>
      Promise.all(
        ASSETS_TO_CACHE.map((url) =>
          cache.add(url).catch((err) => {
            console.warn(`[SW] Failed to pre-cache: ${url}`, err);
          })
        )
      )
    )
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

  // In dev, bypass browser HTTP cache so edits show immediately on reload
  if (IS_DEV) {
    event.respondWith(fetch(event.request, { cache: "no-store" }));
    return;
  }

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

  // Network-first for CSS and JS — ensures a reload always fetches fresh
  // code. Cache-Control: no-cache on the server makes this fast (ETag check),
  // and the cache fallback keeps the app usable offline.
  if (
    url.pathname.endsWith(".css") ||
    url.pathname.endsWith(".js")
  ) {
    event.respondWith(
      fetch(event.request)
        .then((response) => {
          if (response && response.status === 200 && response.type === "basic") {
            const cloned = response.clone();
            caches
              .open(CACHE_NAME)
              .then((cache) => cache.put(event.request, cloned));
          }
          return response;
        })
        .catch(() =>
          caches.match(event.request, { ignoreSearch: true })
        )
    );
    return;
  }

  // Cache-first for images and other static assets — large files that
  // rarely change; CACHE_NAME rotation on deploy keeps them fresh.
  event.respondWith(
    caches.match(event.request).then((cached) => {
      if (cached) return cached;
      return fetch(event.request).then((response) => {
        if (response && response.status === 200 && response.type === "basic") {
          const cloned = response.clone();
          caches
            .open(CACHE_NAME)
            .then((cache) => cache.put(event.request, cloned));
        }
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
