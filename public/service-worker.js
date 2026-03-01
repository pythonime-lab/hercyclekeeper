/*
 * Luna — Service Worker
 * ─────────────────────────────────────────────────────────────
 * Strategy: Cache-first for app shell, network-only for nothing
 * (Luna has no network calls at all — everything is local).
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

const CACHE_VERSION = "v1.0.0";
const CACHE_NAME = `luna-${CACHE_VERSION}`;

// App shell — all files that must be available offline
const APP_SHELL = ["/", "/index.html", "/manifest.json"];

self.addEventListener("install", (event) => {
  self.skipWaiting(); // activate new SW immediately
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(APP_SHELL))
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
  );
  self.clients.claim(); // take control of existing tabs
});

self.addEventListener("fetch", (event) => {
  // Only handle GET requests to same origin — no external requests
  if (event.request.method !== "GET") return;
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return;

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
