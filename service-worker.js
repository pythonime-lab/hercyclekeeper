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

// Handle messages from the app (for notification scheduling)
self.addEventListener("message", (event) => {
  if (event.data.type === "SCHEDULE_NOTIFICATION") {
    console.log("Service Worker received notification schedule request");
    // Store for periodic background sync
    localStorage.setItem(
      "luna_notify_pending",
      JSON.stringify(event.data.data)
    );
  }
});

// Check if it's time to show a notification
async function checkAndShowNotification() {
  const pending = localStorage.getItem("luna_notify_pending");
  if (!pending) return;

  try {
    const data = JSON.parse(pending);
    const notifyDate = new Date(data.date);
    const now = new Date();

    // If notification time has arrived and hasn't been shown in this session
    if (now >= notifyDate && notifyDate.toDateString() === now.toDateString()) {
      const lastShown = localStorage.getItem("luna_notify_shown_date");
      if (lastShown !== now.toDateString()) {
        await self.registration.showNotification("Period Coming Soon", {
          body: `Your period is expected in ${data.daysBefore} day${
            data.daysBefore > 1 ? "s" : ""
          }.`,
          icon: "/luna-cycle/icons/icon-192.png",
          badge: "/luna-cycle/icons/icon-192.png",
          tag: "luna-period-notification",
          requireInteraction: true,
        });
        localStorage.setItem("luna_notify_shown_date", now.toDateString());
      }
    }
  } catch (err) {
    console.warn("Failed to check/show notification:", err);
  }
}

// Check on activation
self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      await checkAndShowNotification();
      self.clients.claim();
    })()
  );
});

// Handle notification clicks
self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil(
    clients.matchAll({ type: "window" }).then((clientList) => {
      // Focus existing window if open
      for (let client of clientList) {
        if (client.url === "/" || client.url.includes("luna-cycle"))
          return client.focus();
      }
      // Open new window if not already open
      if (clients.openWindow) {
        return clients.openWindow("/luna-cycle/");
      }
    })
  );
});
