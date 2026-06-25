const C="mt-f1", S=["/","/index.html","/manifest.json"];
self.addEventListener("install", e => { e.waitUntil(caches.open(C).then(c => c.addAll(S))); self.skipWaiting(); });
self.addEventListener("activate", e => { e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k=>k!==C).map(k=>caches.delete(k))))); self.clients.claim(); });
self.addEventListener("fetch", e => {
  const url = e.request.url;
  if (url.includes("/api/") || url.includes("fonts.googleapis") || url.includes("fonts.gstatic")) return;
  e.respondWith(fetch(e.request).catch(() => caches.match(e.request)));
});
