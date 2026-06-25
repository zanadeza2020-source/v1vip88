const C="mt-f1",S=["/","/index.html","/manifest.json"];
self.addEventListener("install",e=>{e.waitUntil(caches.open(C).then(c=>c.addAll(S)));self.skipWaiting();});
self.addEventListener("activate",e=>{e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==C).map(k=>caches.delete(k)))));self.clients.claim();});
self.addEventListener("fetch",e=>{if(e.request.url.includes("/api/"))return;e.respondWith(fetch(e.request).catch(()=>caches.match(e.request)));});
