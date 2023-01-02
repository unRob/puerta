importScripts(
  'https://storage.googleapis.com/workbox-cdn/releases/6.4.1/workbox-sw.js'
);

workbox.loadModule('workbox-strategies');


self.addEventListener("install", event => {
  console.log("Service worker installed");

  const urlsToCache = ["/login", "/", "index.css", "/index.js", "/login.js"];
  event.waitUntil(
    caches.open("pwa-assets")
    .then(cache => {
        return cache.addAll(urlsToCache);
    })
  );
});

self.addEventListener("activate", event => {
  console.log("Service worker activated");
});


self.addEventListener('fetch', event => {
  if (event.request.url.endsWith('.js') || event.request.url.endsWith('.css')) {
    const cacheFirst = new workbox.strategies.CacheFirst();
    event.respondWith(cacheFirst.handle({request: event.request}));
  }
});