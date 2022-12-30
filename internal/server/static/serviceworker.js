importScripts(
  'https://storage.googleapis.com/workbox-cdn/releases/6.4.1/workbox-sw.js'
);

workbox.loadModule('workbox-strategies');

self.addEventListener("install", event => {
  console.log("Service worker installed");

  const urlsToCache = ["/", "app.js", "styles.css", "logo.svg"];
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
  if (event.request.url.endsWith('.png')) {
    const cacheFirst = new workbox.strategies.CacheFirst();
    event.respondWith(cacheFirst.handle({request: event.request}));
  }
});