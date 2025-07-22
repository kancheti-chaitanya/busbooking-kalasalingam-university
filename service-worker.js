self.addEventListener('install', (event) => {
    event.waitUntil(
      caches.open('busapp-cache').then((cache) => {
        return cache.addAll([
          '/',
          '/static/css/style.css',
          '/static/js/main.js'
          // Add other assets to cache as needed
        ]);
      })
    );
  });
  
  self.addEventListener('fetch', (event) => {
    event.respondWith(
      caches.match(event.request).then((response) => {
        return response || fetch(event.request);
      })
    );
  });
  