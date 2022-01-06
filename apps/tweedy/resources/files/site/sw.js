var CACHE_NAME = 'tweedy-cache';
var urlsToCache = [
  'images/kevin-francis.jpg'
  //'https://tailwindcss.com/_next/static/media/kevin-francis.c9970f19128315df0cfda2b4f54eb981.jpg'
];
var counter = 1;

self.addEventListener('install', (event) => {
  console.log('sw.js: install done');
  self.skipWaiting();
  // Perform install steps
  // event.waitUntil(
  //    //fetch('http://users.csc.calpoly.edu/~jdalbey/TheLastWebPage.html', {mode:'no-cors'})
  //    //.then(response => response.json())
  //    //.then(data => console.log(data))
  //    caches.open(CACHE_NAME)
  //      .then(function(cache) {
  //        return cache.addAll(urlsToCache);
  //      })
  // );
});
self.addEventListener('activate', event => {
  console.log('sw.js: activate done => self.clients.claim()');
  event.waitUntil(self.clients.claim());
  // function fetchkevin() {
  //   console.log('fetchkevin called');
  //   fetch('https://news.ycombinator.com/').then(response => {
  //     const reader = response.body.getReader();
  //     reader.read().then(({done, value}) => {
  //       console.log(new TextDecoder("utf-8").decode(value));
  //     });
  //   });
  // }
  // console.log('activated => ready to handle fetches!');
  //setTimeout(2000, fetchkevin);
  // event.waitUntil(
  //   //fetch('sw.js')
  //   fetch('https://fetch-progress.anthum.com/sw-basic/sw-simple.js')
  //    .then(response => {
  //       const reader = response.body.getReader();
  //       reader.read().then(({done, value}) => {
  //         if (done) {
  //           console.log('done');
  //         }
  //         console.log('readed: ' + value.byteLength);
  //         console.log('data: ' + new TextDecoder("utf-8").decode(value));
  //       });
  //    })
  //    .then(data => console.log('data: ' + data))
  // );
});
self.addEventListener('fetch', (event) => {
  console.log('sw.js: fetch');
  event.respondWith(
    caches.match(event.request)
      .then(function(response) {
        // Cache hit - return response
        console.log('fetch: cache hit, returning from cache');
        if (response) {
          return response;
        }
        console.log('fetch: not cache hit, fetching from the internet');
        return fetch(event.request);
      }
    )
  );
});

self.addEventListener('message', function(event) {
  //const decoder = new TextDecoder("utf-8");
  //const view = new Uint8Array(event.data.arrayBuffer);
  //const text = decoder.decode(view)
  //console.log('sw.js received message: (' + event.data.size + ') => \'' + text + '\'');
  console.log('sw.js received message: \'' + event.data + '\'');
  var promise = event.ports[0].postMessage('Pipa, Rio Grande do Norte ' + counter);
  
  // var promise = self.clients.matchAll()
  // .then(function(clientList) { 
  //   var senderID = event.source.id;

  //   clientList.forEach(function(client) { 
  //     client.postMessage({
  //       client: senderID,
  //       message: "hello. this is message " + counter//event.data
  //     });
  //   });
  // });
  if (event.waitUntil) {
    event.waitUntil(promise);
  }
  counter++;
});