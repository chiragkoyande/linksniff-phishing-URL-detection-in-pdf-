// Service worker for ThreatVision  extension

// Cache name for storing extension resources
const CACHE_NAME = 'ThreatVision-extension-cache-v1';
const RESOURCES = [
  'popup.html',
  'popup.js',
  'styles.css',
  'icons/icon16.png',
  'icons/icon48.png',
  'icons/icon128.png',
  'pdf-viewer.html',
  'pdf-highlighter.js',
  'content-script.js',
  'report.html',
  'url-scanner.html',
  'url-scanner.js'
];

// Install event handler
self.addEventListener('install', (event) => {
  console.log('Service Worker installing...');
  // Skip waiting to activate the new service worker immediately
  self.skipWaiting();
});

// Activate event handler
self.addEventListener('activate', (event) => {
  console.log('Service Worker activating...');
  // Claim clients to ensure the service worker takes control immediately
  event.waitUntil(clients.claim());
});

// Fetch event handler
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  
  // Only handle requests from our extension
  if (!url.href.startsWith(self.location.origin)) {
    return;
  }

  event.respondWith(
    (async () => {
      try {
        // Try to fetch from network first
        const response = await fetch(event.request);
        if (response.ok) {
          return response;
        }
      } catch (error) {
        console.warn('Network fetch failed, falling back to extension resources:', error);
      }

      // If network fetch fails, try to serve from extension resources
      const resource = url.pathname.substring(1);
      if (RESOURCES.includes(resource)) {
        try {
          const extensionUrl = chrome.runtime.getURL(resource);
          const response = await fetch(extensionUrl);
          if (response.ok) {
            return response;
          }
        } catch (error) {
          console.error('Error serving extension resource:', error);
        }
      }

      // If all else fails, return a 404 response
      return new Response('Resource not found', { status: 404 });
    })()
  );
});

// Message event handler
self.addEventListener('message', (event) => {
  console.log('Message received in service worker:', event.data);
  
  if (event.data && event.data.type === 'INIT_EXTENSION') {
    console.log('Initializing extension...');
    // Could perform additional setup here
  }
});

// Import background.js functionality
importScripts('background.js');