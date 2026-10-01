// Service worker for NullShift's browser notifications. It only shows them and handles
// the click: phones (Android Chrome) refuse `new Notification()` from a page.
// ponytail: no push handler, so nothing arrives while the page is closed or the phone
// has suspended it; Web Push (VAPID keys + a subscription store) would add that.
self.addEventListener('install', () => self.skipWaiting())

self.addEventListener('notificationclick', e => {
  e.notification.close()
  const url = new URL(e.notification.data?.url || '/', self.location.origin).href
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(wins => {
    const win = wins.find(w => new URL(w.url).pathname === '/')
    if (!win) return self.clients.openWindow(url)
    win.postMessage({ go: new URL(url).hash })
    return win.focus()
  }))
})
