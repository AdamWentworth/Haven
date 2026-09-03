/* HAVEN's service worker handles encrypted Web Push only. It deliberately
   does not cache the authenticated application or security observations. */
self.addEventListener("push", (event) => {
  let payload = {};
  try {
    payload = event.data ? event.data.json() : {};
  } catch {
    payload = {};
  }
  const title = typeof payload.title === "string" ? payload.title.slice(0, 100) : "HAVEN needs attention";
  const body = typeof payload.body === "string" ? payload.body.slice(0, 240) : "Open HAVEN to review a new security alert.";
  const tag = typeof payload.tag === "string" ? payload.tag.slice(0, 100) : "haven-security-alert";
  event.waitUntil(self.registration.showNotification(title, {
    body,
    tag,
    renotify: true,
    data: { url: "/" },
  }));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil((async () => {
    const windows = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    for (const client of windows) {
      if (new URL(client.url).origin === self.location.origin) {
        await client.focus();
        return;
      }
    }
    await self.clients.openWindow("/");
  })());
});
