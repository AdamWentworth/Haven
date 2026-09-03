export interface SerializedPushSubscription {
  endpoint: string;
  expirationTime: number | null;
  keys: { auth: string; p256dh: string };
}

export function normalizePushDestinationLabel(value: string) {
  const label = value.trim();
  if (!label) throw new Error("Give this notification destination a recognizable name.");
  return label;
}

export function decodeApplicationServerKey(value: string) {
  const padding = "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(value.replaceAll("-", "+").replaceAll("_", "/") + padding);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function serializePushSubscription(subscription: PushSubscription): SerializedPushSubscription {
  const value = subscription.toJSON();
  if (!value.endpoint || !value.keys?.auth || !value.keys?.p256dh) throw new Error("The browser returned an incomplete push subscription.");
  return {
    endpoint: value.endpoint,
    expirationTime: value.expirationTime ?? null,
    keys: { auth: value.keys.auth, p256dh: value.keys.p256dh },
  };
}

export function supportsBackgroundPush() {
  return typeof window !== "undefined"
    && "Notification" in window
    && "serviceWorker" in navigator
    && "PushManager" in window;
}
