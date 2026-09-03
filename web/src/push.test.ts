import { describe, expect, it } from "vitest";
import { decodeApplicationServerKey, serializePushSubscription, supportsBackgroundPush } from "./push";

describe("background push protocol", () => {
  it("decodes an unpadded URL-safe application-server key", () => {
    expect([...decodeApplicationServerKey("AQID-v8")]).toEqual([1, 2, 3, 250, 255]);
  });

  it("serializes only the standard endpoint and encryption keys", () => {
    const subscription = {
      toJSON: () => ({
        endpoint: "https://push.example.invalid/capability",
        expirationTime: null,
        keys: { auth: "auth-key", p256dh: "public-key" },
      }),
    } as unknown as PushSubscription;
    expect(serializePushSubscription(subscription)).toEqual({
      endpoint: "https://push.example.invalid/capability",
      expirationTime: null,
      keys: { auth: "auth-key", p256dh: "public-key" },
    });
  });

  it("rejects incomplete browser subscriptions", () => {
    const subscription = { toJSON: () => ({ endpoint: "https://push.example.invalid/capability", keys: {} }) } as unknown as PushSubscription;
    expect(() => serializePushSubscription(subscription)).toThrow("incomplete");
  });

  it("reports no browser support in the test runtime", () => {
    expect(supportsBackgroundPush()).toBe(false);
  });
});
