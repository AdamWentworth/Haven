import type { AuditEvent, AuthStatus, DeviceDetail, DeviceRecord, FindingReview, FindingReviewState, RuntimeStatus, SecurityAction, SecurityActionKind, SecurityEvent, SecuritySnapshot } from "./types";

async function getJSON<T>(path: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(path, {
    cache: "no-store",
    headers: { Accept: "application/json" },
    signal,
  });
  if (!response.ok) throw new Error(`The HAVEN hub returned HTTP ${response.status}.`);
  return (await response.json()) as T;
}

function csrfToken() {
  const prefix = "haven_csrf=";
  return document.cookie.split(";").map((part) => part.trim()).find((part) => part.startsWith(prefix))?.slice(prefix.length) || "";
}

async function postJSON<T>(path: string, body?: unknown, headers: Record<string, string> = {}): Promise<T> {
  const token = csrfToken();
  const response = await fetch(path, {
    method: "POST",
    cache: "no-store",
    credentials: "same-origin",
    headers: {
      Accept: "application/json",
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      ...(token ? { "X-HAVEN-CSRF": token } : {}),
      ...headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => null) as { error?: string } | null;
    throw new Error(payload?.error || `The HAVEN hub returned HTTP ${response.status}.`);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export async function collectSnapshot(signal?: AbortSignal): Promise<SecuritySnapshot> {
  const token = csrfToken();
  const response = await fetch("/api/security/snapshot", { method: "POST", cache: "no-store", credentials: "same-origin", headers: { Accept: "application/json", ...(token ? { "X-HAVEN-CSRF": token } : {}) }, signal });
  if (!response.ok) throw new Error(`The HAVEN hub returned HTTP ${response.status}.`);
  return (await response.json()) as SecuritySnapshot;
}

export const getLatestSnapshot = (signal?: AbortSignal) => getJSON<SecuritySnapshot>("/api/security/latest", signal);

export const listDevices = (signal?: AbortSignal) => getJSON<DeviceRecord[]>("/api/devices", signal);

export const getDevice = (deviceId: string, signal?: AbortSignal) =>
  getJSON<DeviceDetail>(`/api/devices/${encodeURIComponent(deviceId)}`, signal);

export const getRuntimeStatus = (signal?: AbortSignal) => getJSON<RuntimeStatus>("/api/runtime", signal);

export const listEvents = (deviceId?: string, signal?: AbortSignal) => {
  const query = new URLSearchParams({ limit: "60" });
  if (deviceId) query.set("deviceId", deviceId);
  return getJSON<SecurityEvent[]>(`/api/events?${query.toString()}`, signal);
};

export const getAuthStatus = (signal?: AbortSignal) => getJSON<AuthStatus>("/api/auth/status", signal);

type Ceremony = { ceremonyId: string; publicKey: PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions };

function fromBase64url(value: string): ArrayBuffer {
  const padding = "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(value.replaceAll("-", "+").replaceAll("_", "/") + padding);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0)).buffer;
}

function toBase64url(value: ArrayBuffer | null): string | null {
  if (value === null) return null;
  const bytes = new Uint8Array(value);
  let binary = "";
  bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function creationOptions(value: PublicKeyCredentialCreationOptions) {
  return {
    ...value,
    challenge: fromBase64url(value.challenge as unknown as string),
    user: { ...value.user, id: fromBase64url(value.user.id as unknown as string) },
    excludeCredentials: value.excludeCredentials?.map((item) => ({ ...item, id: fromBase64url(item.id as unknown as string) })),
  } satisfies PublicKeyCredentialCreationOptions;
}

function requestOptions(value: PublicKeyCredentialRequestOptions) {
  return {
    ...value,
    challenge: fromBase64url(value.challenge as unknown as string),
    allowCredentials: value.allowCredentials?.map((item) => ({ ...item, id: fromBase64url(item.id as unknown as string) })),
  } satisfies PublicKeyCredentialRequestOptions;
}

export async function registerPasskey(bootstrapCode: string) {
  const ceremony = await postJSON<Ceremony>("/api/auth/register/begin", { bootstrapCode });
  const credential = await navigator.credentials.create({ publicKey: creationOptions(ceremony.publicKey as PublicKeyCredentialCreationOptions) });
  if (!(credential instanceof PublicKeyCredential) || !(credential.response instanceof AuthenticatorAttestationResponse)) throw new Error("Windows Hello did not return a passkey credential.");
  const response = credential.response;
  return postJSON<{ authenticated: boolean }>("/api/auth/register/finish", {
    id: credential.id,
    rawId: toBase64url(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: toBase64url(response.attestationObject),
      clientDataJSON: toBase64url(response.clientDataJSON),
      transports: response.getTransports?.() || [],
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  }, { "X-HAVEN-Ceremony": ceremony.ceremonyId });
}

export async function loginWithPasskey() {
  const ceremony = await postJSON<Ceremony>("/api/auth/login/begin");
  const credential = await navigator.credentials.get({ publicKey: requestOptions(ceremony.publicKey as PublicKeyCredentialRequestOptions) });
  if (!(credential instanceof PublicKeyCredential) || !(credential.response instanceof AuthenticatorAssertionResponse)) throw new Error("Windows Hello did not return a passkey assertion.");
  const response = credential.response;
  return postJSON<{ authenticated: boolean }>("/api/auth/login/finish", {
    id: credential.id,
    rawId: toBase64url(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: toBase64url(response.authenticatorData),
      clientDataJSON: toBase64url(response.clientDataJSON),
      signature: toBase64url(response.signature),
      userHandle: toBase64url(response.userHandle),
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  }, { "X-HAVEN-Ceremony": ceremony.ceremonyId });
}

export const logout = () => postJSON<void>("/api/auth/logout");

export const listFindingReviews = (deviceId: string, signal?: AbortSignal) => getJSON<FindingReview[]>(`/api/finding-reviews?deviceId=${encodeURIComponent(deviceId)}`, signal);

export const saveFindingReview = (review: { deviceId: string; findingId: string; state: FindingReviewState; note: string; snoozedUntil: string | null }) => postJSON<FindingReview>("/api/finding-reviews", review);

export const listAuditEvents = (signal?: AbortSignal) => getJSON<AuditEvent[]>("/api/audit", signal);

export const listSecurityActions = (signal?: AbortSignal) => getJSON<SecurityAction[]>("/api/actions", signal);

export const requestSecurityAction = (kind: SecurityActionKind) => postJSON<SecurityAction>("/api/actions", { kind });

export const revokeDevice = (deviceId: string) => postJSON<void>(`/api/devices/${encodeURIComponent(deviceId)}/revoke`);
