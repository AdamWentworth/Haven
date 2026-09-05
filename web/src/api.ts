import type { AccountAccessGrant, AccountProfile, AccountProfileInput, AuditEvent, AuthStatus, BrowserSiteReview, BrowserSiteReviewInput, BrowserSiteReviewKey, DeviceDetail, DeviceRecord, ExpectedService, ExpectedServiceInput, FindingReview, FindingReviewState, HavenAlert, ManagedApplianceStatus, ObservedListener, PasskeyInfo, PushDestination, PushNotificationStatus, RuntimeStatus, SecurityAction, SecurityActionKind, SecurityEvent, SecuritySnapshot } from "./types";
import type { SerializedPushSubscription } from "./push";

export class HavenAPIError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
    this.name = "HavenAPIError";
  }
}

async function getJSON<T>(path: string, signal?: AbortSignal, headers: Record<string, string> = {}): Promise<T> {
  const response = await fetch(path, {
    cache: "no-store",
    headers: { Accept: "application/json", ...headers },
    signal,
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => null) as { error?: string } | null;
    throw new HavenAPIError(payload?.error || `The HAVEN hub returned HTTP ${response.status}.`, response.status);
  }
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
    throw new HavenAPIError(payload?.error || `The HAVEN hub returned HTTP ${response.status}.`, response.status);
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

export const listManagedAppliances = (signal?: AbortSignal) => getJSON<ManagedApplianceStatus[]>("/api/appliances", signal);

const accountGrantHeaders = (grant: string): Record<string, string> => grant ? { "X-HAVEN-Account-Access": grant } : {};

export const listAccountProfiles = (grant: string, signal?: AbortSignal) => getJSON<AccountProfile[]>("/api/account-profiles", signal, accountGrantHeaders(grant));

export const saveAccountProfile = (profile: AccountProfileInput, grant: string) => postJSON<AccountProfile>("/api/account-profiles", profile, accountGrantHeaders(grant));

export const removeAccountProfile = (profileId: string, grant: string) => postJSON<void>(`/api/account-profiles/${encodeURIComponent(profileId)}/remove`, undefined, accountGrantHeaders(grant));

export async function unlockAccountNotebook() {
  const grant = await reauthorize("account-notebook:unlock");
  return postJSON<AccountAccessGrant>("/api/account-access/unlock", undefined, { "X-HAVEN-Reauthorization": grant });
}

export const touchAccountNotebook = (grant: string) => postJSON<AccountAccessGrant>("/api/account-access/touch", undefined, accountGrantHeaders(grant));

export const lockAccountNotebook = (grant: string) => postJSON<void>("/api/account-access/lock", undefined, accountGrantHeaders(grant));

export const getDevice = (deviceId: string, signal?: AbortSignal) =>
  getJSON<DeviceDetail>(`/api/devices/${encodeURIComponent(deviceId)}`, signal);

export const listBrowserSiteReviews = (deviceId: string, signal?: AbortSignal) => {
	const query = new URLSearchParams({ deviceId });
	return getJSON<BrowserSiteReview[]>(`/api/browser-site-reviews?${query.toString()}`, signal);
};

export const saveBrowserSiteReview = (review: BrowserSiteReviewInput) => postJSON<BrowserSiteReview>("/api/browser-site-reviews", review);

export const removeBrowserSiteReview = (review: BrowserSiteReviewKey) => postJSON<void>("/api/browser-site-reviews/remove", review);

export const getRuntimeStatus = (signal?: AbortSignal) => getJSON<RuntimeStatus>("/api/runtime", signal);

export const listEvents = (deviceId?: string, signal?: AbortSignal) => {
  const query = new URLSearchParams({ limit: "60" });
  if (deviceId) query.set("deviceId", deviceId);
  return getJSON<SecurityEvent[]>(`/api/events?${query.toString()}`, signal);
};

export const listAlerts = (signal?: AbortSignal) => getJSON<HavenAlert[]>("/api/alerts", signal);

export const getNotificationStatus = (signal?: AbortSignal) => getJSON<PushNotificationStatus>("/api/notifications", signal);

export const registerPushDestination = (subscription: SerializedPushSubscription, label: string) =>
  postJSON<PushDestination>("/api/notifications/subscribe", { subscription, label });

export const removePushDestination = (endpoint: string) =>
  postJSON<void>("/api/notifications/unsubscribe", { endpoint });

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

async function createPasskeyCredential(ceremony: Ceremony) {
  const credential = await navigator.credentials.create({ publicKey: creationOptions(ceremony.publicKey as PublicKeyCredentialCreationOptions) });
  if (!(credential instanceof PublicKeyCredential) || !(credential.response instanceof AuthenticatorAttestationResponse)) throw new Error("The passkey provider did not return a credential.");
  const response = credential.response;
  return {
    id: credential.id,
    rawId: toBase64url(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: toBase64url(response.attestationObject),
      clientDataJSON: toBase64url(response.clientDataJSON),
      transports: response.getTransports?.() || [],
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

async function getPasskeyAssertion(ceremony: Ceremony) {
  const credential = await navigator.credentials.get({ publicKey: requestOptions(ceremony.publicKey as PublicKeyCredentialRequestOptions) });
  if (!(credential instanceof PublicKeyCredential) || !(credential.response instanceof AuthenticatorAssertionResponse)) throw new Error("The passkey provider did not return an assertion.");
  const response = credential.response;
  return {
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
  };
}

export async function registerPasskey(bootstrapCode: string, label: string) {
  const ceremony = await postJSON<Ceremony>("/api/auth/register/begin", { bootstrapCode, label });
  return postJSON<{ authenticated: boolean }>("/api/auth/register/finish", await createPasskeyCredential(ceremony), { "X-HAVEN-Ceremony": ceremony.ceremonyId });
}

export async function loginWithPasskey() {
  const ceremony = await postJSON<Ceremony>("/api/auth/login/begin");
  return postJSON<{ authenticated: boolean }>("/api/auth/login/finish", await getPasskeyAssertion(ceremony), { "X-HAVEN-Ceremony": ceremony.ceremonyId });
}

export async function reauthorize(scope: string) {
  const ceremony = await postJSON<Ceremony>("/api/auth/reauthorize/begin", { scope });
  const result = await postJSON<{ reauthorizationToken: string }>("/api/auth/reauthorize/finish", await getPasskeyAssertion(ceremony), { "X-HAVEN-Ceremony": ceremony.ceremonyId });
  return result.reauthorizationToken;
}

export const listPasskeys = (signal?: AbortSignal) => getJSON<PasskeyInfo[]>("/api/passkeys", signal);

export async function addPasskey(label: string) {
  const grant = await reauthorize("passkey:add");
  const ceremony = await postJSON<Ceremony>("/api/passkeys/register/begin", { label }, { "X-HAVEN-Reauthorization": grant });
  return postJSON<PasskeyInfo>("/api/passkeys/register/finish", await createPasskeyCredential(ceremony), { "X-HAVEN-Ceremony": ceremony.ceremonyId });
}

export async function removePasskey(id: string) {
  const grant = await reauthorize(`passkey:remove:${id}`);
  return postJSON<void>("/api/passkeys/remove", { id }, { "X-HAVEN-Reauthorization": grant });
}

export const logout = () => postJSON<void>("/api/auth/logout");

export const listFindingReviews = (deviceId: string, signal?: AbortSignal) => getJSON<FindingReview[]>(`/api/finding-reviews?deviceId=${encodeURIComponent(deviceId)}`, signal);

export const saveFindingReview = (review: { deviceId: string; findingId: string; state: FindingReviewState; note: string; snoozedUntil: string | null }) => postJSON<FindingReview>("/api/finding-reviews", review);

export const listExpectedServices = (deviceId: string, signal?: AbortSignal) => getJSON<ExpectedService[]>(`/api/expected-services?deviceId=${encodeURIComponent(deviceId)}`, signal);

export const saveExpectedService = (service: ExpectedServiceInput) => postJSON<ExpectedService>("/api/expected-services", service);

export const saveExpectedServices = (deviceId: string, services: ExpectedServiceInput[]) => postJSON<ExpectedService[]>("/api/expected-services/batch", { deviceId, services });

export const removeExpectedService = (service: ExpectedService) => postJSON<void>(`/api/expected-services/${encodeURIComponent(service.id)}/remove`, { deviceId: service.deviceId });

export const listObservedListeners = (deviceId: string, signal?: AbortSignal) => getJSON<ObservedListener[]>(`/api/listener-observations?deviceId=${encodeURIComponent(deviceId)}`, signal);

export const listAuditEvents = (signal?: AbortSignal) => getJSON<AuditEvent[]>("/api/audit", signal);

export const listSecurityActions = (signal?: AbortSignal) => getJSON<SecurityAction[]>("/api/actions", signal);

export async function requestSecurityAction(kind: SecurityActionKind) {
  const grant = await reauthorize(`action:${kind}`);
  return postJSON<SecurityAction>("/api/actions", { kind }, { "X-HAVEN-Reauthorization": grant });
}

export async function revokeDevice(deviceId: string) {
  const grant = await reauthorize(`device:revoke:${deviceId}`);
  return postJSON<void>(`/api/devices/${encodeURIComponent(deviceId)}/revoke`, undefined, { "X-HAVEN-Reauthorization": grant });
}
