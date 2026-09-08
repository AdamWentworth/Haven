import { useCallback, useEffect, useRef, useState } from "react";
import { HavenAPIError, addPasskey, collectSnapshot, getAuthStatus, getDevice, getLatestSnapshot, getNotificationStatus, getRuntimeStatus, getSystemDiagnostics, listAccountProfiles, listAlerts, listAuditEvents, listBrowserSiteReviews, listDevices, listEvents, listExpectedServices, listFindingReviews, listManagedAppliances, listObservedListeners, listPasskeys, listSecurityActions, lockAccountNotebook, loginWithPasskey, logout, registerPasskey, registerPushDestination, removeAccountProfile, removeBrowserSiteReview, removeExpectedService, removePasskey, removePushDestination, requestSecurityAction, runManagedApplianceDeepCheck, saveAccountProfile, saveBrowserSiteReview, saveExpectedService, saveExpectedServices, saveFindingReview, touchAccountNotebook, unlockAccountNotebook } from "./api";
import { Application } from "./application-view";
import { AuthenticationGate } from "./authentication-gate";
import { useDesktopInstall } from "./desktop-install";
import { HavenIcon } from "./icons";
import type { NetworkDeviceObservation } from "./network";
import { decodeApplicationServerKey, normalizePushDestinationLabel, serializePushSubscription, supportsBackgroundPush } from "./push";
import { useAppRoute } from "./routing";
import { AwaitingAgents } from "./system-recovery";
import type {
  AccountAccessGrant,
  AccountProfile,
  AccountProfileInput,
  AuditEvent,
  AuthStatus,
  BrowserSiteReview,
  BrowserSiteReviewInput,
  BrowserSiteReviewKey,
  DeviceRecord,
  ExpectedService,
  ExpectedServiceInput,
  FindingReview,
  FindingReviewState,
  HavenAlert,
  ManagedApplianceStatus,
  ObservedListener,
  PasskeyInfo,
  PushNotificationStatus,
  RuntimeStatus,
  SecurityAction,
  SecurityActionKind,
  SecurityEvent,
  SecurityFinding,
  SecuritySnapshot,
  SystemDiagnostics,
} from "./types";

async function loadNetworkObservations(inventory: DeviceRecord[], demoMode: boolean, signal?: AbortSignal) {
  const visible = inventory.filter((device) => device.trustState !== "revoked");
  return Promise.all(visible.map(async (device): Promise<NetworkDeviceObservation> => {
    const [detail, expectedServices, listenerObservations] = await Promise.all([
      getDevice(device.id, signal),
      demoMode ? Promise.resolve([]) : listExpectedServices(device.id, signal),
      demoMode ? Promise.resolve([]) : listObservedListeners(device.id, signal),
    ]);
    return { device, snapshot: detail.snapshot, expectedServices, listenerObservations };
  }));
}

async function latestEnrolledObservation(inventory: DeviceRecord[], preferredId: string, signal?: AbortSignal) {
  const candidates = inventory.filter((device) => device.trustState !== "revoked" && device.lastCollectedAt);
  const selected = candidates.find((device) => device.id === preferredId)
    || candidates.find((device) => device.status === "current")
    || candidates[0];
  if (!selected) return null;
  const detail = await getDevice(selected.id, signal);
  return detail.snapshot ? { id: selected.id, snapshot: detail.snapshot } : null;
}

export function App() {
  const { route, navigate } = useAppRoute();
  const desktopInstall = useDesktopInstall();
  const [authentication, setAuthentication] = useState<AuthStatus | null>(null);
  const [snapshot, setSnapshot] = useState<SecuritySnapshot | null>(null);
  const [devices, setDevices] = useState<DeviceRecord[]>([]);
  const [networkDevices, setNetworkDevices] = useState<NetworkDeviceObservation[]>([]);
  const [appliances, setAppliances] = useState<ManagedApplianceStatus[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [currentAlerts, setCurrentAlerts] = useState<HavenAlert[]>([]);
  const [reviews, setReviews] = useState<FindingReview[]>([]);
	const [browserSiteReviews, setBrowserSiteReviews] = useState<BrowserSiteReview[]>([]);
	const [expectedServices, setExpectedServices] = useState<ExpectedService[]>([]);
	const [listenerObservations, setListenerObservations] = useState<ObservedListener[]>([]);
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [actions, setActions] = useState<SecurityAction[]>([]);
  const [passkeys, setPasskeys] = useState<PasskeyInfo[]>([]);
  const [accountProfiles, setAccountProfiles] = useState<AccountProfile[]>([]);
  const [accountAccess, setAccountAccess] = useState<AccountAccessGrant | null>(null);
  const [runtime, setRuntime] = useState<RuntimeStatus | null>(null);
	const [diagnostics, setDiagnostics] = useState<SystemDiagnostics | null>(null);
  const [notificationStatus, setNotificationStatus] = useState<PushNotificationStatus | null>(null);
  const [selectedId, setSelectedId] = useState(route.deviceId || "");
  const [demoMode, setDemoMode] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [actionBusy, setActionBusy] = useState(false);
  const [deepCheckBusy, setDeepCheckBusy] = useState<string | null>(null);
  const [inventoryLoaded, setInventoryLoaded] = useState(false);
  const selectedIdRef = useRef(route.deviceId || "");
  const accountAccessRef = useRef<AccountAccessGrant | null>(null);
  const accountLastActivityRef = useRef(Date.now());
  const accountLastTouchRef = useRef(0);
  const alertsSupported = supportsBackgroundPush();
  const [alertsEnabled, setAlertsEnabled] = useState(false);

  const authenticate = useCallback(async (bootstrapCode?: string, label?: string) => {
    if (bootstrapCode === undefined) await loginWithPasskey();
    else await registerPasskey(bootstrapCode, label || "This device");
    setAuthentication(await getAuthStatus());
    setSnapshot(null);
  }, []);

  const refresh = useCallback(async (signal?: AbortSignal) => {
    setRefreshing(true);
    try {
		const [initialInventory, runtimeStatus, diagnosticReport, activity, activeAlerts, pushStatus, managedAppliances] = await Promise.all([listDevices(signal), getRuntimeStatus(signal), getSystemDiagnostics(signal), listEvents(undefined, signal), listAlerts(signal), getNotificationStatus(signal), listManagedAppliances(signal)]);
		let accounts: AccountProfile[] | null = null;
		try {
			if (runtimeStatus.demoMode) accounts = await listAccountProfiles("", signal);
			else if (accountAccessRef.current) accounts = await listAccountProfiles(accountAccessRef.current.token, signal);
		} catch (reason) {
			if (!(reason instanceof HavenAPIError) || reason.status !== 403) throw reason;
			accountAccessRef.current = null;
			setAccountAccess(null);
			accounts = [];
		}
      let inventory = initialInventory;
      let observed: { id: string; snapshot: SecuritySnapshot } | null;
      if (runtimeStatus.demoMode || runtimeStatus.localCollection) {
        const collected = await collectSnapshot(signal);
        inventory = await listDevices(signal);
        observed = { id: collected.device.deviceId || inventory.find((device) => device.trustState === "local")?.id || "", snapshot: collected };
      } else {
        observed = await latestEnrolledObservation(inventory, selectedIdRef.current, signal);
      }
      const networkObservations = await loadNetworkObservations(inventory, runtimeStatus.demoMode, signal);
      setSnapshot(observed?.snapshot || null);
      setDevices(inventory);
      setNetworkDevices(networkObservations);
      setAppliances(managedAppliances);
      setEvents(activity);
      setCurrentAlerts(activeAlerts);
      setRuntime(runtimeStatus);
		setDiagnostics(diagnosticReport);
      setNotificationStatus(pushStatus);
		if (accounts !== null) setAccountProfiles(accounts);
      setDemoMode(runtimeStatus.demoMode);
      const nextId = observed?.id || inventory.find((device) => device.status === "awaiting-first-report")?.id || "";
	  if (!runtimeStatus.demoMode && nextId) setListenerObservations(await listObservedListeners(nextId, signal));
      selectedIdRef.current = nextId;
      setSelectedId(nextId);
      setInventoryLoaded(true);
      setError(null);
    } catch (reason) {
      if (reason instanceof DOMException && reason.name === "AbortError") return;
      setError(reason instanceof Error ? reason.message : "An unexpected collection error occurred.");
    } finally {
      if (!signal?.aborted) setRefreshing(false);
    }
  }, []);

  const selectDevice = useCallback(async (deviceId: string) => {
    setRefreshing(true);
    try {
      const detail = await getDevice(deviceId);
      if (!detail.snapshot) throw new Error("This device has not submitted its first observation yet.");
      setSnapshot(detail.snapshot);
      selectedIdRef.current = deviceId;
      setSelectedId(deviceId);
      setError(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The device observation could not be loaded.");
    } finally {
      setRefreshing(false);
    }
  }, []);

  const loadControls = useCallback(async (deviceId: string, signal?: AbortSignal) => {
	const [findingReviews, siteReviews, serviceExpectations, observedListeners, recentAudit, recentActions, ownerPasskeys] = await Promise.all([
      deviceId ? listFindingReviews(deviceId, signal) : Promise.resolve([]),
	  deviceId ? listBrowserSiteReviews(deviceId, signal) : Promise.resolve([]),
	  deviceId ? listExpectedServices(deviceId, signal) : Promise.resolve([]),
	  deviceId ? listObservedListeners(deviceId, signal) : Promise.resolve([]),
      listAuditEvents(signal),
      listSecurityActions(signal),
      listPasskeys(signal),
    ]);
    setReviews(findingReviews);
	setBrowserSiteReviews(siteReviews);
	setExpectedServices(serviceExpectations);
	setListenerObservations(observedListeners);
    setAudit(recentAudit);
    setActions(recentActions);
    setPasskeys(ownerPasskeys);
  }, []);

	const refreshView = useCallback(async () => {
		try {
			await refresh();
			if (!demoMode && selectedIdRef.current) await loadControls(selectedIdRef.current);
		} catch (reason) {
			setError(reason instanceof Error ? reason.message : "HAVEN could not refresh its control metadata.");
		}
	}, [demoMode, loadControls, refresh]);

	const clearAccountAccess = useCallback(() => {
		accountAccessRef.current = null;
		setAccountAccess(null);
		setAccountProfiles([]);
	}, []);

	const unlockAccounts = useCallback(async () => {
		setActionBusy(true);
		try {
			const access = await unlockAccountNotebook();
			const profiles = await listAccountProfiles(access.token);
			accountAccessRef.current = access;
			accountLastActivityRef.current = Date.now();
			accountLastTouchRef.current = Date.now();
			setAccountAccess(access);
			setAccountProfiles(profiles);
			setAudit(await listAuditEvents());
			setError(null);
		} catch (reason) {
			clearAccountAccess();
			setError(reason instanceof Error ? reason.message : "The account notebook could not be unlocked.");
		} finally {
			setActionBusy(false);
		}
	}, [clearAccountAccess]);

	const lockAccounts = useCallback(async () => {
		const token = accountAccessRef.current?.token || "";
		clearAccountAccess();
		if (token) {
			try { await lockAccountNotebook(token); } catch { /* The local view is already locked; the server grant will expire. */ }
		}
	}, [clearAccountAccess]);

  const reviewFinding = useCallback(async (finding: SecurityFinding, state: FindingReviewState) => {
    if (!selectedId) return;
    let note = "";
    let snoozedUntil: string | null = null;
    if (state === "accepted-risk" || state === "acknowledged") {
      const entered = window.prompt(state === "accepted-risk" ? `Why are you accepting the risk for “${finding.title}”? This note stays in HAVEN's local database and is omitted from the audit summary.` : `Optional note for “${finding.title}”. It stays in HAVEN's local database and is omitted from the audit summary.`);
      if (entered === null) return;
      note = entered.trim();
      if (state === "accepted-risk" && !note) { setError("Accepting risk requires a short reason."); return; }
    }
    if (state === "snoozed") snoozedUntil = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
    try {
      await saveFindingReview({ deviceId: selectedId, findingId: finding.id, state, note, snoozedUntil });
      await Promise.all([loadControls(selectedId), listAlerts().then(setCurrentAlerts)]);
      setError(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The finding review could not be saved.");
    }
  }, [loadControls, selectedId]);

	const classifyBrowserSite = useCallback(async (review: BrowserSiteReviewInput) => {
		setActionBusy(true);
		try {
			await saveBrowserSiteReview(review);
			setBrowserSiteReviews(await listBrowserSiteReviews(review.deviceId));
			setAudit(await listAuditEvents());
			setError(null);
		} catch (reason) {
			setError(reason instanceof Error ? reason.message : "The browser site classification could not be saved.");
		} finally {
			setActionBusy(false);
		}
	}, []);

	const resetBrowserSite = useCallback(async (review: BrowserSiteReviewKey) => {
		setActionBusy(true);
		try {
			await removeBrowserSiteReview(review);
			setBrowserSiteReviews(await listBrowserSiteReviews(review.deviceId));
			setAudit(await listAuditEvents());
			setError(null);
		} catch (reason) {
			setError(reason instanceof Error ? reason.message : "The browser site classification could not be reset.");
		} finally {
			setActionBusy(false);
		}
	}, []);

	const saveServiceExpectation = useCallback(async (service: ExpectedServiceInput) => {
		setActionBusy(true);
		try {
			await saveExpectedService(service);
			const saved = await listExpectedServices(service.deviceId);
			setExpectedServices(saved);
			setNetworkDevices((current) => current.map((entry) => entry.device.id === service.deviceId ? { ...entry, expectedServices: saved } : entry));
			setCurrentAlerts(await listAlerts());
			setAudit(await listAuditEvents());
			setError(null);
		} catch (reason) {
			setError(reason instanceof Error ? reason.message : "The service expectation could not be saved.");
		} finally {
			setActionBusy(false);
		}
	}, []);

	const saveServiceBaseline = useCallback(async (services: ExpectedServiceInput[]) => {
		if (!selectedId || services.length === 0) return;
		setActionBusy(true);
		try {
			const saved = await saveExpectedServices(selectedId, services);
			setExpectedServices(saved);
			setNetworkDevices((current) => current.map((entry) => entry.device.id === selectedId ? { ...entry, expectedServices: saved } : entry));
			setCurrentAlerts(await listAlerts());
			setAudit(await listAuditEvents());
			setError(null);
		} catch (reason) {
			setError(reason instanceof Error ? reason.message : "The suggested service baseline could not be saved.");
		} finally {
			setActionBusy(false);
		}
	}, [selectedId]);

	const removeServiceExpectation = useCallback(async (service: ExpectedService) => {
		if (!window.confirm(`Remove the expected-service classification “${service.label}”? This changes HAVEN's interpretation only; it does not stop the service.`)) return;
		setActionBusy(true);
		try {
			await removeExpectedService(service);
			const saved = await listExpectedServices(service.deviceId);
			setExpectedServices(saved);
			setNetworkDevices((current) => current.map((entry) => entry.device.id === service.deviceId ? { ...entry, expectedServices: saved } : entry));
			setCurrentAlerts(await listAlerts());
			setAudit(await listAuditEvents());
			setError(null);
		} catch (reason) {
			setError(reason instanceof Error ? reason.message : "The service expectation could not be removed.");
		} finally {
			setActionBusy(false);
		}
	}, []);

  const runAction = useCallback(async (kind: SecurityActionKind) => {
    const capability = runtime?.actionCapabilities.find((item) => item.id === kind);
    const label = capability?.label || kind.replaceAll("-", " ");
    if (!window.confirm(`Request “${label}” from the ${capability?.platform || "selected"} provider? HAVEN will ask for a fresh passkey confirmation next.`)) return;
    setActionBusy(true);
    try {
      await requestSecurityAction(kind);
      const recent = await listSecurityActions();
      setActions(recent);
      setError(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The security action could not be requested.");
    } finally {
      setActionBusy(false);
    }
  }, [runtime?.actionCapabilities]);

	const runApplianceDeepCheck = useCallback(async (appliance: ManagedApplianceStatus) => {
		if (!window.confirm(`Run one read-only deep health check on “${appliance.displayName}”? This makes one pinned SSH login and may trigger the appliance's login notification.`)) return;
		setDeepCheckBusy(appliance.id);
		try {
			const updated = await runManagedApplianceDeepCheck(appliance.id);
			setAppliances((current) => current.map((item) => item.id === updated.id ? updated : item));
			setAudit(await listAuditEvents());
			setError(null);
		} catch (reason) {
			setError(reason instanceof Error ? reason.message : "The appliance deep check could not be completed.");
		} finally {
			setDeepCheckBusy(null);
		}
	}, []);

  const addOwnerPasskey = useCallback(async () => {
    const entered = window.prompt("Name this passkey so you can recognize it later (for example, Ubuntu laptop, iPhone, or security key).", "Another trusted device");
    if (entered === null || entered.trim() === "") return;
    setActionBusy(true);
    try {
      await addPasskey(entered.trim());
      setPasskeys(await listPasskeys());
      setError(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The passkey could not be added.");
    } finally {
      setActionBusy(false);
    }
  }, []);

  const removeOwnerPasskey = useCallback(async (passkey: PasskeyInfo) => {
    if (!window.confirm(`Remove the passkey “${passkey.label}”? HAVEN will first ask for a fresh confirmation from a remaining registered passkey.`)) return;
    setActionBusy(true);
    try {
      await removePasskey(passkey.id);
      setPasskeys(await listPasskeys());
      setError(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The passkey could not be removed.");
    } finally {
      setActionBusy(false);
    }
  }, []);

	const saveAccount = useCallback(async (profile: AccountProfileInput) => {
		setActionBusy(true);
		try {
			const token = accountAccessRef.current?.token;
			if (!token) throw new Error("Unlock the account notebook before editing it.");
			await saveAccountProfile(profile, token);
			setAccountProfiles(await listAccountProfiles(token));
			setAudit(await listAuditEvents());
			setError(null);
			return true;
		} catch (reason) {
			if (reason instanceof HavenAPIError && reason.status === 403) clearAccountAccess();
			setError(reason instanceof Error ? reason.message : "The account profile could not be saved.");
			return false;
		} finally {
			setActionBusy(false);
		}
	}, [clearAccountAccess]);

	const removeAccount = useCallback(async (profile: AccountProfile) => {
		if (!window.confirm(`Remove “${profile.provider} · ${profile.label}” from HAVEN? This deletes the encrypted notebook entry; it does not change the provider account.`)) return;
		setActionBusy(true);
		try {
			const token = accountAccessRef.current?.token;
			if (!token) throw new Error("Unlock the account notebook before editing it.");
			await removeAccountProfile(profile.id, token);
			setAccountProfiles(await listAccountProfiles(token));
			setAudit(await listAuditEvents());
			setError(null);
		} catch (reason) {
			if (reason instanceof HavenAPIError && reason.status === 403) clearAccountAccess();
			setError(reason instanceof Error ? reason.message : "The account profile could not be removed.");
		} finally {
			setActionBusy(false);
		}
	}, [clearAccountAccess]);

  const signOut = useCallback(async () => {
    try { await logout(); } finally {
      setAuthentication((current) => current ? { ...current, authenticated: false } : current);
      setSnapshot(null);
      setDevices([]);
      setNetworkDevices([]);
      setAppliances([]);
      setEvents([]);
      setCurrentAlerts([]);
      setReviews([]);
	  setBrowserSiteReviews([]);
	  setExpectedServices([]);
	  setListenerObservations([]);
      setAudit([]);
      setActions([]);
      setPasskeys([]);
		setAccountProfiles([]);
		accountAccessRef.current = null;
		setAccountAccess(null);
      setNotificationStatus(null);
      setAlertsEnabled(false);
      setInventoryLoaded(false);
    }
  }, []);

  const enableAlerts = useCallback(async (requestedLabel = "This browser") => {
    if (!alertsSupported) {
      setError("This browser does not support service-worker background notifications.");
      return;
    }
    if (!notificationStatus?.available || !notificationStatus.vapidPublicKey) {
      setError("The HAVEN hub has not advertised background-notification support.");
      return;
    }
    setActionBusy(true);
    try {
      const label = normalizePushDestinationLabel(requestedLabel);
      const permission = await window.Notification.requestPermission();
      if (permission !== "granted") throw new Error("Background notifications remain blocked. Change this site's notification permission in the browser to enable them.");
      const registration = await navigator.serviceWorker.register("/sw.js", { scope: "/" });
      await navigator.serviceWorker.ready;
      const existing = await registration.pushManager.getSubscription();
      const subscription = existing || await registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: decodeApplicationServerKey(notificationStatus.vapidPublicKey) });
      await registerPushDestination(serializePushSubscription(subscription), label);
      setNotificationStatus(await getNotificationStatus());
      setAlertsEnabled(true);
      setError(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "This browser could not be enabled for background alerts.");
    } finally {
      setActionBusy(false);
    }
  }, [alertsSupported, notificationStatus?.available, notificationStatus?.vapidPublicKey]);

  const disableAlerts = useCallback(async () => {
    if (!alertsSupported) return;
    setActionBusy(true);
    try {
      const registration = await navigator.serviceWorker.getRegistration("/");
      const subscription = await registration?.pushManager.getSubscription();
      if (subscription) {
        await removePushDestination(subscription.endpoint);
        await subscription.unsubscribe();
      }
      setNotificationStatus(await getNotificationStatus());
      setAlertsEnabled(false);
      setError(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Background alerts could not be disabled on this browser.");
    } finally {
      setActionBusy(false);
    }
  }, [alertsSupported]);

  useEffect(() => {
    const controller = new AbortController();
    getAuthStatus(controller.signal).then(setAuthentication).catch((reason) => setError(reason instanceof Error ? reason.message : "HAVEN authentication status is unavailable."));
    return () => controller.abort();
  }, []);

  useEffect(() => {
    if (!authentication?.authenticated) return;
    const controller = new AbortController();
    void refresh(controller.signal);
    return () => controller.abort();
  }, [authentication?.authenticated, refresh]);

  useEffect(() => {
    if (!authentication?.authenticated || !alertsSupported || !notificationStatus?.available) return;
    let active = true;
    void navigator.serviceWorker.getRegistration("/").then((registration) => registration?.pushManager.getSubscription()).then((subscription) => {
      if (active) setAlertsEnabled(window.Notification.permission === "granted" && Boolean(subscription));
    }).catch(() => { if (active) setAlertsEnabled(false); });
    return () => { active = false; };
  }, [alertsSupported, authentication?.authenticated, notificationStatus?.available]);

	useEffect(() => {
		if (!accountAccess || demoMode) return;
		const token = accountAccess.token;
		const recordActivity = () => {
			const now = Date.now();
			const current = accountAccessRef.current;
			if (!current || now >= new Date(current.expiresAt).getTime() || now >= new Date(current.absoluteExpiresAt).getTime()) {
				void lockAccounts();
				return;
			}
			accountLastActivityRef.current = now;
		};
		const checkAccess = async () => {
			if (accountAccessRef.current?.token !== token) return;
			const now = Date.now();
			if (now >= new Date(accountAccessRef.current.expiresAt).getTime() || now >= new Date(accountAccess.absoluteExpiresAt).getTime() || now-accountLastActivityRef.current >= accountAccess.idleTimeoutSeconds*1000) {
				await lockAccounts();
				return;
			}
			if (document.visibilityState !== "visible" || now-accountLastActivityRef.current > 5*60_000 || now-accountLastTouchRef.current < 4*60_000) return;
			accountLastTouchRef.current = now;
			try {
				const refreshed = await touchAccountNotebook(token);
				if (accountAccessRef.current?.token === token) {
					accountAccessRef.current = refreshed;
					setAccountAccess(refreshed);
				}
			} catch (reason) {
				if (reason instanceof HavenAPIError && reason.status === 403) clearAccountAccess();
				else setError(reason instanceof Error ? reason.message : "Private account access could not be refreshed.");
			}
		};
		window.addEventListener("pointerdown", recordActivity, { passive: true });
		window.addEventListener("keydown", recordActivity);
		window.addEventListener("touchstart", recordActivity, { passive: true });
		window.addEventListener("focus", checkAccess);
		document.addEventListener("visibilitychange", checkAccess);
		const interval = window.setInterval(() => void checkAccess(), 30_000);
		return () => {
			window.removeEventListener("pointerdown", recordActivity);
			window.removeEventListener("keydown", recordActivity);
			window.removeEventListener("touchstart", recordActivity);
			window.removeEventListener("focus", checkAccess);
			document.removeEventListener("visibilitychange", checkAccess);
			window.clearInterval(interval);
		};
	}, [accountAccess?.absoluteExpiresAt, accountAccess?.idleTimeoutSeconds, accountAccess?.token, clearAccountAccess, demoMode, lockAccounts]);

  useEffect(() => {
    if (!authentication?.authenticated || !inventoryLoaded || demoMode) return;
    const controller = new AbortController();
    void loadControls(selectedId, controller.signal).catch((reason) => {
      if (!(reason instanceof DOMException && reason.name === "AbortError")) setError(reason instanceof Error ? reason.message : "The action center could not be loaded.");
    });
    return () => controller.abort();
	}, [authentication?.authenticated, demoMode, inventoryLoaded, loadControls, selectedId]);

  useEffect(() => {
    if (!authentication?.authenticated || !inventoryLoaded || route.page !== "device" || !route.deviceId || route.deviceId === selectedIdRef.current) return;
    void selectDevice(route.deviceId);
  }, [authentication?.authenticated, inventoryLoaded, route.deviceId, route.page, selectDevice]);

	useEffect(() => {
		if (!authentication?.authenticated || !inventoryLoaded || demoMode) return;
    const controller = new AbortController();
    const pollControls = async () => {
      try {
        const [recentActions, recentAudit] = await Promise.all([listSecurityActions(controller.signal), listAuditEvents(controller.signal)]);
        setActions(recentActions);
        setAudit(recentAudit);
      } catch (reason) {
        if (!(reason instanceof DOMException && reason.name === "AbortError")) setError(reason instanceof Error ? reason.message : "The action center could not refresh.");
      }
    };
    const interval = window.setInterval(() => void pollControls(), 10_000);
    return () => { controller.abort(); window.clearInterval(interval); };
	}, [authentication?.authenticated, demoMode, inventoryLoaded]);

  useEffect(() => {
    if (!authentication?.authenticated) return;
    const controller = new AbortController();
    const poll = async () => {
      try {
		const [inventory, runtimeStatus, diagnosticReport, activity, activeAlerts, pushStatus, managedAppliances] = await Promise.all([listDevices(controller.signal), getRuntimeStatus(controller.signal), getSystemDiagnostics(controller.signal), listEvents(undefined, controller.signal), listAlerts(controller.signal), getNotificationStatus(controller.signal), listManagedAppliances(controller.signal)]);
        let observed: { id: string; snapshot: SecuritySnapshot } | null;
        if (runtimeStatus.demoMode || runtimeStatus.localCollection) {
          const latest = await getLatestSnapshot(controller.signal);
          observed = { id: latest.device.deviceId || inventory.find((device) => device.trustState === "local")?.id || "", snapshot: latest };
        } else {
          observed = await latestEnrolledObservation(inventory, selectedIdRef.current, controller.signal);
        }
        const networkObservations = await loadNetworkObservations(inventory, runtimeStatus.demoMode, controller.signal);
        setDevices(inventory);
        setNetworkDevices(networkObservations);
        setAppliances(managedAppliances);
        setEvents(activity);
        setCurrentAlerts(activeAlerts);
        setRuntime(runtimeStatus);
		setDiagnostics(diagnosticReport);
        setNotificationStatus(pushStatus);
        setDemoMode(runtimeStatus.demoMode);
        setSnapshot(observed?.snapshot || null);
        const nextId = observed?.id || inventory.find((device) => device.status === "awaiting-first-report")?.id || "";
		if (!runtimeStatus.demoMode && nextId) setListenerObservations(await listObservedListeners(nextId, controller.signal));
        selectedIdRef.current = nextId;
        setSelectedId(nextId);
        setInventoryLoaded(true);
        setError(null);
      } catch (reason) {
        if (reason instanceof DOMException && reason.name === "AbortError") return;
        setError(reason instanceof Error ? reason.message : "HAVEN could not refresh its monitoring status.");
      }
    };
    const interval = window.setInterval(() => void poll(), 60_000);
    return () => {
      controller.abort();
      window.clearInterval(interval);
    };
  }, [authentication?.authenticated]);

  if (!authentication) {
    return <main className="loading-state"><div className="brand-mark"><HavenIcon /></div><p>{error || "Checking HAVEN's security boundary…"}</p></main>;
  }

  if (!authentication.authenticated) {
    return <AuthenticationGate status={authentication} authenticate={authenticate} />;
  }

  if (!snapshot && !inventoryLoaded) {
    return <main className="loading-state"><div className="brand-mark"><HavenIcon /></div><p>{error || "Collecting security posture…"}</p>{error && <button className="refresh-button" onClick={() => void refresh()}>Try again</button>}</main>;
  }

  if (!snapshot) {
    return <AwaitingAgents devices={devices} runtime={runtime} diagnostics={diagnostics} notificationStatus={notificationStatus} passkeys={passkeys} actions={actions} audit={audit} error={error} selectDevice={(id) => void selectDevice(id)} addOwnerPasskey={() => void addOwnerPasskey()} removeOwnerPasskey={(passkey) => void removeOwnerPasskey(passkey)} actionBusy={actionBusy} signOut={() => void signOut()} alertsSupported={alertsSupported} alertsEnabled={alertsEnabled} enableAlerts={(label) => void enableAlerts(label)} disableAlerts={() => void disableAlerts()} desktopInstallStatus={desktopInstall.status} desktopVersion={desktopInstall.nativeVersion} installDesktopApp={async () => { try { await desktopInstall.install(); setError(null); } catch (reason) { setError(reason instanceof Error ? reason.message : "HAVEN could not open the browser installation prompt."); } }} route={route} navigate={navigate} />;
  }

  const selectedDevice = devices.find((device) => device.id === selectedId) || null;
  const selectedEvents = selectedId ? events.filter((event) => event.deviceId === selectedId) : events;
	return <Application snapshot={snapshot} devices={devices} networkDevices={networkDevices} appliances={appliances} events={selectedEvents} networkEvents={events} alerts={currentAlerts} runtime={runtime} diagnostics={diagnostics} notificationStatus={notificationStatus} selectedDevice={selectedDevice} selectDevice={(id) => void selectDevice(id)} refresh={() => void refreshView()} refreshing={refreshing} error={error} demoMode={demoMode} alertsEnabled={alertsEnabled} alertsSupported={alertsSupported} enableAlerts={(label) => void enableAlerts(label)} disableAlerts={() => void disableAlerts()} reviews={reviews} browserSiteReviews={browserSiteReviews} expectedServices={expectedServices} listenerObservations={listenerObservations} audit={audit} actions={actions} passkeys={passkeys} accountProfiles={accountProfiles} accountUnlocked={demoMode || accountAccess !== null} desktopInstallStatus={desktopInstall.status} desktopVersion={desktopInstall.nativeVersion} installDesktopApp={async () => { try { await desktopInstall.install(); setError(null); } catch (reason) { setError(reason instanceof Error ? reason.message : "HAVEN could not open the browser installation prompt."); } }} reviewFinding={(finding, state) => void reviewFinding(finding, state)} classifyBrowserSite={(review) => void classifyBrowserSite(review)} resetBrowserSite={(review) => void resetBrowserSite(review)} saveServiceExpectation={(service) => void saveServiceExpectation(service)} saveServiceExpectations={(services) => void saveServiceBaseline(services)} removeServiceExpectation={(service) => void removeServiceExpectation(service)} runAction={(kind) => void runAction(kind)} addOwnerPasskey={() => void addOwnerPasskey()} removeOwnerPasskey={(passkey) => void removeOwnerPasskey(passkey)} saveAccount={saveAccount} removeAccount={(profile) => void removeAccount(profile)} unlockAccounts={() => void unlockAccounts()} lockAccounts={() => void lockAccounts()} runApplianceDeepCheck={(appliance) => void runApplianceDeepCheck(appliance)} deepCheckBusy={deepCheckBusy} actionBusy={actionBusy} signOut={() => void signOut()} route={route} navigate={navigate} />;
}
