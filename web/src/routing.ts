import { useCallback, useEffect, useState } from "react";

export type PageKey = "overview" | "devices" | "device" | "network" | "appliances" | "accounts" | "activity" | "settings";
export type DeviceSection = "overview" | "posture" | "browsers" | "services" | "history";

export interface AppRoute {
	page: PageKey;
	deviceId?: string;
	section?: DeviceSection;
}

const deviceSections = new Set<DeviceSection>(["overview", "posture", "browsers", "services", "history"]);

export function parseRoute(pathname: string): AppRoute {
	let parts: string[];
	try {
		parts = pathname.split("/").filter(Boolean).map((part) => decodeURIComponent(part));
	} catch {
		return { page: "overview" };
	}
	if (parts.length === 0 || parts[0] === "overview") return { page: "overview" };
	if (parts[0] === "devices" && parts[1]) {
		const requested = parts[2] as DeviceSection | undefined;
		return { page: "device", deviceId: parts[1], section: requested && deviceSections.has(requested) ? requested : "overview" };
	}
	if (parts[0] === "devices") return { page: "devices" };
	if (parts[0] === "network") return { page: "network" };
	if (parts[0] === "appliances") return { page: "appliances" };
	if (parts[0] === "accounts") return { page: "accounts" };
	if (parts[0] === "activity") return { page: "activity" };
	if (parts[0] === "settings") return { page: "settings" };
	return { page: "overview" };
}

export function routePath(route: AppRoute): string {
	if (route.page === "overview") return "/";
	if (route.page === "device") return `/devices/${encodeURIComponent(route.deviceId || "")}/${route.section || "overview"}`;
	return `/${route.page}`;
}

export function useAppRoute() {
	const [route, setRoute] = useState<AppRoute>(() => parseRoute(window.location.pathname));
	useEffect(() => {
		const update = () => setRoute(parseRoute(window.location.pathname));
		window.addEventListener("popstate", update);
		return () => window.removeEventListener("popstate", update);
	}, []);
	const navigate = useCallback((next: AppRoute) => {
		const pathname = routePath(next);
		if (pathname !== window.location.pathname) window.history.pushState(null, "", pathname);
		setRoute(next);
		window.scrollTo({ top: 0, behavior: "auto" });
	}, []);
	return { route, navigate };
}
