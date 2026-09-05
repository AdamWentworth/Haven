import type { MouseEvent, ReactNode } from "react";
import { ActivityIcon, DevicesIcon, HavenIcon, LockIcon, NetworkIcon, ServerIcon, UsersIcon } from "./icons";
import { routePath, type AppRoute, type DeviceSection, type PageKey } from "./routing";

const navigationItems: Array<{ page: Exclude<PageKey, "device">; label: string; icon: ReactNode }> = [
	{ page: "overview", label: "Overview", icon: <HavenIcon /> },
	{ page: "devices", label: "Devices", icon: <DevicesIcon /> },
	{ page: "network", label: "Network", icon: <NetworkIcon /> },
	{ page: "appliances", label: "Appliances", icon: <ServerIcon /> },
	{ page: "accounts", label: "Accounts", icon: <UsersIcon /> },
	{ page: "activity", label: "Activity", icon: <ActivityIcon /> },
	{ page: "settings", label: "Settings", icon: <LockIcon /> },
];

function follow(event: MouseEvent<HTMLAnchorElement>, route: AppRoute, navigate: (route: AppRoute) => void) {
	if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
	event.preventDefault();
	navigate(route);
}

export function AppNavigation({ current, navigate }: { current: PageKey; navigate: (route: AppRoute) => void }) {
	const selected = current === "device" ? "devices" : current;
	return <nav className="app-navigation" aria-label="Primary navigation">
		{navigationItems.map((item) => {
			const route: AppRoute = { page: item.page };
			return <a key={item.page} href={routePath(route)} aria-current={selected === item.page ? "page" : undefined} onClick={(event) => follow(event, route, navigate)}><span aria-hidden="true">{item.icon}</span>{item.label}</a>;
		})}
	</nav>;
}

const deviceSections: Array<{ section: DeviceSection; label: string }> = [
	{ section: "overview", label: "Overview" },
	{ section: "posture", label: "Posture" },
	{ section: "browsers", label: "Browsers" },
	{ section: "services", label: "Services & connections" },
	{ section: "history", label: "History" },
];

export function DeviceNavigation({ deviceId, current, navigate }: { deviceId: string; current: DeviceSection; navigate: (route: AppRoute) => void }) {
	return <nav className="device-navigation" aria-label="Device sections">
		{deviceSections.map((item) => {
			const route: AppRoute = { page: "device", deviceId, section: item.section };
			return <a key={item.section} href={routePath(route)} aria-current={current === item.section ? "page" : undefined} onClick={(event) => follow(event, route, navigate)}>{item.label}</a>;
		})}
	</nav>;
}

export function PageIntro({ eyebrow, title, children }: { eyebrow: string; title: string; children: ReactNode }) {
	return <section className="page-intro" aria-labelledby="page-title"><p className="eyebrow">{eyebrow}</p><h1 id="page-title">{title}</h1><p>{children}</p></section>;
}
