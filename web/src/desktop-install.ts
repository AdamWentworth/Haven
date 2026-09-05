import { useCallback, useEffect, useState } from "react";

export type DesktopInstallStatus = "available" | "installed" | "manual";
export type DesktopInstallOutcome = "accepted" | "dismissed" | "unavailable";

interface BrowserInstallPrompt extends Event {
	prompt: () => Promise<void>;
	userChoice: Promise<{ outcome: "accepted" | "dismissed" }>;
}

function hasInstallPrompt(value: Event): value is BrowserInstallPrompt {
	const candidate = value as Partial<BrowserInstallPrompt>;
	return typeof candidate.prompt === "function" && typeof candidate.userChoice?.then === "function";
}

export function isStandaloneApp() {
	if (typeof window === "undefined" || typeof navigator === "undefined") return false;
	const iosNavigator = navigator as Navigator & { standalone?: boolean };
	return iosNavigator.standalone === true || window.matchMedia?.("(display-mode: standalone)").matches === true;
}

export async function registerApplicationServiceWorker() {
	if (typeof navigator === "undefined" || !("serviceWorker" in navigator)) return null;
	return navigator.serviceWorker.register("/sw.js", { scope: "/" });
}

export function useDesktopInstall() {
	const [prompt, setPrompt] = useState<BrowserInstallPrompt | null>(null);
	const [installed, setInstalled] = useState(isStandaloneApp);

	useEffect(() => {
		const capturePrompt = (event: Event) => {
			if (!hasInstallPrompt(event)) return;
			event.preventDefault();
			setPrompt(event);
		};
		const recordInstallation = () => {
			setPrompt(null);
			setInstalled(true);
		};
		window.addEventListener("beforeinstallprompt", capturePrompt);
		window.addEventListener("appinstalled", recordInstallation);
		return () => {
			window.removeEventListener("beforeinstallprompt", capturePrompt);
			window.removeEventListener("appinstalled", recordInstallation);
		};
	}, []);

	const install = useCallback(async (): Promise<DesktopInstallOutcome> => {
		if (installed || !prompt) return "unavailable";
		await prompt.prompt();
		const choice = await prompt.userChoice;
		setPrompt(null);
		if (choice.outcome === "accepted") setInstalled(true);
		return choice.outcome;
	}, [installed, prompt]);

	return {
		status: installed ? "installed" as const : prompt ? "available" as const : "manual" as const,
		install,
	};
}
