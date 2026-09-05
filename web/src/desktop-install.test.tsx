// @vitest-environment jsdom

import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { isStandaloneApp, nativeDesktopVersion, registerApplicationServiceWorker, useDesktopInstall } from "./desktop-install";

function setDisplayMode(matches: boolean) {
	Object.defineProperty(window, "matchMedia", { configurable: true, value: vi.fn().mockReturnValue({ matches }) });
}

describe("desktop installation", () => {
	let userAgent: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		setDisplayMode(false);
		userAgent = vi.spyOn(window.navigator, "userAgent", "get").mockReturnValue("Mozilla/5.0 test browser");
	});
	afterEach(() => vi.restoreAllMocks());

	it("recognizes a standalone app window", () => {
		setDisplayMode(true);
		expect(isStandaloneApp()).toBe(true);
	});

	it("recognizes the bounded native desktop user-agent marker", () => {
		userAgent.mockReturnValue("Mozilla/5.0 HAVEN-Desktop/0.19.0 Electron");
		expect(nativeDesktopVersion()).toBe("0.19.0");
		expect(isStandaloneApp()).toBe(true);
		const { result } = renderHook(() => useDesktopInstall());
		expect(result.current).toMatchObject({ status: "native", nativeVersion: "0.19.0" });
	});

	it("captures one browser install prompt and records acceptance", async () => {
		const prompt = vi.fn().mockResolvedValue(undefined);
		const event = Object.assign(new Event("beforeinstallprompt", { cancelable: true }), {
			prompt,
			userChoice: Promise.resolve({ outcome: "accepted" as const }),
		});
		const { result } = renderHook(() => useDesktopInstall());
		act(() => window.dispatchEvent(event));
		expect(result.current.status).toBe("available");
		await act(async () => expect(await result.current.install()).toBe("accepted"));
		expect(prompt).toHaveBeenCalledOnce();
		expect(result.current.status).toBe("installed");
	});

	it("registers the existing push-only service worker without requesting permission", async () => {
		const register = vi.fn().mockResolvedValue({ scope: "/" });
		Object.defineProperty(navigator, "serviceWorker", { configurable: true, value: { register } });
		await expect(registerApplicationServiceWorker()).resolves.toEqual({ scope: "/" });
		expect(register).toHaveBeenCalledWith("/sw.js", { scope: "/" });
	});
});
