// @vitest-environment jsdom

import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { isStandaloneApp, registerApplicationServiceWorker, useDesktopInstall } from "./desktop-install";

function setDisplayMode(matches: boolean) {
	Object.defineProperty(window, "matchMedia", { configurable: true, value: vi.fn().mockReturnValue({ matches }) });
}

describe("desktop installation", () => {
	beforeEach(() => setDisplayMode(false));
	afterEach(() => vi.restoreAllMocks());

	it("recognizes a standalone app window", () => {
		setDisplayMode(true);
		expect(isStandaloneApp()).toBe(true);
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
