import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const manifest = JSON.parse(readFileSync(new URL("../public/manifest.webmanifest", import.meta.url), "utf8")) as Record<string, unknown>;
const serviceWorker = readFileSync(new URL("../public/sw.js", import.meta.url), "utf8");
const applicationShell = readFileSync(new URL("../index.html", import.meta.url), "utf8");

describe("installable application contract", () => {
	it("keeps the installed window on the private HAVEN origin", () => {
		expect(manifest).toMatchObject({ id: "/", start_url: "/", scope: "/", display: "standalone" });
		const icons = manifest.icons as Array<{ src: string }>;
		expect(icons.length).toBeGreaterThan(0);
		expect(icons.every((icon) => icon.src.startsWith("/") && !icon.src.includes("://"))).toBe(true);
		expect(icons).toEqual(expect.arrayContaining([
			expect.objectContaining({ sizes: "192x192", type: "image/png" }),
			expect.objectContaining({ sizes: "512x512", type: "image/png" }),
		]));
	});

	it("advertises the manifest without adding an authenticated-page cache", () => {
		expect(applicationShell).toContain('rel="manifest" href="/manifest.webmanifest"');
		expect(serviceWorker).not.toMatch(/addEventListener\(["']fetch["']/);
		expect(serviceWorker).not.toContain("caches.");
	});
});
