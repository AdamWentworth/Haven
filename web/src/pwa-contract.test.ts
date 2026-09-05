import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const manifest = JSON.parse(readFileSync(new URL("../public/manifest.webmanifest", import.meta.url), "utf8")) as Record<string, unknown>;
const serviceWorker = readFileSync(new URL("../public/sw.js", import.meta.url), "utf8");
const applicationShell = readFileSync(new URL("../index.html", import.meta.url), "utf8");
const standardIcon = readFileSync(new URL("../public/haven-app-icon.svg", import.meta.url), "utf8");
const maskableIcon = readFileSync(new URL("../public/haven-maskable-icon.svg", import.meta.url), "utf8");
const iconComponents = readFileSync(new URL("./icons.tsx", import.meta.url), "utf8");

describe("installable application contract", () => {
	it("keeps the installed window on the private HAVEN origin", () => {
		expect(manifest).toMatchObject({ id: "/", start_url: "/", scope: "/", display: "standalone" });
		const icons = manifest.icons as Array<{ src: string; sizes: string; type: string; purpose: string }>;
		expect(icons.length).toBeGreaterThan(0);
		expect(icons.every((icon) => icon.src.startsWith("/") && !icon.src.includes("://"))).toBe(true);
		expect(icons).toEqual(expect.arrayContaining([
			expect.objectContaining({ src: "/haven-app-icon-192.png", sizes: "192x192", type: "image/png", purpose: "any" }),
			expect.objectContaining({ src: "/haven-app-icon-512.png", sizes: "512x512", type: "image/png", purpose: "any" }),
			expect.objectContaining({ src: "/haven-maskable-icon-512.png", sizes: "512x512", type: "image/png", purpose: "maskable" }),
			expect.objectContaining({ src: "/haven-monochrome-icon.svg", sizes: "any", type: "image/svg+xml", purpose: "monochrome" }),
		]));
	});

	it("keeps the normal mark transparent and isolates the opaque maskable tile", () => {
		expect(standardIcon).not.toContain("<rect");
		expect(standardIcon).toContain('fill="#10251d"');
		expect(maskableIcon).toContain('<rect width="24" height="24" fill="#08100d"/>');
		const canonicalPaths = Array.from(standardIcon.matchAll(/<path d="([^"]+)"/g), (match) => match[1]);
		const maskablePaths = Array.from(maskableIcon.matchAll(/<path d="([^"]+)"/g), (match) => match[1]);
		expect(canonicalPaths).toHaveLength(2);
		expect(maskablePaths).toEqual(canonicalPaths);
		for (const path of canonicalPaths) expect(iconComponents).toContain(`d="${path}"`);
	});

	it("advertises the manifest without adding an authenticated-page cache", () => {
		expect(applicationShell).toContain('rel="manifest" href="/manifest.webmanifest"');
		expect(serviceWorker).not.toMatch(/addEventListener\(["']fetch["']/);
		expect(serviceWorker).not.toContain("caches.");
	});
});
