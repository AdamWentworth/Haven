import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const manifest = JSON.parse(readFileSync(new URL("../../desktop/package.json", import.meta.url), "utf8")) as {
		version: string;
		devDependencies: Record<string, string>;
	build: { asar: boolean; files: string[]; electronFuses: Record<string, boolean> };
};
const shell = readFileSync(new URL("../../desktop/main.cjs", import.meta.url), "utf8");
const security = readFileSync(new URL("../../desktop/security.cjs", import.meta.url), "utf8");
const application = readFileSync(new URL("./App.tsx", import.meta.url), "utf8");
const styles = readFileSync(new URL("./styles.css", import.meta.url), "utf8");

describe("native desktop shell contract", () => {
	it("loads the private HTTPS hub without granting remote Node or IPC capabilities", () => {
		expect(security).toContain('const HAVEN_URL = "https://haven.home.arpa:8443/"');
		expect(shell).toContain("nodeIntegration: false");
		expect(shell).toContain("contextIsolation: true");
		expect(shell).toContain("sandbox: true");
		expect(shell).toContain("webSecurity: true");
		expect(shell).not.toMatch(/preload\s*:|ipcMain|ipcRenderer|shell\.openExternal/);
	});

	it("pins dependencies and hardens the packaged desktop boundary", () => {
		expect(manifest.version).toBe("0.20.2");
		expect(manifest.devDependencies.electron).toMatch(/^\d+\.\d+\.\d+$/);
		expect(manifest.devDependencies["@electron/fuses"]).toMatch(/^\d+\.\d+\.\d+$/);
		expect(manifest.build.asar).toBe(true);
		expect(manifest.build.files).not.toContain("node_modules/**/*");
		expect(manifest.build.electronFuses).toMatchObject({
			runAsNode: false,
			enableCookieEncryption: true,
			enableEmbeddedAsarIntegrityValidation: true,
			onlyLoadAppFromAsar: true,
		});
		expect(shell).toContain('setWindowOpenHandler(() => ({ action: "deny" }))');
	});

	it("progressively compacts header controls before moving navigation to the bottom", () => {
		expect(styles).toContain("white-space: nowrap");
		expect(styles).toContain("@media (max-width: 1320px)");
		expect(styles).toContain(".topbar-action-label { display: none; }");
		expect(styles).toContain("@media (max-width: 1160px)");
		expect(styles).toContain(".local-label { display: none; }");
		expect(styles).toContain("@media (max-width: 1050px)");
		expect(styles).toContain(".app-navigation { position: fixed; right: 0; bottom: 0; left: 0;");
		expect(styles).not.toContain(".topbar { flex-wrap: wrap");
		expect(application).toContain('className="topbar-action-label"');
		expect(application).toContain('aria-label="Lock HAVEN"');
	});
});
