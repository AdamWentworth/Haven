"use strict";

const { it } = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");

const main = readFileSync(new URL("main.cjs", `file://${__dirname}/`), "utf8");
const fuseVerifier = readFileSync(new URL("verify-fuses.cjs", `file://${__dirname}/`), "utf8");
const manifest = JSON.parse(readFileSync(new URL("package.json", `file://${__dirname}/`), "utf8"));

it("keeps the remote dashboard inside a sandbox without a preload or IPC bridge", () => {
  assert.match(main, /nodeIntegration: false/);
  assert.match(main, /contextIsolation: true/);
  assert.match(main, /sandbox: true/);
  assert.match(main, /webSecurity: true/);
  assert.match(main, /setPermissionCheckHandler/);
  assert.match(main, /setPermissionRequestHandler/);
  assert.match(main, /notificationPermissionGranted && permission === "notifications"/);
  assert.match(main, /finally \{\s+callback\(credentialId\)/);
  assert.ok(main.includes('setWindowOpenHandler(() => ({ action: "deny" }))'));
  assert.doesNotMatch(main, /preload\s*:|ipcMain|ipcRenderer|shell\.openExternal/);
});

it("hardens the packaged executable with encrypted cookies and ASAR integrity", () => {
	assert.ok(main.includes('path.join(__dirname, "build", "icon.ico")'));
	assert.ok(manifest.build.files.includes("build/icon.ico"));
	assert.equal(manifest.build.win.icon, "build/icon.ico");
  assert.deepEqual(manifest.build.electronFuses, {
    runAsNode: false,
    enableCookieEncryption: true,
    enableNodeOptionsEnvironmentVariable: false,
    enableNodeCliInspectArguments: false,
    enableEmbeddedAsarIntegrityValidation: true,
    onlyLoadAppFromAsar: true,
    loadBrowserProcessSpecificV8Snapshot: false,
    grantFileProtocolExtraPrivileges: false,
  });
  assert.match(fuseVerifier, /WasmTrapHandlers/);
  assert.match(fuseVerifier, /assert\.equal\(fuses\[fuse\], state/);
});
