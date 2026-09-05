"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const {
  FuseState,
  FuseV1Options,
  FuseVersion,
  getCurrentFuseWire,
} = require("@electron/fuses");

const executable = process.argv[2] || path.join(__dirname, "dist", "win-unpacked", "HAVEN.exe");

async function verify() {
  const fuses = await getCurrentFuseWire(executable);
  assert.equal(fuses.version, FuseVersion.V1);

  const expected = new Map([
    [FuseV1Options.RunAsNode, FuseState.DISABLE],
    [FuseV1Options.EnableCookieEncryption, FuseState.ENABLE],
    [FuseV1Options.EnableNodeOptionsEnvironmentVariable, FuseState.DISABLE],
    [FuseV1Options.EnableNodeCliInspectArguments, FuseState.DISABLE],
    [FuseV1Options.EnableEmbeddedAsarIntegrityValidation, FuseState.ENABLE],
    [FuseV1Options.OnlyLoadAppFromAsar, FuseState.ENABLE],
    [FuseV1Options.LoadBrowserProcessSpecificV8Snapshot, FuseState.DISABLE],
    [FuseV1Options.GrantFileProtocolExtraPrivileges, FuseState.DISABLE],
    [FuseV1Options.WasmTrapHandlers, FuseState.ENABLE],
  ]);

  for (const [fuse, state] of expected) {
    assert.equal(fuses[fuse], state, `${FuseV1Options[fuse]} has an unexpected state`);
  }
  console.log(`Verified ${expected.size} Electron fuses in ${executable}.`);
}

verify().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
