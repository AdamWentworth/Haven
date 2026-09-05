"use strict";

// Generated before development, tests, or packaging. The packaged client keeps
// this exact origin pinned at build time; runtime environment variables cannot
// redirect an installed security dashboard.
const { HAVEN_URL } = require("./build/origin.cjs");
const DESKTOP_VERSION = "0.25.0";
const expected = new URL(HAVEN_URL);

function isHavenUrl(rawUrl) {
  try {
    const candidate = new URL(rawUrl);
    return candidate.protocol === "https:"
      && candidate.username === ""
      && candidate.password === ""
      && candidate.origin === expected.origin;
  } catch {
    return false;
  }
}

function desktopUserAgent(baseUserAgent) {
  return `${baseUserAgent} HAVEN-Desktop/${DESKTOP_VERSION} Electron`;
}

module.exports = { DESKTOP_VERSION, HAVEN_URL, desktopUserAgent, isHavenUrl };
