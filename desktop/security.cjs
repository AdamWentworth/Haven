"use strict";

const HAVEN_URL = "https://haven.home.arpa:8443/";
const DESKTOP_VERSION = "0.21.0";
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
