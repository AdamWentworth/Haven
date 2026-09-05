"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { DEFAULT_HAVEN_DESKTOP_ORIGIN, normalizeHavenOrigin } = require("./configure-origin.cjs");
const { DESKTOP_VERSION, HAVEN_URL, desktopUserAgent, isHavenUrl } = require("./security.cjs");

describe("HAVEN desktop origin boundary", () => {
  it("allows routes on the configured private HTTPS origin", () => {
    assert.equal(HAVEN_URL, DEFAULT_HAVEN_DESKTOP_ORIGIN);
    for (const allowed of [HAVEN_URL, `${HAVEN_URL}accounts`, `${HAVEN_URL}devices?selected=one#posture`]) {
      assert.equal(isHavenUrl(allowed), true);
    }
  });

  it("accepts only an exact HTTPS origin at build time", () => {
    assert.equal(normalizeHavenOrigin("https://security.internal.example:9443"), "https://security.internal.example:9443/");
    for (const rejected of ["http://security.internal.example/", "https://user@example.com/", "https://security.internal.example/path", "not a URL"]) {
      assert.throws(() => normalizeHavenOrigin(rejected), /exact HTTPS origin|absolute HTTPS origin/);
    }
  });

  it("rejects alternate schemes, ports, credentials, and lookalike hosts", () => {
    for (const rejected of [
      "http://haven.home.arpa:8443/",
      "https://haven.home.arpa/",
      "https://example.com/",
      "https://haven.home.arpa.evil.example:8443/",
      "https://" + "user" + "@haven.home.arpa:8443/",
      "not a URL",
    ]) {
      assert.equal(isHavenUrl(rejected), false, rejected);
    }
  });

  it("adds only a bounded presentational marker to Chromium's user agent", () => {
    const userAgent = desktopUserAgent("Chromium test agent");
    assert.equal(userAgent, `Chromium test agent HAVEN-Desktop/${DESKTOP_VERSION} Electron`);
  });
});
