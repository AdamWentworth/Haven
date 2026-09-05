"use strict";

const { mkdirSync, writeFileSync } = require("node:fs");
const { join } = require("node:path");

const DEFAULT_HAVEN_DESKTOP_ORIGIN = "https://haven.home.arpa:8443/";

function normalizeHavenOrigin(rawValue) {
  const value = String(rawValue || "").trim();
  let candidate;
  try {
    candidate = new URL(value);
  } catch {
    throw new Error("HAVEN_DESKTOP_ORIGIN must be an absolute HTTPS origin.");
  }
  if (candidate.protocol !== "https:" || candidate.username || candidate.password || candidate.pathname !== "/" || candidate.search || candidate.hash) {
    throw new Error("HAVEN_DESKTOP_ORIGIN must be one exact HTTPS origin with no credentials, path, query, or fragment.");
  }
  return `${candidate.origin}/`;
}

function writeOriginModule(rawValue = process.env.HAVEN_DESKTOP_ORIGIN || DEFAULT_HAVEN_DESKTOP_ORIGIN) {
  const origin = normalizeHavenOrigin(rawValue);
  const outputDirectory = join(__dirname, "build");
  const outputPath = join(outputDirectory, "origin.cjs");
  mkdirSync(outputDirectory, { recursive: true });
  writeFileSync(outputPath, `"use strict";\n\nmodule.exports = { HAVEN_URL: ${JSON.stringify(origin)} };\n`, { encoding: "utf8", mode: 0o600 });
  return origin;
}

if (require.main === module) {
  process.stdout.write(`Configured HAVEN desktop origin: ${writeOriginModule()}\n`);
}

module.exports = { DEFAULT_HAVEN_DESKTOP_ORIGIN, normalizeHavenOrigin, writeOriginModule };
