"use strict";

const { join } = require("path");
const { existsSync } = require("fs");

const PLATFORM_PACKAGES = {
  "linux-x64": "@ossguard/cli-linux-x64",
  "linux-arm64": "@ossguard/cli-linux-arm64",
  "darwin-x64": "@ossguard/cli-darwin-x64",
  "darwin-arm64": "@ossguard/cli-darwin-arm64",
  "win32-x64": "@ossguard/cli-win32-x64",
};

function resolveBinary() {
  const platformKey = `${process.platform}-${process.arch}`;
  const packageName = PLATFORM_PACKAGES[platformKey];

  if (!packageName) {
    const supported = Object.keys(PLATFORM_PACKAGES).join(", ");
    throw new Error(
      `ossguard: unsupported platform "${platformKey}".\n` +
      `Supported platforms: ${supported}\n\n` +
      `Install from PyPI instead: pip install ossguard`
    );
  }

  const isWindows = process.platform === "win32";
  const binaryName = isWindows ? "ossguard.exe" : "ossguard";

  // Try resolving from the platform-specific optional dependency
  try {
    const pkgDir = require.resolve(`${packageName}/package.json`);
    const binPath = join(pkgDir, "..", "bin", binaryName);
    if (existsSync(binPath)) {
      return binPath;
    }
  } catch {
    // Package not installed — fall through to error
  }

  throw new Error(
    `ossguard: could not find the binary for your platform (${platformKey}).\n\n` +
    `The platform package "${packageName}" does not appear to be installed.\n` +
    `This can happen if:\n` +
    `  - You're using --no-optional (don't do this)\n` +
    `  - Your package manager doesn't support optionalDependencies\n\n` +
    `Try reinstalling: npm install -g ossguard\n` +
    `Or install from PyPI: pip install ossguard`
  );
}

module.exports = { resolveBinary, PLATFORM_PACKAGES };
