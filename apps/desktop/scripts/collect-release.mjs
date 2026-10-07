import { cpSync, mkdirSync, readdirSync, rmSync, statSync } from "node:fs";
import { basename, resolve } from "node:path";

const desktopRoot = resolve(import.meta.dirname, "..");
const workspaceRoot = resolve(desktopRoot, "../..");
const bundleRoot = resolve(workspaceRoot, process.env.CARGO_TARGET_DIR || "target", "release/bundle");
const outputRoot = resolve(desktopRoot, "release-assets");
const platform = process.argv[2] || { linux: "linux", darwin: "macos", win32: "windows" }[process.platform];
const acceptedSuffixes = [".appimage", ".deb", ".rpm", ".dmg", ".msi", ".exe", ".sig", ".tar.gz", ".zip"];
const bundleDirectories = {
  linux: ["appimage", "deb", "portable"],
  macos: ["dmg"],
  windows: ["msi", "portable"]
}[platform];
if (!bundleDirectories) throw new Error(`Unknown release platform: ${platform}`);

rmSync(outputRoot, { recursive: true, force: true });
mkdirSync(outputRoot, { recursive: true });

function bundleFiles(directory) {
  const files = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = resolve(directory, entry.name);
    // AppDir/.app contents and bundler staging files are not release assets.
    if (entry.isFile()) files.push(path);
  }
  return files;
}

if (!statSync(bundleRoot, { throwIfNoEntry: false })?.isDirectory()) {
  throw new Error(`No Tauri bundle directory found at ${bundleRoot}`);
}

let copied = 0;
const copiedNames = [];
for (const source of bundleDirectories.flatMap((directory) => bundleFiles(resolve(bundleRoot, directory)))) {
  const lower = source.toLowerCase();
  if (!acceptedSuffixes.some((suffix) => lower.endsWith(suffix))) continue;
  if (statSync(source).size === 0) throw new Error(`Release artifact is empty: ${source}`);
  const destination = resolve(outputRoot, `${platform}-${basename(source)}`);
  if (statSync(destination, { throwIfNoEntry: false })) {
    throw new Error(`Duplicate release artifact name: ${basename(source)}`);
  }
  cpSync(source, destination);
  copiedNames.push(basename(source).toLowerCase());
  copied += 1;
}

if (copied === 0) throw new Error("Tauri produced no recognized release bundle artifacts.");
const requiredSuffixes = {
  linux: [".appimage", ".deb", "_portable.tar.gz"],
  macos: [".dmg"],
  windows: [".msi", "_portable.zip"]
}[platform] || [];
for (const suffix of requiredSuffixes) {
  if (!copiedNames.some((name) => name.endsWith(suffix))) {
    throw new Error(`Missing required ${platform} bundle type: ${suffix}`);
  }
}
console.log(`Collected ${copied} ${platform} release artifacts.`);
