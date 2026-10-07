import { mkdirSync, readdirSync, rmSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { basename, resolve } from "node:path";
import { readFileSync } from "node:fs";

const mode = process.argv[2];
const desktopRoot = resolve(import.meta.dirname, "..");
const workspaceRoot = resolve(desktopRoot, "../..");
const releaseRoot = resolve(workspaceRoot, process.env.CARGO_TARGET_DIR || "target", "release");
const bundleRoot = resolve(releaseRoot, "bundle");
const outputRoot = resolve(bundleRoot, "portable");
const config = JSON.parse(readFileSync(resolve(desktopRoot, "src-tauri/tauri.conf.json"), "utf8"));

function newestFile(directory, suffix) {
  return readdirSync(directory)
    .filter((name) => name.endsWith(suffix))
    .map((name) => ({ name, modified: statSync(resolve(directory, name)).mtimeMs }))
    .sort((left, right) => right.modified - left.modified)[0]?.name;
}

function requireFile(path) {
  if (!statSync(path, { throwIfNoEntry: false })?.isFile()) {
    throw new Error(`Expected portable build file was not found: ${path}`);
  }
}

function runArchive(command, args) {
  const result = spawnSync(command, args, { stdio: "inherit" });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${command} failed with exit code ${result.status}`);
}

rmSync(outputRoot, { recursive: true, force: true });
mkdirSync(outputRoot, { recursive: true });

if (mode === "appimage") {
  const sourceRoot = resolve(bundleRoot, "appimage");
  const launcher = newestFile(sourceRoot, ".AppImage");
  if (!launcher) throw new Error(`No AppImage was found in ${sourceRoot}`);
  requireFile(resolve(sourceRoot, "qiring-portable"));
  const archive = resolve(outputRoot, `QiRing_${config.version}_amd64_portable.tar.gz`);
  runArchive("tar", ["-czf", archive, "-C", sourceRoot, launcher, "qiring-portable"]);
  console.log(`Packaged portable AppImage: ${archive}`);
} else if (mode === "windows") {
  const launcher = process.env.QIRING_OUTPUT_NAME ? `${process.env.QIRING_OUTPUT_NAME}.exe` : "qiring-desktop.exe";
  requireFile(resolve(releaseRoot, launcher));
  requireFile(resolve(releaseRoot, "qiring-portable"));
  const architecture = process.arch === "x64" ? "x64" : process.arch;
  const archive = resolve(outputRoot, `QiRing_${config.version}_${architecture}_portable.zip`);
  runArchive("tar", ["-a", "-cf", archive, "-C", releaseRoot, basename(launcher), "qiring-portable"]);
  console.log(`Packaged portable Windows executable: ${archive}`);
} else {
  throw new Error("Usage: node scripts/package-portable.mjs appimage|windows");
}
