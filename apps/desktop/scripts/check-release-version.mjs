import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const desktopRoot = resolve(import.meta.dirname, "..");
const workspaceRoot = resolve(desktopRoot, "../..");
const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));
// Cargo resolves workspace.package.version inheritance without downloading or building dependencies.
const metadata = JSON.parse(execFileSync("cargo", ["metadata", "--offline", "--no-deps", "--format-version", "1"], {
  cwd: workspaceRoot,
  encoding: "utf8"
}));
const versions = [
  ...metadata.packages.filter((pkg) => metadata.workspace_members.includes(pkg.id))
    .map((pkg) => [`Cargo.toml (${pkg.name})`, pkg.version]),
  ["apps/desktop/package.json", readJson(resolve(desktopRoot, "package.json")).version],
  ["apps/desktop/src-tauri/tauri.conf.json", readJson(resolve(desktopRoot, "src-tauri/tauri.conf.json")).version]
];
const version = versions[0][1];
if (versions.some(([, value]) => value !== version)) {
  throw new Error(`Application versions must match:\n${versions.map(([file, value]) => `${file}: ${value}`).join("\n")}`);
}

// A positional tag also allows maintainers to run the same check locally.
const tag = process.argv[2] ?? (process.env.GITHUB_REF_TYPE === "tag" ? process.env.GITHUB_REF_NAME : undefined);
if (tag !== undefined && tag !== `v${version}`) {
  throw new Error(`Version tag ${tag} does not match application version ${version}; expected v${version}.`);
}
console.log(`Application versions match: ${version}${tag ? ` (tag ${tag})` : ""}.`);
