import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";

const desktopRoot = resolve(import.meta.dirname, "..");
const workflow = readFileSync(resolve(desktopRoot, "../../.github/workflows/release.yml"), "utf8");
const packageJson = JSON.parse(readFileSync(join(desktopRoot, "package.json"), "utf8"));
const signingGroups = {
  linux: ["LINUX_GPG_PRIVATE_KEY", "LINUX_GPG_KEY_ID", "LINUX_GPG_PASSPHRASE"],
  windows: ["WINDOWS_CERTIFICATE", "WINDOWS_CERTIFICATE_PASSWORD", "WINDOWS_TIMESTAMP_URL"],
  macos: ["APPLE_CERTIFICATE", "APPLE_CERTIFICATE_PASSWORD", "KEYCHAIN_PASSWORD"]
};
const api = ["APPLE_API_ISSUER", "APPLE_API_KEY", "APPLE_API_PRIVATE_KEY"];
const appleId = ["APPLE_ID", "APPLE_PASSWORD", "APPLE_TEAM_ID"];

function environment(extra = {}) {
  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (/^(APPLE_|WINDOWS_|LINUX_GPG_|TAURI_|SIGN$|SIGN_KEY$|APPIMAGETOOL_|GITHUB_|QIRING_|CARGO_TARGET_DIR$|KEYCHAIN_PASSWORD$)/.test(key)) delete env[key];
  }
  return { ...env, ...extra };
}

function write(path, contents) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, contents);
}

function fixture(t) {
  const root = mkdtempSync(join(os.tmpdir(), "qiring-release-test-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const desktop = join(root, "apps/desktop");
  mkdirSync(desktop, { recursive: true });
  cpSync(join(desktopRoot, "scripts"), join(desktop, "scripts"), { recursive: true });
  write(join(desktop, "package.json"), JSON.stringify(packageJson));
  write(join(desktop, "src-tauri/tauri.conf.json"), JSON.stringify({ version: "1.2.3" }));
  return { root, desktop, bundle: join(root, "target/release/bundle") };
}

function script(desktop, name, args = [], extra = {}) {
  return spawnSync(process.execPath, [join(desktop, "scripts", name), ...args], {
    cwd: desktop, env: environment(extra), encoding: "utf8"
  });
}

function succeeds(result) {
  assert.equal(result.status, 0, `${result.error || ""}\n${result.stdout}\n${result.stderr}`);
}

function credentials(names) {
  return Object.fromEntries(names.map((key) => [key, key === "WINDOWS_TIMESTAMP_URL" ? "https://timestamp.example.test" : "test-secret"]));
}

for (const platform of Object.keys(signingGroups)) {
  test(`${platform}: no settings allow unsigned builds; any partial set fails`, (t) => {
    const { desktop, root } = fixture(t);
    const output = join(root, "output");
    succeeds(script(desktop, "check-signing-env.mjs", [platform], { GITHUB_OUTPUT: output }));
    assert.equal(readFileSync(output, "utf8"), "enabled=false\n");
    const fields = platform === "macos" ? [...signingGroups.macos, ...api, ...appleId, "APPLE_SIGNING_IDENTITY"] : signingGroups[platform];
    for (const field of fields) {
      const result = script(desktop, "check-signing-env.mjs", [platform], credentials([field]));
      assert.notEqual(result.status, 0, field);
      assert.match(result.stderr, /Incomplete/);
      assert.doesNotMatch(result.stderr, /test-secret/);
    }
    const complete = [...signingGroups[platform], ...(platform === "macos" ? api : [])];
    succeeds(script(desktop, "check-signing-env.mjs", [platform], { ...credentials(complete), GITHUB_OUTPUT: output }));
    assert.equal(readFileSync(output, "utf8"), "enabled=false\nenabled=true\n");
  });
}

test("Apple ID notarization is accepted; partial alternate credentials and invalid timestamps fail", () => {
  succeeds(script(desktopRoot, "check-signing-env.mjs", ["macos"], credentials([...signingGroups.macos, ...appleId])));
  assert.notEqual(script(desktopRoot, "check-signing-env.mjs", ["macos"], credentials([...signingGroups.macos, ...appleId, api[0]])).status, 0);
  assert.notEqual(script(desktopRoot, "check-signing-env.mjs", ["windows"], { ...credentials(signingGroups.windows), WINDOWS_TIMESTAMP_URL: "file:///tmp/timestamp" }).status, 0);
  assert.notEqual(script(desktopRoot, "check-signing-env.mjs", ["unknown"]).status, 0);
  assert.notEqual(script(desktopRoot, "check-signing-env.mjs", ["macos"], { APPLE_SIGNING_IDENTITY: " " }).status, 0);
});

test("version checks resolve workspace inheritance and reject mismatched tags or application versions", (t) => {
  const { root, desktop } = fixture(t);
  write(join(root, "Cargo.toml"), '[workspace]\nmembers = ["apps/desktop/src-tauri"]\nresolver = "2"\n[workspace.package]\nversion = "1.2.3"\n');
  write(join(desktop, "src-tauri/Cargo.toml"), '[package]\nname = "release-test"\nversion.workspace = true\nedition = "2021"\n');
  write(join(desktop, "src-tauri/src/lib.rs"), "");
  write(join(desktop, "package.json"), JSON.stringify({ version: "1.2.3" }));
  succeeds(script(desktop, "check-release-version.mjs", ["v1.2.3"]));
  succeeds(script(desktop, "check-release-version.mjs", [], { GITHUB_REF_TYPE: "branch", GITHUB_REF_NAME: "main" }));
  for (const tag of ["v1.2.4", "1.2.3", "v1.2.3-extra", ""]) {
    assert.notEqual(script(desktop, "check-release-version.mjs", [tag]).status, 0);
  }
  assert.notEqual(script(desktop, "check-release-version.mjs", [], { GITHUB_REF_TYPE: "tag", GITHUB_REF_NAME: "v9.0.0" }).status, 0);
  for (const file of [join(root, "Cargo.toml"), join(desktop, "package.json"), join(desktop, "src-tauri/tauri.conf.json")]) {
    const original = readFileSync(file, "utf8");
    write(file, original.replaceAll("1.2.3", "1.2.4"));
    const result = script(desktop, "check-release-version.mjs", ["v1.2.3"]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /versions must match/);
    write(file, original);
  }
});

test("npm forwards Windows configuration to Tauri and renames only after a successful build", (t) => {
  const { desktop, root, bundle } = fixture(t);
  const stub = join(desktop, "tauri-stub.cjs");
  const log = join(root, "args.json");
  write(stub, 'require("node:fs").writeFileSync(process.env.ARG_LOG, JSON.stringify(process.argv.slice(2))); process.exit(Number(process.env.STUB_EXIT || 0));');
  const bin = join(desktop, "node_modules/.bin/tauri");
  write(bin, `#!/bin/sh\nexec '${process.execPath.replaceAll("'", "'\\''")}' '${stub.replaceAll("'", "'\\''")}' "$@"\n`);
  chmodSync(bin, 0o755);
  write(`${bin}.cmd`, `@"${process.execPath}" "${stub}" %*\r\n`);
  const source = join(bundle, "msi/original.msi");
  write(source, "test installer");
  const config = join(root, "signing config.json");
  const run = (exit) => spawnSync(process.execPath, [process.env.npm_execpath, "run", "build:windows", "--", "--config", config], {
    cwd: desktop, env: environment({ ARG_LOG: log, QIRING_OUTPUT_NAME: "Custom", STUB_EXIT: String(exit) }), encoding: "utf8"
  });
  assert.notEqual(run(7).status, 0);
  assert.equal(readFileSync(source, "utf8"), "test installer");
  succeeds(run(0));
  assert.deepEqual(JSON.parse(readFileSync(log, "utf8")), ["build", "--bundles", "msi", "--config", config]);
  assert.deepEqual(readdirSync(join(bundle, "msi")), ["Custom.msi"]);
});

for (const [platform, files] of Object.entries({
  linux: ["appimage/QiRing.AppImage", "deb/QiRing.deb", "portable/QiRing_portable.tar.gz"],
  macos: ["dmg/QiRing.dmg"],
  windows: ["msi/QiRing.msi", "portable/QiRing_portable.zip"]
})) {
  test(`${platform}: collect final assets only and generate distinct, repeatable checksums`, (t) => {
    const { desktop, root } = fixture(t);
    const target = join(root, "custom-target");
    const bundle = join(target, "release/bundle");
    for (const file of files) write(join(bundle, file), `contents of ${file}`);
    write(join(bundle, "macos/QiRing.app/Contents/Resources/internal.zip"), "not a release asset");
    write(join(bundle, "appimage/QiRing.AppDir/usr/internal.exe"), "not a release asset");
    succeeds(script(desktop, "collect-release.mjs", [platform], { CARGO_TARGET_DIR: target }));
    const assets = join(desktop, "release-assets");
    assert.equal(readdirSync(assets).length, files.length);
    succeeds(script(desktop, "checksums.mjs", [platform]));
    const checksums = readFileSync(join(assets, `${platform}-SHA256SUMS`), "utf8");
    for (const line of checksums.trim().split("\n")) {
      const [digest, name] = line.split("  ");
      assert.equal(createHash("sha256").update(readFileSync(join(assets, name))).digest("hex"), digest);
    }
    succeeds(script(desktop, "checksums.mjs", [platform]));
    assert.equal(readFileSync(join(assets, `${platform}-SHA256SUMS`), "utf8"), checksums);
    write(join(bundle, files[0]), "");
    assert.notEqual(script(desktop, "collect-release.mjs", [platform], { CARGO_TARGET_DIR: target }).status, 0);
    write(join(bundle, files[0]), "restored");
    rmSync(join(bundle, files.at(-1)));
    assert.notEqual(script(desktop, "collect-release.mjs", [platform], { CARGO_TARGET_DIR: target }).status, 0);
  });
}

test("Linux portable archive contains the executable and marker with executable permissions", { skip: process.platform !== "linux" }, (t) => {
  const { root, desktop } = fixture(t);
  const target = join(root, "custom-target");
  const launcher = join(target, "release/bundle/appimage/QiRing.AppImage");
  write(launcher, "test AppImage");
  chmodSync(launcher, 0o755);
  succeeds(script(desktop, "enable-portable.mjs", ["appimage"], { CARGO_TARGET_DIR: target }));
  succeeds(script(desktop, "package-portable.mjs", ["appimage"], { CARGO_TARGET_DIR: target }));
  const archive = join(target, "release/bundle/portable/QiRing_1.2.3_amd64_portable.tar.gz");
  const listing = spawnSync("tar", ["-tvzf", archive], { encoding: "utf8" });
  succeeds(listing);
  assert.match(listing.stdout, /-rwxr-xr-x.*QiRing.AppImage/);
  assert.match(listing.stdout, /qiring-portable/);
});

test("Windows portable archive is a ZIP containing the executable and marker", { skip: process.platform !== "win32" }, (t) => {
  const { root, desktop } = fixture(t);
  const target = join(root, "custom-target");
  write(join(target, "release/qiring-desktop.exe"), "test Windows executable");
  succeeds(script(desktop, "enable-portable.mjs", ["windows"], { CARGO_TARGET_DIR: target }));
  succeeds(script(desktop, "package-portable.mjs", ["windows"], { CARGO_TARGET_DIR: target }));
  const portable = join(target, "release/bundle/portable");
  const [name] = readdirSync(portable);
  const archive = join(portable, name);
  assert.equal(readFileSync(archive).subarray(0, 2).toString(), "PK");
  const listing = spawnSync("tar", ["-tf", archive], { encoding: "utf8" });
  succeeds(listing);
  assert.deepEqual(listing.stdout.trim().split(/\r?\n/).sort(), ["qiring-desktop.exe", "qiring-portable"]);
});

test("macOS smoke checks inspect and detach the mounted DMG, even if signing verification fails", { skip: process.platform === "win32" }, (t) => {
  const { root, bundle } = fixture(t);
  write(join(bundle, "dmg/QiRing.dmg"), "test disk image");
  const block = workflow.split("      - name: Smoke test macOS installer\n")[1].split("\n      - name:")[0];
  const shell = block.split("        run: |\n")[1].split("\n").map((line) => line.replace(/^          /, "")).join("\n");
  const mocks = `
hdiutil() {
  echo "hdiutil $*" >> "$SMOKE_LOG"
  if [ "$1" = "attach" ]; then
    mount_dir="\${!#}"
    mkdir -p "$mount_dir/QiRing.app/Contents"
    touch "$mount_dir/QiRing.app/Contents/Info.plist"
  fi
}
codesign() { echo "codesign $*" >> "$SMOKE_LOG"; return "$SIGN_EXIT"; }
xcrun() { echo "xcrun $*" >> "$SMOKE_LOG"; }
`;
  for (const mode of ["unsigned", "signed", "invalid-signature"]) {
    const log = join(root, `${mode}.log`);
    const result = spawnSync("bash", ["-c", mocks + shell], {
      cwd: root, encoding: "utf8",
      env: environment({ TMPDIR: root, SMOKE_LOG: log, APPLE_CERTIFICATE: mode === "unsigned" ? "" : "test-certificate", SIGN_EXIT: mode === "invalid-signature" ? "1" : "0" })
    });
    if (mode === "invalid-signature") assert.notEqual(result.status, 0);
    else succeeds(result);
    const calls = readFileSync(log, "utf8");
    assert.match(calls, /hdiutil attach .* -readonly -nobrowse -mountpoint/);
    assert.match(calls, /hdiutil detach/);
    if (mode === "unsigned") assert.doesNotMatch(calls, /codesign|xcrun/);
    if (mode === "signed") assert.match(calls, /xcrun stapler validate .*\/QiRing.app/);
  }
});

test("draft workflow creates drafts, retries drafts, and refuses published releases", { skip: process.platform === "win32" }, (t) => {
  const { root } = fixture(t);
  const block = workflow.split("      - name: Create or update draft GitHub release\n")[1];
  assert.ok(block);
  const shell = block.split("        run: |\n")[1].split("\n").map((line) => line.replace(/^          /, "")).join("\n");
  const stub = join(root, "bin/gh");
  write(stub, `#!${process.execPath}
const fs = require('node:fs');
const args = process.argv.slice(2);
fs.appendFileSync(process.env.GH_LOG, JSON.stringify(args) + '\\n');
if (process.env.GH_REPO !== 'example/qiring') process.exit(99);
if (args[1] === 'view') {
  if (process.env.RELEASE_STATE === 'missing') process.exit(1);
  console.log(process.env.RELEASE_STATE === 'draft' ? 'true' : 'false');
}
if (args[1] === 'create' && process.env.CREATE_FAIL === '1') process.exit(1);
`);
  chmodSync(stub, 0o755);
  write(join(root, "release-assets/linux-QiRing.deb"), "asset");
  for (const state of ["missing", "draft", "published", "create-failure"]) {
    const log = join(root, `${state}.jsonl`);
    const result = spawnSync("bash", ["-c", shell], {
      cwd: root,
      env: environment({ PATH: `${dirname(stub)}:${process.env.PATH}`, GH_LOG: log, GH_REPO: "example/qiring", RELEASE_TAG: "v1.2.3", RELEASE_STATE: state === "create-failure" ? "missing" : state, CREATE_FAIL: state === "create-failure" ? "1" : "0" }),
      encoding: "utf8"
    });
    const calls = readFileSync(log, "utf8").trim().split("\n").map(JSON.parse);
    if (state === "published" || state === "create-failure") {
      assert.notEqual(result.status, 0);
      assert.ok(calls.every((args) => args[1] !== "upload"));
    } else {
      succeeds(result);
      assert.ok(calls.some((args) => args[1] === "upload" && args.includes("release-assets/linux-QiRing.deb")));
    }
    for (const args of calls.filter((args) => args[1] === "create")) {
      assert.ok(args.includes("--draft"));
      assert.ok(args.includes("--verify-tag"));
    }
  }
});
