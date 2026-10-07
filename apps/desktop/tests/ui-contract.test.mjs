import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const read = (path) => readFile(new URL(path, import.meta.url), "utf8");

test("production webview boundary is explicit and least privilege", async () => {
  const config = JSON.parse(await read("../src-tauri/tauri.conf.json"));
  assert.equal(config.identifier, "app.qiring.desktop");
  assert.equal(config.app.withGlobalTauri, false);
  assert.equal(config.app.windows[0].minWidth, 800);
  assert.equal(config.app.windows[0].minHeight, 600);
  assert.equal(config.app.windows[0].incognito, true);
  assert.match(config.app.security.csp, /object-src 'none'/);
  assert.doesNotMatch(config.app.security.csp, /unsafe-inline|unsafe-eval/);

  const capability = JSON.parse(await read("../src-tauri/capabilities/main.json"));
  assert.equal(capability.permissions.includes("core:default"), false);
  assert.equal(capability.permissions.includes("allow-prepare-recovery-print"), true);
  assert.equal(capability.permissions.includes("allow-get-bootstrap-theme"), true);
  assert.equal(capability.permissions.includes("allow-set-bootstrap-theme"), true);
  assert.equal(capability.permissions.includes("allow-export-plaintext-csv-dialog"), true);
  assert.equal(capability.permissions.includes("allow-import-selected-plaintext-csv"), true);
  assert.equal(capability.permissions.includes("allow-launch-website"), true);
  assert.equal(capability.permissions.some((permission) => typeof permission === "object" && permission.identifier === "opener:allow-open-url"), false);
});

test("native builds re-embed freshly generated frontend assets", async () => {
  const buildScript = await read("../src-tauri/build.rs");
  assert.match(buildScript, /cargo:rerun-if-changed=\.\.\/web-dist/);
});

test("Tauri build manifest generates every app command permission", async () => {
  const buildScript = await read("../src-tauri/build.rs");
  const capability = JSON.parse(await read("../src-tauri/capabilities/main.json"));
  const appPermissions = capability.permissions
    .filter((permission) => typeof permission === "string" && permission.startsWith("allow-"));

  for (const permission of appPermissions) {
    const command = permission.slice("allow-".length).replaceAll("-", "_");
    assert.match(buildScript, new RegExp(`"${command}"`), `${permission} is missing from build.rs`);
  }
});

test("plaintext transfer requires preview, mapping, and export confirmation", async () => {
  const source = await read("../src/main.js");
  const backend = await read("../src-tauri/src/lib.rs");
  assert.match(source, /Export every Qi as plaintext/);
  assert.match(source, /previewPlaintextCsv/);
  assert.match(source, /include_unmapped_in_notes/);
  assert.match(backend, /selected_csv_imports/);
  assert.match(backend, /preview_selected_plaintext_csv/);
});

test("frontend does not inject user-controlled HTML", async () => {
  const source = await read("../src/main.js");
  const backend = await read("../src-tauri/src/lib.rs");
  assert.doesNotMatch(source, /\.innerHTML\s*=/);
  assert.doesNotMatch(source, /insertAdjacentHTML|document\.write/);
  assert.doesNotMatch(backend, /Command::new|fn open_url/);
});

test("native form controls follow the active color scheme", async () => {
  const css = await read("../src/styles.css");
  assert.match(css, /select option[\s\S]*color-scheme:\s*inherit/);
  assert.match(css, /select option[\s\S]*background-color:\s*var\(--surface-2\)/);
  assert.match(css, /select option[\s\S]*color:\s*var\(--text\)/);
});

test("pre-unlock theme uses the app-owned preference file instead of Web storage", async () => {
  const bootstrap = await read("../src/theme-bootstrap.js");
  const backend = await read("../src-tauri/src/lib.rs");
  assert.doesNotMatch(bootstrap, /localStorage|sessionStorage/);
  assert.match(bootstrap, /get_bootstrap_theme/);
  assert.match(bootstrap, /set_bootstrap_theme/);
  assert.match(backend, /ui-preferences\.json/);
});

test("favicon import is capability scoped and blocks private networks", async () => {
  const backend = await read("../src-tauri/src/lib.rs");
  const capability = JSON.parse(await read("../src-tauri/capabilities/main.json"));
  assert.equal(capability.permissions.includes("allow-fetch-favicon"), true);
  assert.match(backend, /no_proxy\(\)/);
  assert.match(backend, /addresses\.iter\(\)\.any\(\|address\| !is_public_ip/);
  assert.match(backend, /MAX_QI_ICON_BYTES/);
});

test("release workflow publishes installer and portable targets", async () => {
  const workflow = await read("../../../.github/workflows/release.yml");
  const collector = await read("../scripts/collect-release.mjs");
  const packager = await read("../scripts/package-portable.mjs");
  assert.match(workflow, /npm run build:\$\{\{ matrix\.platform \}\}/);
  assert.match(workflow, /package-portable\.mjs appimage/);
  assert.match(workflow, /enable-portable\.mjs windows/);
  assert.match(workflow, /npm run build:windows/);
  assert.match(workflow, /package-portable\.mjs windows/);
  assert.match(collector, /linux: \["\.appimage", "\.deb", "_portable\.tar\.gz"\]/);
  assert.match(collector, /windows: \["\.msi", "_portable\.zip"\]/);
  assert.match(packager, /"qiring-portable"/);
});

test("password-derived vault work runs off the Tauri main thread", async () => {
  const backend = await read("../src-tauri/src/lib.rs");
  assert.match(backend, /async fn unlock_vault_master[\s\S]*?run_service_blocking/);
  assert.match(backend, /async fn unlock_vault_recovery[\s\S]*?run_service_blocking/);
  assert.match(backend, /async fn rotate_master_password[\s\S]*?run_service_blocking/);
  assert.match(backend, /async fn run_service_blocking[\s\S]*?spawn_blocking/);
});

test("window state is durable and Linux backend selection is explicit", async () => {
  const backend = await read("../src-tauri/src/lib.rs");
  const launcher = await read("../../../scripts/run-desktop.sh");
  assert.match(backend, /WINDOW_BOUNDS_PERSIST_DELAY/);
  assert.match(backend, /persist_window_bounds_if_settled/);
  assert.match(backend, /absolute_window_position_supported/);
  assert.match(launcher, /QIRING_WINDOW_BACKEND/);
  assert.match(launcher, /--x11/);
  assert.match(launcher, /--wayland/);
  assert.match(launcher, /WINIT_UNIX_BACKEND/);
});

test("Linux recovery printing does not force a GTK file format", async () => {
  const backend = await read("../src-tauri/src/lib.rs");
  assert.match(backend, /settings\.set\("output-basename"/);
  assert.doesNotMatch(backend, /settings\.set\("output-file-format"/);
});

test("keyboard shortcut labels use the active operating-system convention", async () => {
  const { formatShortcut, shortcutAriaLabel, shortcutModifier } = await import("../src/shortcuts.js");

  assert.equal(shortcutModifier("Linux x86_64"), "Ctrl");
  assert.equal(formatShortcut("K", "Linux x86_64"), "Ctrl+K");
  assert.equal(formatShortcut("Shift+U", "Win32"), "Ctrl+Shift+U");
  assert.equal(shortcutModifier("MacIntel"), "⌘");
  assert.equal(formatShortcut("K", "MacIntel"), "⌘K");
  assert.equal(formatShortcut("Shift+U", "MacIntel"), "⌘⇧U");
  assert.equal(shortcutAriaLabel("Shift+U", "MacIntel"), "Command plus Shift plus U");
});
