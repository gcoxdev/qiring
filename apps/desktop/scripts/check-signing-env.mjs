import { appendFileSync } from "node:fs";

const platform = process.argv[2];

const required = {
  linux: ["LINUX_GPG_PRIVATE_KEY", "LINUX_GPG_KEY_ID", "LINUX_GPG_PASSPHRASE"],
  macos: ["APPLE_CERTIFICATE", "APPLE_CERTIFICATE_PASSWORD", "KEYCHAIN_PASSWORD"],
  windows: ["WINDOWS_CERTIFICATE", "WINDOWS_CERTIFICATE_PASSWORD", "WINDOWS_TIMESTAMP_URL"]
}[platform];

if (!required) throw new Error(`Unknown release platform: ${platform}`);
const apiKey = ["APPLE_API_ISSUER", "APPLE_API_KEY", "APPLE_API_PRIVATE_KEY"];
const appleId = ["APPLE_ID", "APPLE_PASSWORD", "APPLE_TEAM_ID"];
const settings = platform === "macos"
  ? [...required, "APPLE_SIGNING_IDENTITY", ...apiKey, ...appleId]
  : required;
const has = (name) => Boolean(process.env[name]?.trim());
const signing = settings.some((name) => Boolean(process.env[name]));
if (!signing) {
  console.log(`No ${platform} signing credentials supplied; building unsigned.`);
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, "enabled=false\n");
  process.exit(0);
}
const missing = required.filter((name) => !has(name));

if (platform === "macos") {
  const hasApiKey = apiKey.every(has);
  const hasAppleId = appleId.every(has);
  for (const group of [apiKey, appleId]) {
    if (group.some(has)) missing.push(...group.filter((name) => !has(name)));
  }
  if (!hasApiKey && !hasAppleId) {
    missing.push("Apple notarization credentials (API key or Apple ID set)");
  }
}

if (missing.length > 0) {
  throw new Error(`Incomplete ${platform} signing configuration; missing: ${missing.join(", ")}. Supply the complete set or remove all ${platform} signing settings to build unsigned.`);
}

if (platform === "windows") {
  const timestampUrl = new URL(process.env.WINDOWS_TIMESTAMP_URL);
  if (!["http:", "https:"].includes(timestampUrl.protocol)) {
    throw new Error("WINDOWS_TIMESTAMP_URL must use HTTP or HTTPS.");
  }
}
console.log(`Complete ${platform} signing configuration supplied; signing and verification are required.`);
if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, "enabled=true\n");
