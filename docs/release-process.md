# QiRing release process

Pushing a version tag such as `v0.1.2` starts **Release desktop bundles** in GitHub Actions. After all three platform builds succeed, the workflow creates a **draft** GitHub release and attaches the assets. A maintainer reviews the draft and clicks **Publish release** manually. The workflow never publishes it automatically.

Signing is optional for both tagged releases and manual test builds. You can release unsigned builds without buying certificates or setting signing secrets. Each platform decides independently whether to sign, so a release can contain both signed and unsigned platform builds.

## What is produced

| Platform | Downloads |
| --- | --- |
| Linux | AppImage, DEB installer, and `_portable.tar.gz` archive |
| Windows | MSI installer and `_portable.zip` archive |
| macOS | DMG installer containing QiRing.app |

Portable archives contain the launcher and a `qiring-portable` marker. Extract both into the same writable folder; QiRing creates `QiRingData` there on first launch. The Windows portable archive uses the executable extracted from the MSI, including its signature when signing is enabled. Tauri restores the unsigned build output after bundling, so the workflow packages the extracted installer payload.

Each platform also produces an SPDX JSON software bill of materials (SBOM: an inventory of dependencies) and a separately named checksum file: `linux-SHA256SUMS`, `windows-SHA256SUMS`, or `macos-SHA256SUMS`. These names prevent one platform's checksums from overwriting another's. GitHub stores build-provenance attestations for the uploaded files; these attestations are separate from platform code signatures.

## Prepare the version and run checks

1. Choose an unused version, for example `0.1.3`. Update these files to the same value, without the leading `v`:
   - `Cargo.toml`: `[workspace.package].version` (the Rust crates inherit this version).
   - `apps/desktop/package.json`: `version`.
   - `apps/desktop/src-tauri/tauri.conf.json`: `version`.
2. Refresh the lockfile version metadata after changing versions. From the repository root, run `npm --prefix apps/desktop install --package-lock-only`. After building the frontend, run `cargo check --workspace` to refresh Cargo's workspace version metadata. Review and include the resulting `apps/desktop/package-lock.json` and `Cargo.lock` changes with your release changes.
3. Run the local checks below. Install the desktop prerequisites in [development.md](development.md) first. Replace `v0.1.3` with your chosen tag.

```sh
npm --prefix apps/desktop ci
node apps/desktop/scripts/check-release-version.mjs v0.1.3
npm --prefix apps/desktop run test:release
npm --prefix apps/desktop run test:ui-contract
npm --prefix apps/desktop run build
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --locked
```

The frontend build must precede Rust checks and tests: the desktop Rust crate embeds `apps/desktop/web-dist`. The version checker uses offline Cargo metadata to resolve workspace versions without compiling or downloading dependencies. It rejects mismatched Rust/frontend/Tauri versions and tags that are not exactly `v` plus the application version. A manual build from a branch checks version consistency without requiring a tag; a manual build from a tag also checks that tag.

Wait for the normal **CI** workflow to pass on the exact changes being released. CI checks version consistency, release tooling, formatting, Rust linting/tests, a native Linux debug build, JavaScript and Rust dependency audits, UI contracts, and browser/accessibility tests. The native build also catches mismatched Tauri JavaScript/Rust versions: keep `@tauri-apps/api` and the Rust `tauri` crate on the same major/minor version when updating dependencies. This check does not package installers; use the manual release workflow below to test all three platforms. The release workflow runs its own tooling and Rust tests, but does not repeat every CI check or automatically wait for CI.

## Optional signing

For unsigned builds, leave all signing secrets for that platform unset. For signed builds, open **Settings → Secrets and variables → Actions → New repository secret** and supply the complete applicable set below. Never commit private keys or passwords to the repository. Organization secrets can also be used if this repository has access to them.

| Platform | Required secrets when signing |
| --- | --- |
| Linux | `LINUX_GPG_PRIVATE_KEY` (base64-encoded private-key export), `LINUX_GPG_KEY_ID`, `LINUX_GPG_PASSPHRASE` |
| Windows | `WINDOWS_CERTIFICATE` (base64-encoded PFX containing the private key), `WINDOWS_CERTIFICATE_PASSWORD`, `WINDOWS_TIMESTAMP_URL` (the certificate provider's HTTP/HTTPS timestamp service) |
| macOS | `APPLE_CERTIFICATE` (base64-encoded P12), `APPLE_CERTIFICATE_PASSWORD`, `KEYCHAIN_PASSWORD` (a password for the temporary build keychain), plus one complete notarization set below |

For macOS notarization, supply either:

- `APPLE_API_ISSUER`, `APPLE_API_KEY` (key ID), and `APPLE_API_PRIVATE_KEY` (the raw `.p8` file contents); or
- `APPLE_ID`, `APPLE_PASSWORD` (app-specific password), and `APPLE_TEAM_ID`.

`APPLE_SIGNING_IDENTITY` is optional when the full macOS signing set is present; otherwise the workflow derives the identity from the imported certificate. Remove unused, partial notarization settings when changing authentication methods. This workflow expects nonempty certificate passwords and a nonempty Linux passphrase. See Tauri's [macOS signing guide](https://v2.tauri.app/distribute/sign/macos/) and [Windows signing guide](https://v2.tauri.app/distribute/sign/windows/) for certificate setup.

If any signing setting is supplied for a platform, its full required set must be present. Incomplete settings fail before compilation, including on manual runs. Complete settings enable certificate/key import, signing, and verification. Invalid keys, incorrect passwords, failed signing, or failed verification stop the job; the workflow does not silently fall back to unsigned output.

Linux signing applies to the AppImage, including the copy inside the portable archive; it does not sign the DEB. Windows checks Authenticode signatures on the MSI and extracted executables. macOS checks the app's signature and notarization staple. The Linux smoke test checks for an embedded AppImage signature; it does not independently establish trust in that signing key.

Tauri updater artifacts are currently disabled (`createUpdaterArtifacts: false`). `TAURI_SIGNING_PRIVATE_KEY` and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` are for updater signatures if that feature is enabled later; they do not replace platform credentials and are not needed for this release process. Git tag signing is also separate from signing installers.

Unsigned Windows/macOS applications may show operating-system trust warnings or be blocked by default launch policies. macOS tooling may apply an ad-hoc signature as required by the platform; that is not Developer ID signing or notarization. State the signing status for each platform in the release notes.

## Test the workflow without creating a release

1. Push the reviewed workflow changes to a branch when ready. The workflow must also exist on the default branch for GitHub to offer its **Run workflow** button.
2. Open **Actions → Release desktop bundles → Run workflow**, choose the branch, and start it.
3. Wait for the Linux, macOS, and Windows jobs. Open the run's summary and download its `qiring-linux`, `qiring-macos`, and `qiring-windows` artifacts.

Manual `workflow_dispatch` runs exercise builds, packaging, smoke checks, SBOMs, checksums, and attestations. They never create or update a GitHub release, even when dispatched against a tag. Signing follows the available secrets; to test fully unsigned builds, use a repository without those platform secrets.

## Push a version tag and find the draft

Once changes are reviewed, committed, pushed, and CI is green, create the tag on that exact commit. These are instructions for the maintainer to run when ready; preparing or testing the workflow does not create a tag.

```sh
git tag -a v0.1.3 -m "QiRing 0.1.3"
git push origin v0.1.3
```

Use `git tag -s` instead of `git tag -a` if you have Git tag signing configured. A signed tag is optional and independent of installer signing. Push only the intended version tag, and do not move an existing release tag to a different commit.

Open **Actions → Release desktop bundles** and select the run for that tag. It checks versions and credentials before compilation, builds frontend assets before Rust tests, and builds all three platforms. It then:

- Extracts the Linux AppImage, DEB, and portable archive, checking the executable and marker.
- Verifies and mounts the macOS DMG to check its app bundle, plus signing/notarization when configured. Tauri removes the temporary `.app` after a DMG-only build, so this check uses the app inside the actual installer.
- Administratively extracts the Windows MSI and expands the portable ZIP, checking their contents and signatures when configured.
- Collects final bundles, generates SBOMs and platform checksums, attests the files, and uploads workflow artifacts.
- Downloads all platforms, verifies their checksums, and creates or updates the draft with all collected downloads, SBOMs, and checksum files attached.

After **all jobs**, including `publish`, are green, open the repository's **Releases** page while signed in with repository write access. Find the entry marked **Draft** for your tag and click its edit button. The draft starts with generated release notes. Draft creation uses GitHub CLI's [`--draft` option](https://cli.github.com/manual/gh_release_create), with `GH_REPO` set explicitly to the current repository.

If a platform fails, inspect that job's log before retrying. Rerunning a failed workflow can replace assets on an existing draft. If an upload fails partway through, the draft can be incomplete: wait for a fully successful run and inspect its assets. Reruns refuse to change an already published release. Never publish while a build or rerun is in progress; a rerun means the replaced downloads need review again.

## Manual checks and publishing

Passing automation proves the configured checks passed; it does not prove that the application launches and works on every supported system. Before publishing, download the exact draft assets and check the following on clean Linux, Windows, and macOS machines or VMs:

- Confirm the expected installers and both portable archives are attached, with all three SBOMs and checksum files. Confirm versions and architectures in the filenames.
- Verify the checksums. From the folder containing a platform's downloads, use `sha256sum --check linux-SHA256SUMS` on Linux or `shasum -a 256 -c macos-SHA256SUMS` on macOS. On Windows, use `Get-FileHash -Algorithm SHA256 .\windows-<artifact-name>` and compare the hash with its line in `windows-SHA256SUMS`. Download the SBOM too if checking every line in a checksum file.
- Verify build provenance with `gh attestation verify <downloaded-file> --repo OWNER/REPO`, replacing the placeholders with your asset and repository. Confirm the expected tag commit and release workflow. Check the expected signing identity when signing was enabled, including the AppImage key through your trusted verification process.
- Install and launch each native installer. Extract each portable archive, keep its marker beside the launcher, and verify that it uses a local `QiRingData` folder.
- Exercise first-run vault creation, lock/unlock, recovery, backup/import, and upgrades from the previous release using test data. Check that existing vaults survive the upgrade.
- Edit the draft notes to describe changes, signing status, supported platforms, installation instructions, and known issues. Mark prereleases appropriately if applicable.

When those checks pass, click **Publish release** on the draft's edit page. This is the manual step that makes the release public. Announce it only after verifying the published downloads.
