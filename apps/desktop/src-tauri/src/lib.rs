use anyhow::Context;
use base64::Engine;
use dom_query::Document;
use qiring_core::{
    csv_template_bytes, sniff_image_media_type, AppSettings, BackupManifest, BackupPreview, BackupSnapshot,
    CsvColumnMapping, CsvImportPreview, CsvImportReport, GeneratedPassword, HealthReport, ImportReport,
    ItemInput, ItemPatch, ItemSummary, ListFilter, PasswordPolicy, PasswordProfile, PlaintextExportManifest,
    RecoveryMaterial, RecoveryUnlockResult, SecurityStatus, TotpCode, UnlockResult, VaultItem, VaultService,
    VaultSummary,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager, PhysicalPosition, PhysicalSize, State, WindowEvent};
use tauri_plugin_dialog::DialogExt;
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Clone)]
struct AppState {
    service: Arc<Mutex<VaultService>>,
    clipboard: Arc<ClipboardGuard>,
    selected_backups: Arc<Mutex<HashMap<String, PathBuf>>>,
    selected_csv_imports: Arc<Mutex<HashMap<String, PathBuf>>>,
    approved_backup_directories: Arc<Mutex<HashSet<PathBuf>>>,
    window_bounds: Arc<WindowBoundsGuard>,
    pending_print_basename: Arc<Mutex<Option<String>>>,
    ui_preferences_path: PathBuf,
}

impl AppState {
    fn new(vault_path: PathBuf, window_state_path: PathBuf, ui_preferences_path: PathBuf) -> Self {
        Self {
            service: Arc::new(Mutex::new(VaultService::new(vault_path))),
            clipboard: Arc::new(ClipboardGuard::default()),
            selected_backups: Arc::new(Mutex::new(HashMap::new())),
            selected_csv_imports: Arc::new(Mutex::new(HashMap::new())),
            approved_backup_directories: Arc::new(Mutex::new(HashSet::new())),
            window_bounds: Arc::new(WindowBoundsGuard {
                path: window_state_path,
                current: Mutex::new(WindowBoundsState::default()),
                persistence: Mutex::new(()),
            }),
            pending_print_basename: Arc::new(Mutex::new(None)),
            ui_preferences_path,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, Serialize)]
struct PersistedWindowBounds {
    x: i32,
    y: i32,
    width: u32,
    height: u32,
    maximized: bool,
}

struct WindowBoundsGuard {
    path: PathBuf,
    current: Mutex<WindowBoundsState>,
    persistence: Mutex<()>,
}

#[derive(Default)]
struct WindowBoundsState {
    bounds: Option<PersistedWindowBounds>,
    revision: u64,
    persisted_revision: u64,
    changed_at: Option<Instant>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct UiPreferences {
    theme: String,
}

impl Default for UiPreferences {
    fn default() -> Self {
        Self {
            theme: "system".into(),
        }
    }
}

struct StoragePaths {
    vault: PathBuf,
    window_state: PathBuf,
    ui_preferences: PathBuf,
    portable: bool,
}

struct ClipboardGuard {
    state: Mutex<ClipboardState>,
}

struct ClipboardState {
    backend: Option<arboard::Clipboard>,
    owned: OwnedClipboard,
}

impl Default for ClipboardGuard {
    fn default() -> Self {
        Self {
            state: Mutex::new(ClipboardState {
                backend: arboard::Clipboard::new().ok(),
                owned: OwnedClipboard::default(),
            }),
        }
    }
}

#[derive(Default)]
struct OwnedClipboard {
    value: Option<Zeroizing<String>>,
    expires_at: Option<Instant>,
}

#[derive(Serialize)]
struct CreateVaultResult {
    summary: VaultSummary,
    recovery: RecoveryMaterial,
}

#[derive(Serialize)]
struct SelectedBackup {
    token: String,
    display_path: String,
}

const MAX_QI_ICON_BYTES: usize = 512 * 1024;
const MAX_FAVICON_CANDIDATES: usize = 8;
const MAX_SVG_ELEMENTS: usize = 4_096;
const MAX_SVG_NESTING_DEPTH: usize = 64;
const RASTERIZED_FAVICON_SIZE: u32 = 128;
const FAVICON_BROWSER_USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36";
const WINDOW_MIN_WIDTH: u32 = 800;
const WINDOW_MIN_HEIGHT: u32 = 600;
const WINDOW_BOUNDS_PERSIST_DELAY: Duration = Duration::from_millis(500);
const WINDOW_BOUNDS_PERSIST_POLL: Duration = Duration::from_millis(200);
const RECOVERY_PRINT_TITLE_PREFIX: &str = "QiRing-Recovery-Key-";
const PREVIOUS_APP_IDENTIFIER: &str = "dev.qiring.desktop";
#[cfg(any(target_os = "linux", target_os = "windows"))]
const PORTABLE_DATA_DIRECTORY: &str = "QiRingData";
#[cfg(any(target_os = "linux", target_os = "windows"))]
const PORTABLE_MARKER_FILE: &str = "qiring-portable";
const PORTABLE_ENVIRONMENT_VARIABLE: &str = "QIRING_PORTABLE";
const MAX_UI_PREFERENCES_BYTES: u64 = 4 * 1024;
const MAX_WINDOW_STATE_BYTES: u64 = 64 * 1024;

#[tauri::command]
async fn create_vault(
    state: State<'_, AppState>,
    master_password: String,
    settings: Option<AppSettings>,
) -> Result<CreateVaultResult, String> {
    let master_password = Zeroizing::new(master_password);
    let service = Arc::clone(&state.service);
    run_service_blocking(service, move |service| {
        let (summary, recovery) = service
            .create_vault(&master_password, settings.unwrap_or_default())
            .map_err(display_error)?;
        Ok(CreateVaultResult { summary, recovery })
    })
    .await
}

#[tauri::command]
async fn unlock_vault_master(
    state: State<'_, AppState>,
    master_password: String,
) -> Result<UnlockResult, String> {
    let master_password = Zeroizing::new(master_password);
    let service = Arc::clone(&state.service);
    run_service_blocking(service, move |service| {
        service
            .unlock_vault_master(&master_password)
            .map_err(display_error)
    })
    .await
}

#[tauri::command]
async fn unlock_vault_recovery(
    state: State<'_, AppState>,
    recovery_key: String,
    new_master_password: String,
) -> Result<RecoveryUnlockResult, String> {
    let recovery_key = Zeroizing::new(recovery_key);
    let new_master_password = Zeroizing::new(new_master_password);
    let service = Arc::clone(&state.service);
    run_service_blocking(service, move |service| {
        service
            .unlock_vault_recovery(&recovery_key, &new_master_password)
            .map_err(display_error)
    })
    .await
}

#[tauri::command]
async fn regenerate_recovery_key(
    state: State<'_, AppState>,
    master_password: String,
) -> Result<RecoveryMaterial, String> {
    let master_password = Zeroizing::new(master_password);
    let service = Arc::clone(&state.service);
    run_service_blocking(service, move |service| {
        service
            .regenerate_recovery_key(&master_password)
            .map_err(display_error)
    })
    .await
}

#[tauri::command]
async fn save_recovery_key_dialog(
    app: AppHandle,
    recovery_key: String,
    basename: String,
) -> Result<Option<String>, String> {
    let recovery_key = Zeroizing::new(recovery_key);
    let basename = recovery_print_basename(&basename)
        .ok_or_else(|| "The recovery-key export filename is invalid.".to_string())?;
    let filename = format!("{basename}.txt");
    let picker = app.clone();
    let selection = tauri::async_runtime::spawn_blocking(move || {
        picker
            .dialog()
            .file()
            .set_title("Save QiRing recovery key")
            .set_file_name(&filename)
            .add_filter("Plain text", &["txt"])
            .blocking_save_file()
    })
    .await
    .map_err(|error| format!("recovery-key save dialog failed: {error}"))?;
    let Some(selection) = selection else {
        return Ok(None);
    };
    let path = selection
        .into_path()
        .map_err(|error| format!("selected file is not a local path: {error}"))?;
    let contents = Zeroizing::new(format!(
        "QiRing recovery key\n\n{}\n\nStore this file offline. Anyone with this key and the Ring file can reset the Ring master password.\n",
        recovery_key.as_str()
    ));
    qiring_storage::save_bytes_atomic_user_directory(&path, contents.as_bytes()).map_err(display_error)?;
    Ok(Some(path.display().to_string()))
}

#[tauri::command]
fn prepare_recovery_print(state: State<'_, AppState>, basename: String) -> Result<(), String> {
    let basename = recovery_print_basename(&basename)
        .ok_or_else(|| "The recovery print filename is invalid.".to_string())?;
    *state
        .pending_print_basename
        .lock()
        .map_err(|_| "recovery print state lock poisoned".to_string())? = Some(basename.to_owned());
    Ok(())
}

#[tauri::command]
fn lock_vault(state: State<'_, AppState>) -> Result<(), String> {
    lock_service(&state)?.lock_vault();
    clear_owned_clipboard(&state);
    clear_ephemeral_authorizations(&state);
    Ok(())
}

#[tauri::command]
fn touch_activity(state: State<'_, AppState>) -> Result<(), String> {
    lock_service(&state)?.touch_activity().map_err(display_error)
}

#[tauri::command]
fn add_item(state: State<'_, AppState>, input: ItemInput) -> Result<Uuid, String> {
    lock_service(&state)?.add_item(input).map_err(display_error)
}

#[tauri::command]
fn update_item(state: State<'_, AppState>, item_id: Uuid, patch: ItemPatch) -> Result<(), String> {
    lock_service(&state)?
        .update_item(item_id, patch)
        .map_err(display_error)
}

#[tauri::command]
fn delete_item(state: State<'_, AppState>, item_id: Uuid) -> Result<(), String> {
    lock_service(&state)?.delete_item(item_id).map_err(display_error)
}

#[tauri::command]
fn undo_delete(state: State<'_, AppState>) -> Result<Uuid, String> {
    lock_service(&state)?.undo_delete().map_err(display_error)
}

#[tauri::command]
fn list_items(state: State<'_, AppState>, filter: Option<ListFilter>) -> Result<Vec<ItemSummary>, String> {
    lock_service(&state)?
        .list_items(filter.unwrap_or_default())
        .map_err(display_error)
}

#[tauri::command]
fn get_item(state: State<'_, AppState>, item_id: Uuid) -> Result<VaultItem, String> {
    lock_service(&state)?.get_item(item_id).map_err(display_error)
}

#[tauri::command]
fn get_totp_code(state: State<'_, AppState>, item_id: Uuid) -> Result<TotpCode, String> {
    lock_service(&state)?
        .get_totp_code(item_id)
        .map_err(display_error)
}

#[tauri::command]
fn generate_password(
    state: State<'_, AppState>,
    policy: Option<PasswordPolicy>,
) -> Result<GeneratedPassword, String> {
    lock_service(&state)?
        .generate_password(policy.unwrap_or_default())
        .map_err(display_error)
}

#[tauri::command]
fn list_profiles(state: State<'_, AppState>) -> Result<Vec<PasswordProfile>, String> {
    lock_service(&state)?.list_profiles().map_err(display_error)
}

#[tauri::command]
fn save_profile(state: State<'_, AppState>, profile: PasswordProfile) -> Result<Uuid, String> {
    lock_service(&state)?.save_profile(profile).map_err(display_error)
}

#[tauri::command]
fn delete_profile(state: State<'_, AppState>, profile_id: Uuid) -> Result<(), String> {
    lock_service(&state)?
        .delete_profile(profile_id)
        .map_err(display_error)
}

#[tauri::command]
fn get_settings(state: State<'_, AppState>) -> Result<AppSettings, String> {
    lock_service(&state)?.get_settings().map_err(display_error)
}

#[tauri::command]
fn update_settings(state: State<'_, AppState>, settings: AppSettings) -> Result<(), String> {
    let current = lock_service(&state)?.get_settings().map_err(display_error)?;
    if settings.backup_preferences.directory != current.backup_preferences.directory {
        let selected = settings.backup_preferences.directory.as_ref().map(PathBuf::from);
        if selected.as_ref().is_some_and(|path| {
            !state
                .approved_backup_directories
                .lock()
                .map(|approved| approved.contains(path))
                .unwrap_or(false)
        }) {
            return Err("Choose the automatic backup directory with the system dialog first.".into());
        }
    }
    let theme = settings.theme.clone();
    lock_service(&state)?
        .update_settings(settings)
        .map_err(display_error)?;
    if let Err(error) = save_ui_preferences(&state.ui_preferences_path, &UiPreferences { theme }) {
        eprintln!("Settings were saved, but the startup theme preference could not be updated: {error}");
    }
    Ok(())
}

#[tauri::command]
fn get_bootstrap_theme(state: State<'_, AppState>) -> Result<String, String> {
    load_ui_preferences(&state.ui_preferences_path)
        .map(|preferences| preferences.theme)
        .map_err(display_error)
}

#[tauri::command]
fn set_bootstrap_theme(state: State<'_, AppState>, theme: String) -> Result<(), String> {
    if !is_valid_theme(&theme) {
        return Err("Theme must be system, dark, or light.".into());
    }
    save_ui_preferences(&state.ui_preferences_path, &UiPreferences { theme }).map_err(display_error)
}

#[tauri::command]
fn health_report(state: State<'_, AppState>) -> Result<HealthReport, String> {
    lock_service(&state)?.health_report().map_err(display_error)
}

#[tauri::command]
async fn choose_backup_directory(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<Option<String>, String> {
    let picker = app.clone();
    let selection = tauri::async_runtime::spawn_blocking(move || {
        picker
            .dialog()
            .file()
            .set_title("Choose automatic backup directory")
            .blocking_pick_folder()
    })
    .await
    .map_err(|error| format!("backup directory dialog failed: {error}"))?;
    let Some(selection) = selection else {
        return Ok(None);
    };
    let path = selection
        .into_path()
        .map_err(|error| format!("selected directory is not a local path: {error}"))?;
    state
        .approved_backup_directories
        .lock()
        .map_err(|_| "state lock poisoned".to_string())?
        .insert(path.clone());
    Ok(Some(path.display().to_string()))
}

#[tauri::command]
async fn select_item_icon_dialog(app: AppHandle) -> Result<Option<String>, String> {
    let picker = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let selection = picker
            .dialog()
            .file()
            .set_title("Choose a Qi icon")
            .add_filter("Image", &["png", "jpg", "jpeg", "webp", "gif", "ico"])
            .blocking_pick_file();
        let Some(selection) = selection else {
            return Ok(None);
        };
        let path = selection
            .into_path()
            .map_err(|error| format!("selected image is not a local path: {error}"))?;
        let metadata =
            fs::metadata(&path).map_err(|error| format!("could not inspect the selected image: {error}"))?;
        if metadata.len() > MAX_QI_ICON_BYTES as u64 {
            return Err("Qi icons are limited to 512 KiB. Choose a smaller image.".into());
        }
        let bytes = fs::read(&path).map_err(|error| format!("could not read the selected image: {error}"))?;
        image_data_url(&bytes).map(Some)
    })
    .await
    .map_err(|error| format!("Qi icon dialog failed: {error}"))?
}

#[tauri::command]
async fn fetch_favicon(url: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || fetch_favicon_data_url(&url))
        .await
        .map_err(|error| format!("favicon task failed: {error}"))?
}

#[tauri::command]
fn launch_website(url: String) -> Result<(), String> {
    let url = parse_website_url(&url)?;

    #[cfg(target_os = "linux")]
    {
        // GIO launches the registered URI handler directly. This avoids KDE's
        // KIO URL-to-cache-file conversion used by xdg-open on some systems.
        gio::AppInfo::launch_default_for_uri(url.as_str(), None::<&gio::AppLaunchContext>)
            .map_err(|_| "The website could not be opened in the default browser.".to_string())
    }

    #[cfg(not(target_os = "linux"))]
    {
        tauri_plugin_opener::open_url(url.as_str(), None::<&str>)
            .map_err(|_| "The website could not be opened in the default browser.".to_string())
    }
}

fn parse_website_url(raw_url: &str) -> Result<url::Url, String> {
    let url = url::Url::parse(raw_url)
        .map_err(|_| "Enter a complete URL beginning with http:// or https://.".to_string())?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err("QiRing only opens HTTP and HTTPS website URLs.".to_string());
    }
    Ok(url)
}

#[tauri::command]
async fn export_backup_dialog(
    app: AppHandle,
    state: State<'_, AppState>,
    passphrase: String,
) -> Result<Option<BackupManifest>, String> {
    let passphrase = Zeroizing::new(passphrase);
    let picker = app.clone();
    let selection = tauri::async_runtime::spawn_blocking(move || {
        picker
            .dialog()
            .file()
            .set_title("Export encrypted QiRing backup")
            .set_file_name("qiring-ring.qiring-backup")
            .add_filter("QiRing encrypted backup", &["qiring-backup"])
            .blocking_save_file()
    })
    .await
    .map_err(|error| format!("backup save dialog failed: {error}"))?;
    let Some(selection) = selection else {
        return Ok(None);
    };
    let path = selection
        .into_path()
        .map_err(|error| format!("selected file is not a local path: {error}"))?;
    lock_service(&state)?
        .export_backup(path, &passphrase)
        .map(Some)
        .map_err(display_error)
}

#[tauri::command]
async fn select_backup_file(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<Option<SelectedBackup>, String> {
    let picker = app.clone();
    let selection = tauri::async_runtime::spawn_blocking(move || {
        picker
            .dialog()
            .file()
            .set_title("Select encrypted QiRing backup")
            .add_filter("QiRing encrypted backup", &["qiring-backup"])
            .blocking_pick_file()
    })
    .await
    .map_err(|error| format!("backup open dialog failed: {error}"))?;
    let Some(selection) = selection else {
        return Ok(None);
    };
    let path = selection
        .into_path()
        .map_err(|error| format!("selected file is not a local path: {error}"))?;
    let token = Uuid::new_v4().to_string();
    let mut selections = state
        .selected_backups
        .lock()
        .map_err(|_| "state lock poisoned".to_string())?;
    selections.clear();
    selections.insert(token.clone(), path.clone());
    Ok(Some(SelectedBackup {
        token,
        display_path: path.display().to_string(),
    }))
}

#[tauri::command]
fn preview_selected_backup(
    state: State<'_, AppState>,
    token: String,
    passphrase: String,
) -> Result<BackupPreview, String> {
    let passphrase = Zeroizing::new(passphrase);
    let path = selected_backup_path(&state, &token)?;
    lock_service(&state)?
        .preview_backup(path, &passphrase)
        .map_err(display_error)
}

#[tauri::command]
fn import_selected_backup(
    state: State<'_, AppState>,
    token: String,
    passphrase: String,
) -> Result<ImportReport, String> {
    let passphrase = Zeroizing::new(passphrase);
    let path = state
        .selected_backups
        .lock()
        .map_err(|_| "state lock poisoned".to_string())?
        .remove(&token)
        .ok_or_else(|| "Backup selection expired; choose the file again.".to_string())?;
    lock_service(&state)?
        .import_backup(path, &passphrase)
        .map_err(display_error)
}

#[tauri::command]
async fn save_csv_template_dialog(app: AppHandle) -> Result<Option<String>, String> {
    let picker = app.clone();
    let selection = tauri::async_runtime::spawn_blocking(move || {
        picker
            .dialog()
            .file()
            .set_title("Save QiRing CSV import template")
            .set_file_name("qiring-import-template.csv")
            .add_filter("CSV spreadsheet", &["csv"])
            .blocking_save_file()
    })
    .await
    .map_err(|error| format!("CSV template save dialog failed: {error}"))?;
    let Some(selection) = selection else {
        return Ok(None);
    };
    let path = selection
        .into_path()
        .map_err(|error| format!("selected file is not a local path: {error}"))?;
    qiring_storage::save_bytes_atomic_user_directory(&path, &csv_template_bytes()).map_err(display_error)?;
    Ok(Some(path.display().to_string()))
}

#[tauri::command]
async fn export_plaintext_csv_dialog(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<Option<PlaintextExportManifest>, String> {
    let picker = app.clone();
    let selection = tauri::async_runtime::spawn_blocking(move || {
        picker
            .dialog()
            .file()
            .set_title("Export plaintext QiRing CSV")
            .set_file_name("qiring-plaintext-export.csv")
            .add_filter("CSV spreadsheet", &["csv"])
            .blocking_save_file()
    })
    .await
    .map_err(|error| format!("CSV export dialog failed: {error}"))?;
    let Some(selection) = selection else {
        return Ok(None);
    };
    let path = selection
        .into_path()
        .map_err(|error| format!("selected file is not a local path: {error}"))?;
    let service = Arc::clone(&state.service);
    run_service_blocking(service, move |service| {
        service
            .export_plaintext_csv(path)
            .map(Some)
            .map_err(display_error)
    })
    .await
}

#[tauri::command]
async fn select_plaintext_csv_file(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<Option<SelectedBackup>, String> {
    let picker = app.clone();
    let selection = tauri::async_runtime::spawn_blocking(move || {
        picker
            .dialog()
            .file()
            .set_title("Select CSV spreadsheet to import")
            .add_filter("CSV spreadsheet", &["csv"])
            .blocking_pick_file()
    })
    .await
    .map_err(|error| format!("CSV open dialog failed: {error}"))?;
    let Some(selection) = selection else {
        return Ok(None);
    };
    let path = selection
        .into_path()
        .map_err(|error| format!("selected file is not a local path: {error}"))?;
    let token = Uuid::new_v4().to_string();
    let mut selections = state
        .selected_csv_imports
        .lock()
        .map_err(|_| "state lock poisoned".to_string())?;
    selections.clear();
    selections.insert(token.clone(), path.clone());
    Ok(Some(SelectedBackup {
        token,
        display_path: path.display().to_string(),
    }))
}

#[tauri::command]
async fn preview_selected_plaintext_csv(
    state: State<'_, AppState>,
    token: String,
) -> Result<CsvImportPreview, String> {
    let path = selected_csv_path(&state, &token)?;
    let service = Arc::clone(&state.service);
    run_service_blocking(service, move |service| {
        service.preview_plaintext_csv(path).map_err(display_error)
    })
    .await
}

#[tauri::command]
async fn import_selected_plaintext_csv(
    state: State<'_, AppState>,
    token: String,
    mapping: CsvColumnMapping,
) -> Result<CsvImportReport, String> {
    let path = selected_csv_path(&state, &token)?;
    let service = Arc::clone(&state.service);
    let report = run_service_blocking(service, move |service| {
        service.import_plaintext_csv(path, mapping).map_err(display_error)
    })
    .await?;
    state
        .selected_csv_imports
        .lock()
        .map_err(|_| "state lock poisoned".to_string())?
        .remove(&token);
    Ok(report)
}

#[tauri::command]
fn list_snapshots(state: State<'_, AppState>) -> Result<Vec<BackupSnapshot>, String> {
    lock_service(&state)?.list_snapshots().map_err(display_error)
}

#[tauri::command]
fn restore_snapshot(state: State<'_, AppState>, path: String) -> Result<ImportReport, String> {
    lock_service(&state)?
        .restore_snapshot(path)
        .map_err(display_error)
}

#[tauri::command]
async fn rotate_master_password(
    state: State<'_, AppState>,
    old_password: String,
    new_password: String,
) -> Result<(), String> {
    let old_password = Zeroizing::new(old_password);
    let new_password = Zeroizing::new(new_password);
    let service = Arc::clone(&state.service);
    run_service_blocking(service, move |service| {
        service
            .rotate_master_password(&old_password, &new_password)
            .map_err(display_error)
    })
    .await
}

#[tauri::command]
fn get_security_status(state: State<'_, AppState>) -> Result<SecurityStatus, String> {
    lock_service(&state)?.get_security_status().map_err(display_error)
}

#[tauri::command]
fn vault_exists(state: State<'_, AppState>) -> Result<bool, String> {
    Ok(lock_service(&state)?.vault_exists())
}

#[tauri::command]
fn copy_secret(state: State<'_, AppState>, value: String) -> Result<u32, String> {
    let value = Zeroizing::new(value);
    if value.is_empty() || value.len() > 100_000 {
        return Err("Clipboard value is empty or too large.".into());
    }
    let seconds = lock_service(&state)?
        .get_security_status()
        .map_err(display_error)?
        .clipboard_clear_seconds;
    let mut clipboard = state
        .clipboard
        .state
        .lock()
        .map_err(|_| "clipboard state lock poisoned".to_string())?;
    let backend = clipboard
        .backend
        .as_mut()
        .ok_or_else(|| "the system clipboard is unavailable".to_string())?;
    write_secret_to_clipboard(backend, value.as_str())
        .map_err(|error| format!("failed to write clipboard: {error}"))?;
    clipboard.owned.value = Some(value);
    clipboard.owned.expires_at = Instant::now().checked_add(Duration::from_secs(u64::from(seconds)));
    Ok(seconds)
}

pub fn run() {
    apply_platform_runtime_defaults();
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let storage = resolve_storage_paths(app)?;
            if storage.portable {
                eprintln!(
                    "QiRing portable mode is active. App-owned data: {}",
                    storage
                        .vault
                        .parent()
                        .map(Path::display)
                        .map(|path| path.to_string())
                        .unwrap_or_else(|| "unknown".into())
                );
            }
            let state = AppState::new(storage.vault, storage.window_state, storage.ui_preferences);
            let background_state = state.clone();
            let app_handle = app.handle().clone();
            app.manage(state);

            if let Some(window) = app.get_webview_window("main") {
                #[cfg(target_os = "linux")]
                configure_linux_print_defaults(
                    &window,
                    Arc::clone(&app.state::<AppState>().pending_print_basename),
                )?;

                let bounds = app.state::<AppState>().window_bounds.clone();
                if !restore_window_bounds(&window, &bounds) {
                    capture_window_bounds(&window.as_ref().window(), &bounds);
                }

                let persistence_bounds = bounds.clone();
                std::thread::spawn(move || loop {
                    std::thread::sleep(WINDOW_BOUNDS_PERSIST_POLL);
                    persist_window_bounds_if_settled(&persistence_bounds);
                });
            }

            std::thread::spawn(move || loop {
                std::thread::sleep(Duration::from_secs(1));
                clear_expired_clipboard_from_guard(&background_state.clipboard);
                let locked = background_state
                    .service
                    .lock()
                    .map(|mut service| service.lock_if_idle())
                    .unwrap_or(true);
                if locked {
                    clear_owned_clipboard_from_guard(&background_state.clipboard);
                    clear_ephemeral_authorizations(&background_state);
                    let _ = app_handle.emit("vault-locked", "idle");
                }
            });
            Ok(())
        })
        .on_window_event(handle_window_event)
        .invoke_handler(tauri::generate_handler![
            create_vault,
            unlock_vault_master,
            unlock_vault_recovery,
            regenerate_recovery_key,
            save_recovery_key_dialog,
            prepare_recovery_print,
            lock_vault,
            touch_activity,
            add_item,
            update_item,
            delete_item,
            undo_delete,
            list_items,
            get_item,
            get_totp_code,
            generate_password,
            list_profiles,
            save_profile,
            delete_profile,
            get_settings,
            update_settings,
            get_bootstrap_theme,
            set_bootstrap_theme,
            health_report,
            choose_backup_directory,
            select_item_icon_dialog,
            fetch_favicon,
            launch_website,
            export_backup_dialog,
            select_backup_file,
            preview_selected_backup,
            import_selected_backup,
            save_csv_template_dialog,
            export_plaintext_csv_dialog,
            select_plaintext_csv_file,
            preview_selected_plaintext_csv,
            import_selected_plaintext_csv,
            list_snapshots,
            restore_snapshot,
            rotate_master_password,
            get_security_status,
            vault_exists,
            copy_secret,
        ])
        .build(tauri::generate_context!())
        .expect("failed to build QiRing desktop app");

    app.run(|app_handle, event| {
        if matches!(
            event,
            tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit
        ) {
            let state = app_handle.state::<AppState>();
            clear_owned_clipboard_and_release(&state);
        }
    });
}

fn recovery_print_basename(title: &str) -> Option<&str> {
    (title.starts_with(RECOVERY_PRINT_TITLE_PREFIX)
        && title.len() <= 64
        && title
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'))
    .then_some(title)
}

#[cfg(target_os = "linux")]
fn configure_linux_print_defaults(
    window: &tauri::WebviewWindow,
    pending_basename: Arc<Mutex<Option<String>>>,
) -> tauri::Result<()> {
    window.with_webview(|platform_webview| {
        use webkit2gtk::{PrintOperationExt, WebViewExt};

        platform_webview.inner().connect_print(move |webview, operation| {
            let basename = pending_basename
                .lock()
                .ok()
                .and_then(|mut pending| pending.take())
                .or_else(|| {
                    webview
                        .title()
                        .and_then(|title| recovery_print_basename(title.as_str()).map(str::to_owned))
                });
            let Some(basename) = basename else {
                return false;
            };
            let settings = operation.print_settings().unwrap_or_else(gtk::PrintSettings::new);
            settings.set("output-basename", Some(&basename));
            // Leave the file format to GTK's Print to File controls. GTK 3's file
            // backend compares this private setting against lowercase values and
            // aborts the process when an unrecognized value is supplied.
            operation.set_print_settings(&settings);
            false
        });
    })
}

fn handle_window_event(window: &tauri::Window, event: &WindowEvent) {
    let state = window.state::<AppState>();
    match event {
        WindowEvent::Moved(_) | WindowEvent::Resized(_) => {
            capture_window_bounds(window, &state.window_bounds);
        }
        WindowEvent::CloseRequested { .. } => {
            capture_window_bounds(window, &state.window_bounds);
            persist_window_bounds(&state.window_bounds);
            clear_owned_clipboard(&state);
        }
        _ => {}
    }
    let should_lock = match event {
        WindowEvent::Focused(false) => state
            .service
            .lock()
            .map(|service| service.should_lock_on_window_blur())
            .unwrap_or(true),
        WindowEvent::Resized(_) => {
            window.is_minimized().unwrap_or(false)
                && state
                    .service
                    .lock()
                    .map(|service| service.should_lock_on_minimize())
                    .unwrap_or(true)
        }
        _ => false,
    };
    if should_lock {
        if let Ok(mut service) = state.service.lock() {
            service.lock_vault();
        }
        clear_owned_clipboard(&state);
        clear_ephemeral_authorizations(&state);
        let _ = window.app_handle().emit("vault-locked", "window");
    }
}

fn image_data_url(bytes: &[u8]) -> Result<String, String> {
    if bytes.is_empty() || bytes.len() > MAX_QI_ICON_BYTES {
        return Err("Qi icons must be non-empty and no larger than 512 KiB.".into());
    }
    let media_type = sniff_image_media_type(bytes)
        .ok_or_else(|| "Qi icons must contain a valid PNG, JPEG, WebP, GIF, or ICO image.".to_string())?;
    Ok(format!(
        "data:{media_type};base64,{}",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    ))
}

fn fetch_favicon_data_url(raw_url: &str) -> Result<String, String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let page_url = reqwest::Url::parse(raw_url)
        .map_err(|_| "Enter a complete website URL beginning with http:// or https://.".to_string())?;
    validate_favicon_url(&page_url)?;

    let mut conventional_url = page_url.clone();
    conventional_url.set_path("/favicon.ico");
    conventional_url.set_query(None);
    conventional_url.set_fragment(None);

    let mut candidates = Vec::new();
    let mut seen = HashSet::new();
    let page_origin = favicon_referrer_origin(&page_url);
    for (document_url, referrer) in [(conventional_url.clone(), Some(&page_origin)), (page_url, None)] {
        let Ok(resource) = fetch_public_resource(document_url, referrer) else {
            continue;
        };
        if let Ok(data_url) = favicon_resource_data_url(&resource.bytes) {
            return Ok(data_url);
        }
        for candidate in discover_favicon_urls(&resource.final_url, &resource.bytes) {
            if seen.insert(candidate.as_str().to_string()) {
                candidates.push(candidate);
            }
            if candidates.len() >= MAX_FAVICON_CANDIDATES {
                break;
            }
        }
        if candidates.len() >= MAX_FAVICON_CANDIDATES {
            break;
        }
    }

    for candidate in candidates {
        let Ok(resource) = fetch_public_resource(candidate, Some(&page_origin)) else {
            continue;
        };
        if let Ok(data_url) = favicon_resource_data_url(&resource.bytes) {
            return Ok(data_url);
        }
    }

    Err("The website did not provide a supported favicon.".into())
}

struct FetchedFaviconResource {
    final_url: reqwest::Url,
    bytes: Vec<u8>,
}

fn fetch_public_resource(
    mut target: reqwest::Url,
    referrer: Option<&reqwest::Url>,
) -> Result<FetchedFaviconResource, String> {
    validate_favicon_url(&target)?;

    for _ in 0..=4 {
        let (host, endpoint) = resolve_public_endpoint(&target)?;
        let mut builder = reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(4))
            .timeout(Duration::from_secs(8))
            .user_agent(FAVICON_BROWSER_USER_AGENT);
        if host.parse::<IpAddr>().is_err() {
            builder = builder.resolve(&host, endpoint);
        }
        let client = builder
            .build()
            .map_err(|error| format!("could not initialize the favicon client: {error}"))?;
        let mut request = client.get(target.clone());
        if let Some(referrer) = referrer {
            let fetch_site = if referrer.host_str() == target.host_str() {
                "same-origin"
            } else {
                "cross-site"
            };
            request = request
                .header(
                    reqwest::header::ACCEPT,
                    "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
                )
                .header(reqwest::header::REFERER, referrer.as_str())
                .header("sec-fetch-dest", "image")
                .header("sec-fetch-mode", "no-cors")
                .header("sec-fetch-site", fetch_site);
        } else {
            request = request
                .header(
                    reqwest::header::ACCEPT,
                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                )
                .header("sec-fetch-dest", "document")
                .header("sec-fetch-mode", "navigate")
                .header("sec-fetch-site", "none")
                .header("upgrade-insecure-requests", "1");
        }
        let response = request
            .send()
            .map_err(|error| format!("could not fetch the website favicon: {error}"))?;

        if response.status().is_redirection() {
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| "The favicon redirect did not provide a valid destination.".to_string())?;
            target = target
                .join(location)
                .map_err(|_| "The favicon redirected to an invalid URL.".to_string())?;
            validate_favicon_url(&target)?;
            continue;
        }
        if !response.status().is_success() {
            return Err(format!(
                "The favicon request returned HTTP {}.",
                response.status().as_u16()
            ));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_QI_ICON_BYTES as u64)
        {
            return Err("The website favicon is larger than 512 KiB.".into());
        }
        let mut bytes = Vec::new();
        response
            .take((MAX_QI_ICON_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("could not read the website favicon: {error}"))?;
        if bytes.len() > MAX_QI_ICON_BYTES {
            return Err("The website favicon is larger than 512 KiB.".into());
        }
        return Ok(FetchedFaviconResource {
            final_url: target,
            bytes,
        });
    }
    Err("The website favicon redirected too many times.".into())
}

fn favicon_referrer_origin(url: &reqwest::Url) -> reqwest::Url {
    let mut origin = url.clone();
    origin.set_path("/");
    origin.set_query(None);
    origin.set_fragment(None);
    origin
}

fn discover_favicon_urls(base_url: &reqwest::Url, bytes: &[u8]) -> Vec<reqwest::Url> {
    let Ok(html) = std::str::from_utf8(bytes) else {
        return Vec::new();
    };
    let document = Document::from(html);
    document
        .select("link[href]")
        .iter()
        .filter(|link| {
            link.attr("rel").is_some_and(|rel| {
                rel.split_ascii_whitespace().any(|value| {
                    let value = value.to_ascii_lowercase();
                    value == "icon" || value.ends_with("-icon")
                })
            })
        })
        .filter_map(|link| link.attr("href"))
        .filter_map(|href| base_url.join(href.as_ref()).ok())
        .filter(|url| validate_favicon_url(url).is_ok())
        .take(MAX_FAVICON_CANDIDATES)
        .collect()
}

fn favicon_resource_data_url(bytes: &[u8]) -> Result<String, String> {
    if sniff_image_media_type(bytes).is_some() {
        return image_data_url(bytes);
    }
    let png = rasterize_svg_favicon(bytes)?;
    image_data_url(&png)
}

fn rasterize_svg_favicon(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.is_empty() || bytes.len() > MAX_QI_ICON_BYTES {
        return Err("SVG favicon exceeds the supported size.".into());
    }
    validate_svg_complexity(bytes)?;
    let result = std::panic::catch_unwind(|| {
        let options = resvg::usvg::Options {
            image_href_resolver: resvg::usvg::ImageHrefResolver {
                resolve_data: Box::new(|_, _, _| None),
                resolve_string: Box::new(|_, _| None),
            },
            ..Default::default()
        };
        let tree = resvg::usvg::Tree::from_data(bytes, &options)
            .map_err(|_| "The website favicon is not a valid SVG image.".to_string())?;
        let size = tree.size();
        let scale = (RASTERIZED_FAVICON_SIZE as f32 / size.width())
            .min(RASTERIZED_FAVICON_SIZE as f32 / size.height());
        let translate_x = (RASTERIZED_FAVICON_SIZE as f32 - size.width() * scale) / 2.0;
        let translate_y = (RASTERIZED_FAVICON_SIZE as f32 - size.height() * scale) / 2.0;
        let transform =
            resvg::tiny_skia::Transform::from_row(scale, 0.0, 0.0, scale, translate_x, translate_y);
        let mut pixmap = resvg::tiny_skia::Pixmap::new(RASTERIZED_FAVICON_SIZE, RASTERIZED_FAVICON_SIZE)
            .ok_or_else(|| "Could not allocate the SVG favicon canvas.".to_string())?;
        resvg::render(&tree, transform, &mut pixmap.as_mut());
        pixmap
            .encode_png()
            .map_err(|_| "Could not encode the SVG favicon as PNG.".to_string())
    });
    result.map_err(|_| "The website SVG favicon could not be rendered safely.".to_string())?
}

fn validate_svg_complexity(bytes: &[u8]) -> Result<(), String> {
    use quick_xml::events::Event;

    let mut reader = quick_xml::Reader::from_reader(bytes);
    let mut depth = 0usize;
    let mut elements = 0usize;
    loop {
        match reader.read_event() {
            Ok(Event::Start(_)) => {
                depth = depth.saturating_add(1);
                elements = elements.saturating_add(1);
                if depth > MAX_SVG_NESTING_DEPTH || elements > MAX_SVG_ELEMENTS {
                    return Err("The website SVG favicon is too complex.".into());
                }
            }
            Ok(Event::Empty(_)) => {
                elements = elements.saturating_add(1);
                if elements > MAX_SVG_ELEMENTS {
                    return Err("The website SVG favicon is too complex.".into());
                }
            }
            Ok(Event::End(_)) => depth = depth.saturating_sub(1),
            Ok(Event::Eof) => return Ok(()),
            Err(_) => return Err("The website favicon is not a valid SVG image.".into()),
            _ => {}
        }
    }
}

fn validate_favicon_url(url: &reqwest::Url) -> Result<(), String> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err("Favicon import only supports HTTP and HTTPS websites.".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("Website URLs containing embedded credentials are not supported.".into());
    }
    if url.host_str().is_none() {
        return Err("The website URL does not contain a host.".into());
    }
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "The website URL does not use a supported port.".to_string())?;
    if !matches!(port, 80 | 443) {
        return Err("Favicon import is limited to standard HTTP and HTTPS ports.".into());
    }
    Ok(())
}

fn resolve_public_endpoint(url: &reqwest::Url) -> Result<(String, SocketAddr), String> {
    validate_favicon_url(url)?;
    let host = url.host_str().expect("validated URL host").to_string();
    let port = url.port_or_known_default().expect("validated URL port");
    let addresses = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|_| "The website host could not be resolved.".to_string())?
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err("The website host did not resolve to an address.".into());
    }
    if addresses.iter().any(|address| !is_public_ip(address.ip())) {
        return Err("Favicon import blocks local, private, and reserved network addresses.".into());
    }
    Ok((host, addresses[0]))
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_unspecified()
        || a == 0
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && matches!(c, 0 | 2))
        || (a == 198 && matches!(b, 18 | 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113))
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    let address = u128::from(ip);
    let in_prefix = |network: Ipv6Addr, prefix_length: u32| {
        let mask = u128::MAX << (128 - prefix_length);
        address & mask == u128::from(network) & mask
    };

    // Publicly routable IPv6 unicast space is currently allocated from 2000::/3.
    // Exclude every IANA special-purpose block within that allocation as well;
    // in particular, translation and tunnelling prefixes must never be allowed
    // to turn a native favicon request into an IPv4 SSRF request.
    in_prefix(Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0), 3)
        && !in_prefix(Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 23)
        && !in_prefix(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32)
        && !in_prefix(Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16)
        && !in_prefix(Ipv6Addr::new(0x2620, 0x004f, 0x8000, 0, 0, 0, 0, 0), 48)
        && !in_prefix(Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0), 20)
}

fn restore_window_bounds(window: &tauri::WebviewWindow, guard: &WindowBoundsGuard) -> bool {
    let Ok(bytes) = qiring_storage::read_bounded(&guard.path, MAX_WINDOW_STATE_BYTES) else {
        return false;
    };
    let Ok(saved) = serde_json::from_slice::<PersistedWindowBounds>(&bytes) else {
        return false;
    };
    if !is_valid_window_bounds(&saved) {
        return false;
    }
    let Ok(monitors) = window.available_monitors() else {
        return false;
    };
    if monitors.is_empty() {
        return false;
    }

    let saved_right = i64::from(saved.x) + i64::from(saved.width);
    let saved_bottom = i64::from(saved.y) + i64::from(saved.height);
    let preferred = monitors.iter().find(|monitor| {
        let position = monitor.position();
        let size = monitor.size();
        let right = i64::from(position.x) + i64::from(size.width);
        let bottom = i64::from(position.y) + i64::from(size.height);
        i64::from(saved.x) < right
            && saved_right > i64::from(position.x)
            && i64::from(saved.y) < bottom
            && saved_bottom > i64::from(position.y)
    });
    let primary = window.primary_monitor().ok().flatten();
    let monitor = preferred.or(primary.as_ref()).unwrap_or(&monitors[0]);
    let monitor_position = monitor.position();
    let monitor_size = monitor.size();
    let width = saved
        .width
        .max(WINDOW_MIN_WIDTH.min(monitor_size.width))
        .min(monitor_size.width);
    let height = saved
        .height
        .max(WINDOW_MIN_HEIGHT.min(monitor_size.height))
        .min(monitor_size.height);
    let max_x = i64::from(monitor_position.x) + i64::from(monitor_size.width - width);
    let max_y = i64::from(monitor_position.y) + i64::from(monitor_size.height - height);
    let centered_x = i64::from(monitor_position.x) + i64::from(monitor_size.width - width) / 2;
    let centered_y = i64::from(monitor_position.y) + i64::from(monitor_size.height - height) / 2;
    let saved_intersects_preferred = preferred.is_some();
    let x = if saved_intersects_preferred {
        i64::from(saved.x).clamp(i64::from(monitor_position.x), max_x)
    } else {
        centered_x
    } as i32;
    let y = if saved_intersects_preferred {
        i64::from(saved.y).clamp(i64::from(monitor_position.y), max_y)
    } else {
        centered_y
    } as i32;

    let restored = PersistedWindowBounds {
        x,
        y,
        width,
        height,
        maximized: saved.maximized,
    };
    if let Ok(mut state) = guard.current.lock() {
        state.bounds = Some(restored);
        if restored != saved {
            state.revision = 1;
            state.changed_at = Some(Instant::now());
        }
    }

    let _ = window.set_size(PhysicalSize::new(restored.width, restored.height));
    let _ = window.set_position(PhysicalPosition::new(restored.x, restored.y));
    if restored.maximized {
        let _ = window.maximize();
    }
    true
}

fn capture_window_bounds(window: &tauri::Window, guard: &WindowBoundsGuard) {
    let maximized = window.is_maximized().unwrap_or(false);
    let minimized = window.is_minimized().unwrap_or(false);
    if minimized {
        return;
    }
    let Ok(mut current) = guard.current.lock() else {
        return;
    };
    if maximized {
        if let Some(mut bounds) = current.bounds {
            bounds.maximized = true;
            record_window_bounds(&mut current, bounds, Instant::now());
        }
        return;
    }
    let Ok(size) = window.inner_size() else {
        return;
    };
    let position = absolute_window_position_supported()
        .then(|| window.outer_position().ok())
        .flatten();
    let (x, y) = position
        .map(|position| (position.x, position.y))
        .or_else(|| current.bounds.map(|bounds| (bounds.x, bounds.y)))
        .unwrap_or((0, 0));
    let bounds = PersistedWindowBounds {
        x,
        y,
        width: size.width,
        height: size.height,
        maximized: false,
    };
    record_window_bounds(&mut current, bounds, Instant::now());
}

fn record_window_bounds(state: &mut WindowBoundsState, bounds: PersistedWindowBounds, changed_at: Instant) {
    if state.bounds == Some(bounds) {
        return;
    }
    state.bounds = Some(bounds);
    state.revision = state.revision.saturating_add(1);
    state.changed_at = Some(changed_at);
}

fn pending_window_bounds(
    guard: &WindowBoundsGuard,
    now: Instant,
    force: bool,
) -> Option<(PersistedWindowBounds, u64)> {
    let state = guard.current.lock().ok()?;
    if state.revision == state.persisted_revision {
        return None;
    }
    if !force
        && state
            .changed_at
            .is_none_or(|changed_at| now.saturating_duration_since(changed_at) < WINDOW_BOUNDS_PERSIST_DELAY)
    {
        return None;
    }
    Some((state.bounds?, state.revision))
}

fn persist_window_bounds_if_settled(guard: &WindowBoundsGuard) {
    persist_window_bounds_inner(guard, false);
}

fn persist_window_bounds(guard: &WindowBoundsGuard) {
    persist_window_bounds_inner(guard, true);
}

fn persist_window_bounds_inner(guard: &WindowBoundsGuard, force: bool) {
    let Ok(_persistence) = guard.persistence.lock() else {
        return;
    };
    let Some((bounds, revision)) = pending_window_bounds(guard, Instant::now(), force) else {
        return;
    };
    let result = (|| -> anyhow::Result<()> {
        let bytes = serde_json::to_vec_pretty(&bounds).context("failed to serialize window state")?;
        if let Some(parent) = guard.path.parent() {
            fs::create_dir_all(parent).context("failed to create window-state directory")?;
        }
        qiring_storage::save_bytes_atomic(&guard.path, &bytes).context("failed to save window state")
    })();

    let Ok(mut state) = guard.current.lock() else {
        return;
    };
    if let Err(error) = result {
        if state.revision == revision {
            state.changed_at = Some(Instant::now());
        }
        eprintln!("QiRing could not save window state: {error:#}");
        return;
    }
    state.persisted_revision = revision;
    if state.revision == revision {
        state.changed_at = None;
    }
}

#[cfg(target_os = "linux")]
fn absolute_window_position_supported() -> bool {
    let configured_backend = env::var("WINIT_UNIX_BACKEND")
        .ok()
        .or_else(|| env::var("GDK_BACKEND").ok())
        .and_then(|value| value.split(',').next().map(str::trim).map(str::to_owned));
    match configured_backend.as_deref() {
        Some("x11") => true,
        Some("wayland") => false,
        _ => !env::var("XDG_SESSION_TYPE").is_ok_and(|session| session.eq_ignore_ascii_case("wayland")),
    }
}

#[cfg(not(target_os = "linux"))]
fn absolute_window_position_supported() -> bool {
    true
}

fn selected_backup_path(state: &AppState, token: &str) -> Result<PathBuf, String> {
    state
        .selected_backups
        .lock()
        .map_err(|_| "state lock poisoned".to_string())?
        .get(token)
        .cloned()
        .ok_or_else(|| "Backup selection expired; choose the file again.".to_string())
}

fn selected_csv_path(state: &AppState, token: &str) -> Result<PathBuf, String> {
    state
        .selected_csv_imports
        .lock()
        .map_err(|_| "state lock poisoned".to_string())?
        .get(token)
        .cloned()
        .ok_or_else(|| "CSV selection expired; choose the file again.".to_string())
}

fn lock_service(state: &AppState) -> Result<std::sync::MutexGuard<'_, VaultService>, String> {
    state
        .service
        .lock()
        .map_err(|_| "state lock poisoned".to_string())
}

async fn run_service_blocking<T, F>(service: Arc<Mutex<VaultService>>, operation: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(&mut VaultService) -> Result<T, String> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(move || {
        let mut service = service.lock().map_err(|_| "state lock poisoned".to_string())?;
        operation(&mut service)
    })
    .await
    .map_err(|error| format!("Ring operation task failed: {error}"))?
}

#[cfg(target_os = "linux")]
fn write_secret_to_clipboard(clipboard: &mut arboard::Clipboard, value: &str) -> Result<(), arboard::Error> {
    use arboard::SetExtLinux;

    clipboard.set().exclude_from_history().text(value)
}

#[cfg(target_os = "macos")]
fn write_secret_to_clipboard(clipboard: &mut arboard::Clipboard, value: &str) -> Result<(), arboard::Error> {
    use arboard::SetExtApple;

    clipboard.set().exclude_from_history().text(value)
}

#[cfg(target_os = "windows")]
fn write_secret_to_clipboard(clipboard: &mut arboard::Clipboard, value: &str) -> Result<(), arboard::Error> {
    use arboard::SetExtWindows;

    clipboard.set().exclude_from_monitoring().text(value)
}

fn clear_owned_clipboard(state: &AppState) {
    clear_owned_clipboard_from_guard(&state.clipboard);
}

fn clear_owned_clipboard_and_release(state: &AppState) {
    if let Ok(mut clipboard) = state.clipboard.state.lock() {
        clear_owned_clipboard_state(&mut clipboard);
        clipboard.backend.take();
        forget_owned_clipboard(&mut clipboard.owned);
    }
}

fn clear_owned_clipboard_from_guard(guard: &ClipboardGuard) {
    if let Ok(mut clipboard) = guard.state.lock() {
        clear_owned_clipboard_state(&mut clipboard);
    }
}

fn clear_expired_clipboard_from_guard(guard: &ClipboardGuard) {
    if let Ok(mut clipboard) = guard.state.lock() {
        if clipboard
            .owned
            .expires_at
            .is_none_or(|expiry| Instant::now() < expiry)
        {
            return;
        }
        clear_owned_clipboard_state(&mut clipboard);
    }
}

fn clear_owned_clipboard_state(clipboard: &mut ClipboardState) {
    if clipboard.owned.value.is_none() {
        return;
    }
    let Some(backend) = clipboard.backend.as_mut() else {
        return;
    };
    let Ok(clipboard_value) = backend.get_text() else {
        return;
    };
    if !clipboard_matches_owned(&clipboard.owned, &clipboard_value) {
        forget_owned_clipboard(&mut clipboard.owned);
        return;
    }
    if backend.clear().is_ok() {
        forget_owned_clipboard(&mut clipboard.owned);
    }
}

fn clipboard_matches_owned(owned: &OwnedClipboard, clipboard_value: &str) -> bool {
    owned
        .value
        .as_ref()
        .is_some_and(|value| clipboard_value == value.as_str())
}

fn forget_owned_clipboard(owned: &mut OwnedClipboard) {
    owned.value = None;
    owned.expires_at = None;
}

fn clear_ephemeral_authorizations(state: &AppState) {
    if let Ok(mut selections) = state.selected_backups.lock() {
        selections.clear();
    }
    if let Ok(mut selections) = state.selected_csv_imports.lock() {
        selections.clear();
    }
    if let Ok(mut directories) = state.approved_backup_directories.lock() {
        directories.clear();
    }
}

fn resolve_storage_paths(app: &tauri::App) -> anyhow::Result<StoragePaths> {
    let standard_data = app
        .path()
        .app_data_dir()
        .context("operating system did not provide an application data directory")?;
    let standard_config = app
        .path()
        .app_config_dir()
        .context("operating system did not provide an application configuration directory")?;
    let previous_data = app
        .path()
        .data_dir()
        .context("operating system did not provide a data directory")?
        .join(PREVIOUS_APP_IDENTIFIER);
    let previous_config = app
        .path()
        .config_dir()
        .context("operating system did not provide a configuration directory")?
        .join(PREVIOUS_APP_IDENTIFIER);

    let portable_root = resolve_portable_data_root()?;
    let (vault, window_state, ui_preferences, portable) = if let Some(root) = portable_root {
        (
            root.join("vault.qiring"),
            root.join("window-state.json"),
            root.join("ui-preferences.json"),
            true,
        )
    } else {
        (
            standard_data.join("vault.qiring"),
            standard_config.join("window-state.json"),
            standard_config.join("ui-preferences.json"),
            false,
        )
    };

    for parent in [vault.parent(), window_state.parent(), ui_preferences.parent()]
        .into_iter()
        .flatten()
    {
        qiring_storage::ensure_private_directory(parent)
            .with_context(|| format!("failed to prepare QiRing data directory {}", parent.display()))?;
    }

    let mut ring_candidates = Vec::new();
    if portable {
        ring_candidates.push(standard_data.join("vault.qiring"));
    }
    ring_candidates.push(previous_data.join("vault.qiring"));
    if let Some(legacy) = legacy_vault_path() {
        ring_candidates.push(legacy);
    }
    migrate_ring_if_missing(&vault, &ring_candidates)?;

    let mut window_candidates = Vec::new();
    if portable {
        window_candidates.push(standard_config.join("window-state.json"));
    }
    window_candidates.push(previous_config.join("window-state.json"));
    migrate_json_if_missing::<PersistedWindowBounds>(
        &window_state,
        &window_candidates,
        MAX_WINDOW_STATE_BYTES,
        "window state",
        is_valid_window_bounds,
    )?;

    let mut preference_candidates = Vec::new();
    if portable {
        preference_candidates.push(standard_config.join("ui-preferences.json"));
    }
    preference_candidates.push(previous_config.join("ui-preferences.json"));
    migrate_json_if_missing::<UiPreferences>(
        &ui_preferences,
        &preference_candidates,
        MAX_UI_PREFERENCES_BYTES,
        "UI preferences",
        |preferences| is_valid_theme(&preferences.theme),
    )?;

    Ok(StoragePaths {
        vault,
        window_state,
        ui_preferences,
        portable,
    })
}

fn resolve_portable_data_root() -> anyhow::Result<Option<PathBuf>> {
    let explicitly_requested =
        env::args_os().any(|argument| argument == "--portable") || portable_environment_requested()?;

    #[cfg(target_os = "linux")]
    {
        let launcher = env::var_os("APPIMAGE").map(PathBuf::from);
        let marker_requested = launcher
            .as_deref()
            .and_then(Path::parent)
            .is_some_and(|parent| parent.join(PORTABLE_MARKER_FILE).is_file());
        if !explicitly_requested && !marker_requested {
            if launcher
                .as_deref()
                .is_some_and(portable_data_directory_exists_beside)
            {
                anyhow::bail!(
                    "QiRingData exists beside this AppImage but portable mode is disabled. Restore the qiring-portable marker or move QiRingData before using standard mode"
                );
            }
            return Ok(None);
        }
        let launcher = launcher.context(
            "portable mode on Linux requires an AppImage launch (the APPIMAGE environment variable is missing)",
        )?;
        portable_root_beside_launcher(&launcher).map(Some)
    }

    #[cfg(target_os = "windows")]
    {
        let launcher = env::current_exe().context("failed to locate the QiRing executable")?;
        let marker_requested = launcher
            .parent()
            .is_some_and(|parent| parent.join(PORTABLE_MARKER_FILE).is_file());
        if !explicitly_requested && !marker_requested {
            if portable_data_directory_exists_beside(&launcher) {
                anyhow::bail!(
                    "QiRingData exists beside this executable but portable mode is disabled. Restore the qiring-portable marker or move QiRingData before using standard mode"
                );
            }
            return Ok(None);
        }
        portable_root_beside_launcher(&launcher).map(Some)
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        if explicitly_requested {
            anyhow::bail!("portable mode is supported only by AppImage and standalone Windows builds");
        }
        Ok(None)
    }
}

fn portable_environment_requested() -> anyhow::Result<bool> {
    let Some(value) = env::var_os(PORTABLE_ENVIRONMENT_VARIABLE) else {
        return Ok(false);
    };
    let normalized = value.to_string_lossy().trim().to_ascii_lowercase();
    match normalized.as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "" | "0" | "false" | "no" | "off" => Ok(false),
        _ => anyhow::bail!("{PORTABLE_ENVIRONMENT_VARIABLE} must be 1/true/yes/on or 0/false/no/off"),
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn portable_data_directory_exists_beside(launcher: &Path) -> bool {
    launcher
        .parent()
        .is_some_and(|parent| parent.join(PORTABLE_DATA_DIRECTORY).is_dir())
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn portable_root_beside_launcher(launcher: &Path) -> anyhow::Result<PathBuf> {
    let launcher = fs::canonicalize(launcher)
        .with_context(|| format!("failed to resolve launcher path {}", launcher.display()))?;
    if !launcher.is_file() {
        anyhow::bail!("portable launcher is not a file: {}", launcher.display());
    }
    let parent = launcher
        .parent()
        .context("portable launcher has no parent directory")?;
    let root = parent.join(PORTABLE_DATA_DIRECTORY);
    match fs::symlink_metadata(&root) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            anyhow::bail!(
                "portable data directory must not be a symbolic link: {}",
                root.display()
            );
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect portable data directory {}", root.display()))
        }
    }
    #[cfg(target_os = "windows")]
    reject_windows_install_directory(&launcher)?;
    qiring_storage::ensure_private_directory(&root).with_context(|| {
        format!(
            "portable mode cannot create or secure {}. Move QiRing to a writable private directory or disable portable mode",
            root.display()
        )
    })?;
    verify_portable_directory_writable(&root)?;
    Ok(root)
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn verify_portable_directory_writable(root: &Path) -> anyhow::Result<()> {
    let probe = root.join(format!(".write-check-{}", Uuid::new_v4()));
    qiring_storage::save_bytes_atomic(&probe, b"QiRing portable storage check")
        .with_context(|| format!("portable data directory is not writable: {}", root.display()))?;
    fs::remove_file(&probe)
        .with_context(|| format!("failed to remove portable storage check file {}", probe.display()))?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn reject_windows_install_directory(launcher: &Path) -> anyhow::Result<()> {
    for variable in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"] {
        let Some(directory) = env::var_os(variable).map(PathBuf::from) else {
            continue;
        };
        if launcher.starts_with(&directory) {
            anyhow::bail!(
                "portable mode is not supported for an installed executable under {}. Use the standalone Windows build in a user-writable private directory",
                directory.display()
            );
        }
    }
    Ok(())
}

fn migrate_ring_if_missing(target: &Path, candidates: &[PathBuf]) -> anyhow::Result<()> {
    if target
        .try_exists()
        .context("failed to inspect Ring destination")?
    {
        return Ok(());
    }

    struct Candidate {
        path: PathBuf,
        vault_id: Uuid,
        bytes: Vec<u8>,
    }

    let mut existing = Vec::new();
    let mut seen = HashSet::new();
    for candidate in candidates {
        if candidate == target || !seen.insert(candidate.clone()) {
            continue;
        }
        match fs::symlink_metadata(candidate) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect existing Ring {}", candidate.display()))
            }
        }
        let bytes = qiring_storage::read_bounded(candidate, qiring_storage::MAX_VAULT_FILE_BYTES)
            .with_context(|| format!("failed to read existing Ring {}", candidate.display()))?;
        let vault = qiring_storage::parse_vault_bytes(&bytes)
            .with_context(|| format!("existing Ring is invalid: {}", candidate.display()))?;
        let vault_id = match vault {
            qiring_storage::VaultFile::Current(vault) => vault.metadata.vault_id,
            qiring_storage::VaultFile::Legacy(vault) => vault.metadata.vault_id,
        };
        existing.push(Candidate {
            path: candidate.clone(),
            vault_id,
            bytes,
        });
    }

    let Some(source) = existing.first() else {
        return Ok(());
    };
    if let Some(conflict) = existing
        .iter()
        .skip(1)
        .find(|candidate| candidate.vault_id != source.vault_id)
    {
        anyhow::bail!(
            "multiple different existing Rings were found at {} and {}. QiRing did not choose one automatically; copy the intended vault.qiring to {} and restart",
            source.path.display(),
            conflict.path.display(),
            target.display()
        );
    }

    qiring_storage::save_bytes_atomic(target, &source.bytes).with_context(|| {
        format!(
            "failed to copy existing Ring from {} to {}",
            source.path.display(),
            target.display()
        )
    })?;
    qiring_storage::load_vault_file(target)
        .with_context(|| format!("copied Ring failed validation at {}", target.display()))?;
    eprintln!(
        "Copied existing QiRing data from {} to {}. The original was left in place.",
        source.path.display(),
        target.display()
    );
    Ok(())
}

fn migrate_json_if_missing<T>(
    target: &Path,
    candidates: &[PathBuf],
    maximum_bytes: u64,
    description: &str,
    is_valid: impl Fn(&T) -> bool,
) -> anyhow::Result<()>
where
    T: for<'de> Deserialize<'de>,
{
    if target
        .try_exists()
        .with_context(|| format!("failed to inspect {description} destination"))?
    {
        return Ok(());
    }
    let mut seen = HashSet::new();
    for candidate in candidates {
        if candidate == target || !seen.insert(candidate.clone()) {
            continue;
        }
        match fs::symlink_metadata(candidate) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect {description} at {}", candidate.display()))
            }
        }
        let bytes = match qiring_storage::read_bounded(candidate, maximum_bytes) {
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!(
                    "Ignored invalid previous {description} at {}: {error}",
                    candidate.display()
                );
                continue;
            }
        };
        let value = match serde_json::from_slice::<T>(&bytes) {
            Ok(value) => value,
            Err(error) => {
                eprintln!(
                    "Ignored invalid previous {description} at {}: {error}",
                    candidate.display()
                );
                continue;
            }
        };
        if !is_valid(&value) {
            eprintln!(
                "Ignored invalid previous {description} at {}.",
                candidate.display()
            );
            continue;
        }
        qiring_storage::save_bytes_atomic(target, &bytes).with_context(|| {
            format!(
                "failed to copy {description} from {} to {}",
                candidate.display(),
                target.display()
            )
        })?;
        eprintln!(
            "Copied QiRing {description} from {} to {}. The original was left in place.",
            candidate.display(),
            target.display()
        );
        break;
    }
    Ok(())
}

fn is_valid_theme(theme: &str) -> bool {
    matches!(theme, "system" | "dark" | "light")
}

fn is_valid_window_bounds(bounds: &PersistedWindowBounds) -> bool {
    bounds.width > 0 && bounds.height > 0 && bounds.width <= 32_768 && bounds.height <= 32_768
}

fn load_ui_preferences(path: &Path) -> anyhow::Result<UiPreferences> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(UiPreferences::default()),
        Err(error) => return Err(error).context("failed to inspect UI preferences"),
        Ok(_) => {}
    }
    let bytes = qiring_storage::read_bounded(path, MAX_UI_PREFERENCES_BYTES)
        .context("failed to read UI preferences")?;
    let preferences: UiPreferences =
        serde_json::from_slice(&bytes).context("failed to parse UI preferences")?;
    if !is_valid_theme(&preferences.theme) {
        anyhow::bail!("stored theme preference is invalid");
    }
    Ok(preferences)
}

fn save_ui_preferences(path: &Path, preferences: &UiPreferences) -> anyhow::Result<()> {
    if !is_valid_theme(&preferences.theme) {
        anyhow::bail!("theme preference is invalid");
    }
    let bytes = serde_json::to_vec_pretty(preferences).context("failed to serialize UI preferences")?;
    qiring_storage::save_bytes_atomic(path, &bytes).context("failed to save UI preferences")
}

fn legacy_vault_path() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    let base = env::var_os("APPDATA").map(|value| PathBuf::from(value).join("QiRing"));
    #[cfg(target_os = "macos")]
    let base = env::var_os("HOME").map(|value| {
        PathBuf::from(value)
            .join("Library")
            .join("Application Support")
            .join("QiRing")
    });
    #[cfg(target_os = "linux")]
    let base = env::var_os("XDG_DATA_HOME")
        .map(|value| PathBuf::from(value).join("qiring"))
        .or_else(|| {
            env::var_os("HOME").map(|value| PathBuf::from(value).join(".local").join("share").join("qiring"))
        });
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    let base: Option<PathBuf> = None;
    base.map(|path| path.join(".qiring").join("vault.qiring"))
}

fn display_error(error: anyhow::Error) -> String {
    error.to_string()
}

fn apply_platform_runtime_defaults() {
    #[cfg(target_os = "linux")]
    if env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none() {
        env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ring_bytes(vault_id: Uuid) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "metadata": {
                "vault_id": vault_id,
                "created_at": "2026-08-11T00:00:00Z",
                "schema_version": 2,
                "master_kdf": {
                    "params": { "memory_cost_kib": 8192, "iterations": 1, "parallelism": 1 },
                    "salt": vec![0_u8; 16]
                },
                "recovery_kdf": {
                    "params": { "memory_cost_kib": 8192, "iterations": 1, "parallelism": 1 },
                    "salt": vec![1_u8; 16]
                }
            },
            "wrapped_keys": {
                "wrapped_dek_by_master": {
                    "nonce": vec![0_u8; 24],
                    "ciphertext": vec![0_u8; 48]
                },
                "wrapped_dek_by_recovery": {
                    "nonce": vec![1_u8; 24],
                    "ciphertext": vec![1_u8; 48]
                }
            },
            "vault_blob": {
                "nonce": vec![2_u8; 24],
                "ciphertext": vec![2_u8; 16]
            }
        }))
        .expect("sample Ring JSON")
    }

    fn sample_window_bounds(width: u32) -> PersistedWindowBounds {
        PersistedWindowBounds {
            x: 120,
            y: 80,
            width,
            height: 700,
            maximized: false,
        }
    }

    #[test]
    fn backup_paths_require_an_unforgeable_dialog_selection_token() {
        let state = AppState::new(
            PathBuf::from("/tmp/qiring-test-vault"),
            PathBuf::from("/tmp/qiring-test-window-state"),
            PathBuf::from("/tmp/qiring-test-ui-preferences"),
        );
        assert!(selected_backup_path(&state, "unknown").is_err());
        state
            .selected_backups
            .lock()
            .expect("lock")
            .insert("approved".into(), PathBuf::from("/tmp/selected.qiring-backup"));
        assert_eq!(
            selected_backup_path(&state, "approved").expect("approved path"),
            PathBuf::from("/tmp/selected.qiring-backup")
        );
    }

    #[test]
    fn ring_migration_copies_valid_data_and_keeps_the_source() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source = directory.path().join("old").join("vault.qiring");
        let target = directory.path().join("new").join("vault.qiring");
        let bytes = sample_ring_bytes(Uuid::new_v4());
        qiring_storage::save_bytes_atomic(&source, &bytes).expect("write source Ring");

        migrate_ring_if_missing(&target, std::slice::from_ref(&source)).expect("migrate Ring");

        assert_eq!(fs::read(&target).expect("target Ring"), bytes);
        assert!(source.is_file());
        qiring_storage::load_vault_file(&target).expect("valid copied Ring");
    }

    #[test]
    fn ring_migration_refuses_to_choose_between_different_rings() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let first = directory.path().join("first").join("vault.qiring");
        let second = directory.path().join("second").join("vault.qiring");
        let target = directory.path().join("target").join("vault.qiring");
        qiring_storage::save_bytes_atomic(&first, &sample_ring_bytes(Uuid::new_v4()))
            .expect("write first Ring");
        qiring_storage::save_bytes_atomic(&second, &sample_ring_bytes(Uuid::new_v4()))
            .expect("write second Ring");

        let error = migrate_ring_if_missing(&target, &[first, second]).expect_err("conflicting Rings");

        assert!(error.to_string().contains("multiple different existing Rings"));
        assert!(!target.exists());
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[test]
    fn portable_storage_uses_a_dedicated_writable_sidecar() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let launcher = directory.path().join(if cfg!(target_os = "windows") {
            "qiring-desktop.exe"
        } else {
            "QiRing.AppImage"
        });
        fs::write(&launcher, b"launcher").expect("write launcher");

        let root = portable_root_beside_launcher(&launcher).expect("portable root");

        // Windows temp paths may use an 8.3 alias; the launcher path is canonicalized.
        let expected = fs::canonicalize(directory.path()).expect("canonical temporary directory");
        assert_eq!(root, expected.join(PORTABLE_DATA_DIRECTORY));
        assert!(root.is_dir());
        assert!(fs::read_dir(&root).expect("read sidecar").next().is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn portable_storage_rejects_a_symlinked_sidecar() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temporary directory");
        let launcher = directory.path().join("QiRing.AppImage");
        let redirected = directory.path().join("redirected");
        fs::write(&launcher, b"launcher").expect("write launcher");
        fs::create_dir(&redirected).expect("create redirected directory");
        symlink(&redirected, directory.path().join(PORTABLE_DATA_DIRECTORY)).expect("create sidecar symlink");

        let error = portable_root_beside_launcher(&launcher).expect_err("symlink must be rejected");

        assert!(error.to_string().contains("must not be a symbolic link"));
    }

    #[test]
    fn ui_preferences_round_trip_in_an_app_owned_file() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source = directory.path().join("old").join("ui-preferences.json");
        let target = directory.path().join("new").join("ui-preferences.json");
        save_ui_preferences(
            &source,
            &UiPreferences {
                theme: "light".into(),
            },
        )
        .expect("save preferences");

        migrate_json_if_missing::<UiPreferences>(
            &target,
            std::slice::from_ref(&source),
            MAX_UI_PREFERENCES_BYTES,
            "UI preferences",
            |preferences| is_valid_theme(&preferences.theme),
        )
        .expect("migrate preferences");

        assert_eq!(
            load_ui_preferences(&target).expect("load preferences").theme,
            "light"
        );
        assert!(source.is_file());
    }

    #[test]
    fn website_launcher_is_app_scoped_instead_of_exposing_the_opener_plugin() {
        let capability: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/main.json")).expect("capability JSON");
        let permissions = capability["permissions"].as_array().expect("permissions");
        assert!(permissions
            .iter()
            .any(|permission| permission == "allow-launch-website"));
        assert!(!permissions
            .iter()
            .any(|permission| { permission["identifier"] == "opener:allow-open-url" }));
    }

    #[test]
    fn website_launcher_rejects_non_web_urls() {
        assert!(parse_website_url("https://example.com/path").is_ok());
        assert!(parse_website_url("http://localhost.test").is_ok());
        assert!(parse_website_url("file:///tmp/secret").is_err());
        assert!(parse_website_url("javascript:alert(1)").is_err());
        assert!(parse_website_url("https://").is_err());
    }

    #[test]
    fn window_bounds_persist_only_after_the_resize_quiet_period() {
        let guard = WindowBoundsGuard {
            path: PathBuf::from("/tmp/qiring-test-window-state"),
            current: Mutex::new(WindowBoundsState::default()),
            persistence: Mutex::new(()),
        };
        let started = Instant::now();
        {
            let mut state = guard.current.lock().expect("window state lock");
            record_window_bounds(&mut state, sample_window_bounds(900), started);
        }

        assert!(pending_window_bounds(
            &guard,
            started + WINDOW_BOUNDS_PERSIST_DELAY - Duration::from_millis(1),
            false
        )
        .is_none());
        assert_eq!(
            pending_window_bounds(&guard, started, true),
            Some((sample_window_bounds(900), 1))
        );
        assert_eq!(
            pending_window_bounds(&guard, started + WINDOW_BOUNDS_PERSIST_DELAY, false),
            Some((sample_window_bounds(900), 1))
        );

        let resized_at = started + Duration::from_secs(1);
        {
            let mut state = guard.current.lock().expect("window state lock");
            record_window_bounds(&mut state, sample_window_bounds(1_000), resized_at);
        }
        assert!(pending_window_bounds(&guard, resized_at + Duration::from_millis(100), false).is_none());
        assert_eq!(
            pending_window_bounds(&guard, resized_at + WINDOW_BOUNDS_PERSIST_DELAY, false),
            Some((sample_window_bounds(1_000), 2))
        );
    }

    #[test]
    fn favicon_import_rejects_local_networks_and_non_images() {
        for address in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            assert!(!is_public_ip(address));
        }
        assert!(is_public_ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))));
        assert!(image_data_url(b"not an image").is_err());
    }

    #[test]
    fn favicon_import_rejects_special_purpose_ipv6_ranges() {
        for address in [
            "64:ff9b::a9fe:a9fe",   // NAT64 well-known prefix
            "64:ff9b:1::a9fe:a9fe", // NAT64 local-use prefix
            "::ffff:0:a9fe:a9fe",   // IPv4-translatable
            "2002:a9fe:a9fe::",     // 6to4
            "fec0::1234",           // deprecated site-local
            "2001:db8::1",          // documentation
            "3fff::1",              // documentation
        ] {
            let address = address.parse::<Ipv6Addr>().expect("valid test address");
            assert!(!is_public_ipv6(address), "accepted {address}");
        }

        assert!(is_public_ipv6(
            "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap()
        ));
    }

    #[test]
    fn favicon_import_accepts_supported_magic_bytes() {
        let data_url = image_data_url(b"\x89PNG\r\n\x1a\nmock").expect("PNG");
        assert!(data_url.starts_with("data:image/png;base64,"));
    }

    #[test]
    fn favicon_import_discovers_declared_icon_urls() {
        let base = reqwest::Url::parse("https://auth.example.test/log-in").expect("base URL");
        let html = br#"
            <html><head>
              <link rel="stylesheet" href="/ignored.css">
              <link rel="icon" type="image/svg+xml" href="https://cdn.example.test/icon.svg">
              <link rel="apple-touch-icon" href="/touch.png">
              <link rel="icon" href="data:image/png;base64,AAAA">
            </head></html>
        "#;

        let urls = discover_favicon_urls(&base, html);
        assert_eq!(
            urls.iter().map(reqwest::Url::as_str).collect::<Vec<_>>(),
            [
                "https://cdn.example.test/icon.svg",
                "https://auth.example.test/touch.png"
            ]
        );
    }

    #[test]
    fn favicon_import_sends_only_the_site_origin_as_referrer() {
        let page =
            reqwest::Url::parse("https://example.test/private/path?token=secret#fragment").expect("page URL");
        assert_eq!(favicon_referrer_origin(&page).as_str(), "https://example.test/");
    }

    #[test]
    fn favicon_import_rasterizes_svg_without_storing_svg() {
        let svg = br##"<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32">
            <rect width="32" height="32" fill="#10a37f"/>
        </svg>"##;
        let data_url = favicon_resource_data_url(svg).expect("SVG favicon");
        assert!(data_url.starts_with("data:image/png;base64,"));
        assert!(!data_url.contains("svg+xml"));
    }

    #[test]
    fn favicon_import_rejects_deeply_nested_svg_before_rendering() {
        let mut svg = String::from(r#"<svg xmlns="http://www.w3.org/2000/svg">"#);
        for _ in 0..MAX_SVG_NESTING_DEPTH {
            svg.push_str("<g>");
        }
        svg.push_str(r#"<rect width="1" height="1"/>"#);
        for _ in 0..MAX_SVG_NESTING_DEPTH {
            svg.push_str("</g>");
        }
        svg.push_str("</svg>");

        assert_eq!(
            rasterize_svg_favicon(svg.as_bytes()).expect_err("reject deeply nested SVG"),
            "The website SVG favicon is too complex."
        );
    }

    #[test]
    fn favicon_import_rejects_excessive_svg_elements_before_rendering() {
        let mut svg = String::from(r#"<svg xmlns="http://www.w3.org/2000/svg">"#);
        for _ in 0..MAX_SVG_ELEMENTS {
            svg.push_str("<g/>");
        }
        svg.push_str("</svg>");

        assert_eq!(
            rasterize_svg_favicon(svg.as_bytes()).expect_err("reject SVG with too many elements"),
            "The website SVG favicon is too complex."
        );
    }

    #[test]
    fn print_basename_accepts_only_bounded_recovery_titles() {
        assert_eq!(
            recovery_print_basename("QiRing-Recovery-Key-2026-08-09"),
            Some("QiRing-Recovery-Key-2026-08-09")
        );
        assert_eq!(recovery_print_basename("Vault — QiRing"), None);
        assert_eq!(recovery_print_basename("QiRing-Recovery-Key-../../vault"), None);
        assert_eq!(
            recovery_print_basename(
                "QiRing-Recovery-Key-2026-08-09-extra-extra-extra-extra-extra-extra-extra-extra"
            ),
            None
        );
    }

    #[test]
    fn clipboard_cleanup_matches_only_an_unchanged_owned_value() {
        let mut matching = OwnedClipboard {
            value: Some(Zeroizing::new("copied secret".to_string())),
            expires_at: Instant::now().checked_add(Duration::from_secs(30)),
        };
        assert!(clipboard_matches_owned(&matching, "copied secret"));
        forget_owned_clipboard(&mut matching);
        assert!(matching.value.is_none());
        assert!(matching.expires_at.is_none());

        let replaced = OwnedClipboard {
            value: Some(Zeroizing::new("copied secret".to_string())),
            expires_at: Instant::now().checked_add(Duration::from_secs(30)),
        };
        assert!(!clipboard_matches_owned(&replaced, "newer clipboard content"));
    }
}
