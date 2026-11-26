use std::sync::Mutex;

use zeroize::Zeroizing;

use crate::vault::{DisguiseMode, Vault, VaultEntry};

type VaultState = Mutex<Option<Vault>>;

#[tauri::command]
pub fn create_vault(
    state: tauri::State<'_, VaultState>,
    path: String,
    password: String,
    burn_password: Option<String>,
    disguise: String,
) -> Result<Vec<VaultEntry>, String> {
    let mode = if disguise == "decoy" {
        DisguiseMode::Decoy
    } else {
        DisguiseMode::Error
    };
    let mut vault = Vault::create(&path, &password, burn_password.as_deref(), mode)
        .map_err(|error| error.to_string())?;
    let entries = vault.entries().to_vec();
    *state.lock().map_err(|_| "vault state unavailable")? = Some(vault);
    Ok(entries)
}

#[tauri::command]
pub fn open_vault(
    state: tauri::State<'_, VaultState>,
    path: String,
    password: String,
) -> Result<Vec<VaultEntry>, String> {
    let vault = Vault::open(&path, &password).map_err(|error| error.to_string())?;
    let entries = vault.entries().to_vec();
    *state.lock().map_err(|_| "vault state unavailable")? = Some(vault);
    Ok(entries)
}

#[tauri::command]
pub fn list_entries(state: tauri::State<'_, VaultState>) -> Result<Vec<VaultEntry>, String> {
    let guard = state.lock().map_err(|_| "vault state unavailable")?;
    guard
        .as_ref()
        .map(|vault| vault.entries().to_vec())
        .ok_or_else(|| "no vault is open".to_string())
}

#[tauri::command]
pub fn add_entry(
    state: tauri::State<'_, VaultState>,
    name: String,
    content: String,
) -> Result<Vec<VaultEntry>, String> {
    let content = Zeroizing::new(content);
    let mut guard = state.lock().map_err(|_| "vault state unavailable")?;
    let vault = guard
        .as_mut()
        .ok_or_else(|| "no vault is open".to_string())?;
    vault
        .add_entry(&name, content.as_bytes())
        .map_err(|error| error.to_string())?;
    Ok(vault.entries().to_vec())
}

#[tauri::command]
pub fn read_entry(state: tauri::State<'_, VaultState>, name: String) -> Result<String, String> {
    let guard = state.lock().map_err(|_| "vault state unavailable")?;
    let vault = guard
        .as_ref()
        .ok_or_else(|| "no vault is open".to_string())?;
    let content = vault.read_entry(&name).map_err(|error| error.to_string())?;
    String::from_utf8(content.to_vec()).map_err(|_| "file is not UTF-8 text".to_string())
}

#[tauri::command]
pub fn delete_entry(
    state: tauri::State<'_, VaultState>,
    name: String,
) -> Result<Vec<VaultEntry>, String> {
    let mut guard = state.lock().map_err(|_| "vault state unavailable")?;
    let vault = guard
        .as_mut()
        .ok_or_else(|| "no vault is open".to_string())?;
    vault
        .delete_entry(&name)
        .map_err(|error| error.to_string())?;
    Ok(vault.entries().to_vec())
}

#[tauri::command]
pub fn compact_vault(state: tauri::State<'_, VaultState>) -> Result<(), String> {
    let mut guard = state.lock().map_err(|_| "vault state unavailable")?;
    guard
        .as_mut()
        .ok_or_else(|| "no vault is open".to_string())?
        .compact()
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn lock_vault(state: tauri::State<'_, VaultState>) -> Result<(), String> {
    *state.lock().map_err(|_| "vault state unavailable")? = None;
    Ok(())
}
