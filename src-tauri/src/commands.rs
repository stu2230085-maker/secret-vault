use std::sync::Mutex;

use zeroize::Zeroizing;

use crate::vault::{DisguiseMode, Vault, VaultEntry, VaultStats};

type VaultState = Mutex<Option<Vault>>;

fn parse_disguise(disguise: &str) -> DisguiseMode {
    if disguise == "decoy" {
        DisguiseMode::Decoy
    } else {
        DisguiseMode::Error
    }
}

#[tauri::command]
pub fn create_vault(
    state: tauri::State<'_, VaultState>,
    path: String,
    password: String,
    burn_password: Option<String>,
    disguise: String,
) -> Result<Vec<VaultEntry>, String> {
    let vault = Vault::create(
        &path,
        &password,
        burn_password.as_deref(),
        parse_disguise(&disguise),
    )
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
pub fn add_entry_bytes(
    state: tauri::State<'_, VaultState>,
    name: String,
    content: Vec<u8>,
) -> Result<Vec<VaultEntry>, String> {
    let content = Zeroizing::new(content);
    let mut guard = state.lock().map_err(|_| "vault state unavailable")?;
    let vault = guard
        .as_mut()
        .ok_or_else(|| "no vault is open".to_string())?;
    vault
        .add_entry(&name, &content)
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
pub fn read_entry_bytes(
    state: tauri::State<'_, VaultState>,
    name: String,
) -> Result<Vec<u8>, String> {
    let guard = state.lock().map_err(|_| "vault state unavailable")?;
    let vault = guard
        .as_ref()
        .ok_or_else(|| "no vault is open".to_string())?;
    let content = vault.read_entry(&name).map_err(|error| error.to_string())?;
    Ok(content.to_vec())
}

#[tauri::command]
pub fn rename_entry(
    state: tauri::State<'_, VaultState>,
    old_name: String,
    new_name: String,
) -> Result<Vec<VaultEntry>, String> {
    let mut guard = state.lock().map_err(|_| "vault state unavailable")?;
    let vault = guard
        .as_mut()
        .ok_or_else(|| "no vault is open".to_string())?;
    vault
        .rename_entry(&old_name, &new_name)
        .map_err(|error| error.to_string())?;
    Ok(vault.entries().to_vec())
}

#[tauri::command]
pub fn rename_folder(
    state: tauri::State<'_, VaultState>,
    old_prefix: String,
    new_prefix: String,
) -> Result<Vec<VaultEntry>, String> {
    let mut guard = state.lock().map_err(|_| "vault state unavailable")?;
    let vault = guard
        .as_mut()
        .ok_or_else(|| "no vault is open".to_string())?;
    vault
        .rename_folder(&old_prefix, &new_prefix)
        .map_err(|error| error.to_string())?;
    Ok(vault.entries().to_vec())
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
pub fn change_passwords(
    state: tauri::State<'_, VaultState>,
    current_password: String,
    new_password: String,
    burn_password: Option<String>,
    disguise: String,
) -> Result<(), String> {
    let mut guard = state.lock().map_err(|_| "vault state unavailable")?;
    let vault = guard
        .as_mut()
        .ok_or_else(|| "no vault is open".to_string())?;
    vault
        .change_passwords(
            &current_password,
            &new_password,
            burn_password.as_deref(),
            parse_disguise(&disguise),
        )
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn vault_stats(state: tauri::State<'_, VaultState>) -> Result<VaultStats, String> {
    let guard = state.lock().map_err(|_| "vault state unavailable")?;
    guard
        .as_ref()
        .ok_or_else(|| "no vault is open".to_string())?
        .stats()
        .map_err(|error| error.to_string())
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
