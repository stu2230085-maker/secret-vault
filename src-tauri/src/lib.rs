pub mod vault;

#[cfg(feature = "desktop")]
mod commands;

#[cfg(feature = "desktop")]
pub fn run() {
    use std::sync::Mutex;

    tauri::Builder::default()
        .manage(Mutex::new(None::<vault::Vault>))
        .invoke_handler(tauri::generate_handler![
            commands::create_vault,
            commands::open_vault,
            commands::list_entries,
            commands::add_entry,
            commands::read_entry,
            commands::delete_entry,
            commands::compact_vault,
            commands::lock_vault
        ])
        .run(tauri::generate_context!())
        .expect("failed to run Secret Vault");
}
