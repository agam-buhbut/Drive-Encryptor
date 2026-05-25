#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod passphrase;
mod secret_token;
mod sink;

use commands::AppState;
use tauri::Manager;

fn main() {
    install_tracing();

    tauri::Builder::default()
        .setup(|app| {
            let state = AppState::default();
            // Spawn the token-store sweeper. Tauri 2 sets up a Tokio runtime
            // inside its async runtime; spawning a tokio task here works
            // because we registered the tokio runtime via tauri's plugin.
            let pp_tokens = state.passphrase_tokens.clone();
            let rk_tokens = state.recovery_key_tokens.clone();
            tauri::async_runtime::spawn(async move {
                pp_tokens.spawn_sweeper();
                rk_tokens.spawn_sweeper();
            });
            app.manage(state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::list_drives,
            commands::plan_encrypt,
            commands::commit_passphrase,
            commands::commit_recovery_key,
            commands::request_passphrase,
            commands::start_encrypt,
            commands::start_unlock,
            commands::dismount,
            commands::pick_folder,
            commands::cancel,
            commands::save_recovery_pdf,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn install_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .compact()
        .init();
}
