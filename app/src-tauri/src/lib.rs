//! Tauri command layer that wraps the Rusty-Steamless core.

use rusty_core::logger::{Level, Logger};
use rusty_core::options::Options;
use rusty_core::pe::PeFile;
use rusty_core::variants::unpackers;
use serde::Serialize;
use tauri::{AppHandle, Emitter};

/// A single line forwarded to the frontend console.
#[derive(Clone, Debug, Serialize)]
struct LogEvent {
    level: String,
    message: String,
}

/// Bridges the core `Logger` trait to Tauri events (`log`).
struct EventLogger {
    app: AppHandle,
}

impl Logger for EventLogger {
    fn log(&self, level: Level, message: &str) {
        let level = match level {
            Level::Debug => "debug",
            Level::Info => "info",
            Level::Success => "success",
            Level::Error => "error",
        };
        let _ = self.app.emit(
            "log",
            LogEvent {
                level: level.to_string(),
                message: message.to_string(),
            },
        );
    }
}

/// Result of an unpack attempt.
#[derive(Clone, Debug, Serialize)]
struct UnpackReport {
    success: bool,
    message: String,
    used_variant: Option<String>,
}

/// Lists the SteamStub variants known to the core, in dispatch order.
#[tauri::command]
fn list_variants() -> Vec<String> {
    unpackers()
        .iter()
        .map(|unpacker| unpacker.name().to_string())
        .collect()
}

/// Unpack `path` with the given options, streaming log lines to the `log`
/// event as the work progresses.
#[tauri::command]
fn unpack(app: AppHandle, path: String, options: Options) -> Result<UnpackReport, String> {
    let logger = EventLogger { app };

    let pe = PeFile::parse(&path).map_err(|error| {
        let message = format!("failed to parse '{path}': {error}");
        logger.log(Level::Error, &message);
        message
    })?;

    for unpacker in unpackers() {
        if !unpacker.can_process(&pe) {
            continue;
        }

        let name = unpacker.name();
        logger.log(Level::Info, &format!("This file is packed with: {name}"));
        logger.log(Level::Info, "Attempting to unpack…");

        // Parse a fresh copy per attempt so a failed run never mutates the
        // image checked by the remaining variants.
        let mut fresh = PeFile::parse(&path).map_err(|error| {
            let message = format!("failed to parse '{path}': {error}");
            logger.log(Level::Error, &message);
            message
        })?;

        match unpacker.process(&mut fresh, &options, &logger) {
            Ok(()) => {
                logger.log(Level::Success, &format!("Unpacked successfully with {name}!"));
                return Ok(UnpackReport {
                    success: true,
                    message: "unpacked successfully".to_string(),
                    used_variant: Some(name.to_string()),
                });
            }
            Err(error) => logger.log(
                Level::Error,
                &format!("Failed to unpack with {name}: {error}"),
            ),
        }
    }

    let message = format!("no SteamStub variant matched '{path}'");
    logger.log(Level::Error, "No SteamStub variant matched this file!");
    Ok(UnpackReport {
        success: false,
        message,
        used_variant: None,
    })
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![list_variants, unpack])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}