//! `rusty-steamless` - SteamStub DRM remover CLI.
//!
//! Auto-detects which SteamStub variant packed a file and unpacks it next to
//! the original as `<file>.unpacked.exe`.

use anyhow::{Context, Result};
use clap::Parser;

use rusty_core::logger::{Level, Logger};
use rusty_core::options::Options;
use rusty_core::pe::PeFile;
use rusty_core::variants::unpackers;

/// SteamStub DRM remover.
#[derive(Debug, Parser)]
#[command(name = "rusty-steamless", version, about)]
struct Args {
    /// The file to unpack (a packed executable or a directory of them).
    #[arg(required = true)]
    file: String,

    /// Suppress output except for errors.
    #[arg(short = 'q', long, conflicts_with = "verbose")]
    quiet: bool,

    /// Show debug messages.
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Keep the .bind section in the unpacked file.
    #[arg(long)]
    keepbind: bool,

    /// Keep the DOS stub data in the unpacked file (default is to zero it).
    #[arg(long)]
    keepstub: bool,

    /// Dump the decoded SteamStub payload to disk (`<file>.payload`).
    #[arg(long)]
    dumppayload: bool,

    /// Dump the decrypted SteamDRMP.dll to disk.
    #[arg(long)]
    dumpdrmp: bool,

    /// Re-align unpacked sections to their alignment values.
    #[arg(long)]
    realign: bool,

    /// Recalculate the unpacked file's checksum after saving.
    #[arg(long)]
    recalcchecksum: bool,

    /// Enable experimental features.
    #[arg(long)]
    exp: bool,
}

/// Prints log messages to the console.
struct ConsoleLogger {
    quiet: bool,
    verbose: bool,
}

impl Logger for ConsoleLogger {
    fn log(&self, level: Level, message: &str) {
        if self.quiet && level != Level::Error {
            return;
        }
        if !self.verbose && level == Level::Debug {
            return;
        }

        let prefix = match level {
            Level::Debug => "+",
            Level::Info => "*",
            Level::Success => "-",
            Level::Error => "!",
        };
        println!("[{prefix}] {message}");
    }
}

/// Attempts to unpack `path` with every known variant, in C# CLI order.
fn unpack_path(path: &str, options: &Options, logger: &dyn Logger) -> Result<()> {
    let pe = PeFile::parse(path)
        .with_context(|| format!("failed to parse '{}' as a portable executable", path))?;

    for unpacker in unpackers() {
        if !unpacker.can_process(&pe) {
            continue;
        }

        println!("[*] {path} is packed!");
        println!("[*] Attempting to unpack with: {}", unpacker.name());

        // Parse a fresh copy per attempt so a failed run never mutates the
        // image checked by the remaining variants.
        let mut fresh = PeFile::parse(path)
            .with_context(|| format!("failed to parse '{}' as a portable executable", path))?;
        match unpacker.process(&mut fresh, options, logger) {
            Ok(()) => return Ok(()),
            Err(error) => {
                logger.log(
                    Level::Error,
                    &format!("Failed to unpack with {}: {error}", unpacker.name()),
                );
            }
        }
    }

    Err(anyhow::anyhow!(
        "no SteamStub variant matched '{}' (is it packed with SteamStub?)",
        path
    ))
}

fn main() {
    if let Err(error) = run() {
        eprintln!("[!] {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Args::parse();

    let options = Options {
        verbose_output: args.verbose,
        keep_bind_section: args.keepbind,
        dump_payload_to_disk: args.dumppayload,
        dump_steam_drmp_to_disk: args.dumpdrmp,
        use_experimental_features: args.exp,
        realign_sections: args.realign,
        zero_dos_stub_data: !args.keepstub,
        recalculate_file_checksum: args.recalcchecksum,
    };

    let logger = ConsoleLogger {
        quiet: args.quiet,
        verbose: args.verbose,
    };

    if std::path::Path::new(&args.file).is_dir() {
        let mut failed = false;
        for entry in std::fs::read_dir(&args.file)
            .with_context(|| format!("failed to read directory '{}'", args.file))?
        {
            let entry = entry.context("failed to read directory entry")?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let target = path.display().to_string();
            if let Err(error) = unpack_path(&target, &options, &logger) {
                logger.log(Level::Error, &error.to_string());
                failed = true;
            }
        }
        if failed {
            anyhow::bail!("one or more files failed to unpack");
        }
        return Ok(());
    }

    match unpack_path(&args.file, &options, &logger) {
        Ok(()) => Ok(()),
        Err(error) => Err(error),
    }
}
