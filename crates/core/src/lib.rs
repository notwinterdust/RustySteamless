//! Rusty-Steamless core library.
//!
//! Cross-platform port of the Steamless C# internals: PE parsing,
//! crypto helpers, pattern scanning and the SteamStub unpacker variants.

use thiserror::Error;

pub mod crypto;
pub mod logger;
pub mod options;
pub mod pattern;
pub mod pe;
pub mod variants;

/// Convenience result type used across the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Top-level error type for the library.
#[derive(Debug, Error)]
pub enum Error {
    /// Input file could not be read from disk.
    #[error("failed to read input file: {0}")]
    Io(#[from] std::io::Error),
    /// The file was not a valid portable executable image.
    #[error("invalid PE file: {0}")]
    InvalidPe(String),
    /// Not enough data to satisfy a read at the given offset.
    #[error("unexpected end of data")]
    OutOfBounds,
    /// An unpacking step failed.
    #[error("unpack failed: {0}")]
    Unpack(String),
    /// A required feature was not found within the file data.
    #[error("pattern not found")]
    PatternNotFound,
}
