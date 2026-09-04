//! Rusty-Steamless core library.
//!
//! Cross-platform port of the Steamless C# internals: PE parsing,
//! crypto helpers, pattern scanning and the SteamStub unpacker variants.

pub mod pe;
pub mod crypto;
pub mod pattern;
pub mod options;