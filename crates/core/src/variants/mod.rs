//! Unpacker variants.
//!
//! A faithful port of the Steamless C# unpacker plugins:
//!
//! * [`var10`] - SteamStub Variant 1.0 (x86)
//! * [`var20`] - SteamStub Variant 2.0 (x86)
//! * [`var21`] - SteamStub Variant 2.1 (x86)
//! * [`var30`] - SteamStub Variant 3.0 (x86 + x64)
//! * [`var31`] - SteamStub Variant 3.1 (x86 + x64)
//!
//! The [`Unpacker`] trait mirrors the C# `SteamlessPlugin` contract:
//! [`can_process`](Unpacker::can_process) sniffs whether a file matches the
//! variant and [`process`](Unpacker::process) performs the unpacking.

pub mod common;
pub mod var10;
pub mod var20;
pub mod var21;
pub mod var30;
pub mod var31;
pub(crate) mod var_3x;

use crate::logger::Logger;
use crate::options::Options;
use crate::pe::PeFile;
use crate::Result;

/// A SteamStub variant unpacker.
pub trait Unpacker {
    /// The human readable name of the unpacker.
    fn name(&self) -> &'static str;

    /// Returns true if the file can be processed by this variant.
    fn can_process(&self, pe: &PeFile) -> bool;

    /// Unpacks `pe`, mutating it in place, and writes the `.unpacked.exe`
    /// output next to the input file.
    fn process(&self, pe: &mut PeFile, options: &Options, logger: &dyn Logger) -> Result<()>;
}

/// The unpackers that should be tried against a file, in the same order the
/// C# CLI discovers them (sorted by plugin name: variants 1.0, 2.0, 2.1,
/// 3.0 x64, 3.0 x86, 3.1 x64, 3.1 x86).
pub fn unpackers() -> Vec<Box<dyn Unpacker>> {
    vec![
        Box::new(var10::Variant10),
        Box::new(var20::Variant20),
        Box::new(var21::Variant21),
        Box::new(var30::Variant30::x64()),
        Box::new(var30::Variant30::x86()),
        Box::new(var31::Variant31::x64()),
        Box::new(var31::Variant31::x86()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_order_matches_csharp_cli() {
        let names: Vec<String> = unpackers().iter().map(|u| u.name().to_string()).collect();
        assert!(names[0].contains("1.0"));
        assert!(names[1].contains("2.0"));
        assert!(names[2].contains("2.1"));
        assert!(names[3].contains("3.0") && names[3].contains("x64"));
        assert!(names[4].contains("3.0") && names[4].contains("x86"));
        assert!(names[5].contains("3.1") && names[5].contains("x64"));
        assert!(names[6].contains("3.1") && names[6].contains("x86"));
    }
}
