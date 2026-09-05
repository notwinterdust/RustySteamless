//! SteamStub DRM Variant 3.0 unpacker (x86 and x64).
//!
//! Byte-exact port of `Steamless.Unpacker.Variant30.{x86,x64}.Main.cs`.

use crate::logger::{Level, Logger};
use crate::options::Options;
use crate::pe::PeFile;
use crate::variants::var_3x::{self, Variant};
use crate::Result;

/// SteamStub Variant 3.0 unpacker.
pub struct Variant30 {
    is64: bool,
}

impl Variant30 {
    /// The 32-bit (x86) variant 3.0 unpacker.
    pub const fn x86() -> Self {
        Self { is64: false }
    }

    /// The 64-bit (x64) variant 3.0 unpacker.
    pub const fn x64() -> Self {
        Self { is64: true }
    }
}

impl crate::variants::Unpacker for Variant30 {
    fn name(&self) -> &'static str {
        if self.is64 {
            "SteamStub Variant 3.0 Unpacker (x64)"
        } else {
            "SteamStub Variant 3.0 Unpacker (x86)"
        }
    }

    fn can_process(&self, pe: &PeFile) -> bool {
        if pe.is_file_64() != self.is64 || !pe.has_section(".bind") {
            return false;
        }
        var_3x::get_header_size(pe, Variant::V30, self.is64)
            .map(var_3x::is_v30_size)
            .unwrap_or(false)
    }

    fn process(&self, pe: &mut PeFile, options: &Options, logger: &dyn Logger) -> Result<()> {
        logger.log(Level::Info, "File is packed with SteamStub Variant 3.0!");

        logger.log(
            Level::Info,
            "Step 1 - Read, decode and validate the SteamStub DRM header.",
        );
        let mut state = var_3x::step1(pe, Variant::V30, self.is64)?;

        logger.log(
            Level::Info,
            "Step 2 - Read, decode and process the payload data.",
        );
        var_3x::step2(pe, options, &mut state, logger)?;

        logger.log(
            Level::Info,
            "Step 3 - Read, decode and dump the SteamDRMP.dll file.",
        );
        var_3x::step3(pe, options, &state, logger)?;

        logger.log(
            Level::Info,
            "Step 4 - Handle .bind section. Find code section.",
        );
        var_3x::step4(pe, options, &mut state, Variant::V30, self.is64, logger)?;

        logger.log(
            Level::Info,
            "Step 5 - Read, decrypt and process code section.",
        );
        var_3x::step5(pe, &mut state, Variant::V30, self.is64, logger)?;

        logger.log(Level::Info, "Step 6 - Rebuild and save the unpacked file.");
        let target = var_3x::step6(pe, options, &state, Variant::V30, self.is64)?;

        logger.log(Level::Success, " --> Unpacked file saved to disk!");
        logger.log(
            Level::Success,
            &format!(" --> File Saved As: {}", target.display()),
        );
        Ok(())
    }
}
