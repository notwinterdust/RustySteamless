//! SteamStub DRM Variant 1.0 (x86) unpacker.
//!
//! Byte-exact port of `Steamless.Unpacker.Variant10.x86.Main.cs`.

use crate::logger::{Level, Logger};
use crate::options::Options;
use crate::pe::{Buf, PeFile};
use crate::variants::common;
use crate::{Error, Result};

/// SteamStub Variant 1.0 unpacker (x86).
pub struct Variant10;

/// Signature found at the start of the v1.x bind unpacker function.
const BIND_START_PATTERN: &str = "60 81 EC 00 10 00 00 BE ?? ?? ?? ?? B9 6A";
/// Signature near the end of the v1.x bind unpacker function (the OEP jump).
const OEP_PATTERN: &str = "61 B8 ?? ?? ?? ?? FF E0";

impl crate::variants::Unpacker for Variant10 {
    fn name(&self) -> &'static str {
        "SteamStub Variant 1.0 Unpacker (x86)"
    }

    fn can_process(&self, pe: &PeFile) -> bool {
        if pe.is_file_64() || !pe.has_section(".bind") {
            return false;
        }
        common::find_pattern_in_section(pe, ".bind", BIND_START_PATTERN).is_ok()
    }

    fn process(&self, pe: &mut PeFile, options: &Options, logger: &dyn Logger) -> Result<()> {
        logger.log(Level::Info, "File is packed with SteamStub Variant 1.0!");

        logger.log(
            Level::Info,
            "Step 1 - Read, decode and validate the SteamStub DRM header.",
        );
        let original_entry_point = self.step1(pe)?;

        logger.log(Level::Info, "Step 2 - Handle .bind section.");
        self.step2(pe, options, logger)?;

        logger.log(Level::Info, "Step 3 - Rebuild and save the unpacked file.");
        let target = common::save(pe, options, original_entry_point)?;

        logger.log(Level::Success, " --> Unpacked file saved to disk!");
        logger.log(
            Level::Success,
            &format!(" --> File Saved As: {}", target.display()),
        );
        Ok(())
    }
}

impl Variant10 {
    /// Step 1: read, decode and validate the SteamStub DRM header.
    fn step1(&self, pe: &PeFile) -> Result<u32> {
        let bind = pe
            .get_section(".bind")
            .ok_or_else(|| Error::Unpack(".bind section not found".into()))?;
        if !bind.is_valid() {
            return Err(Error::Unpack(".bind section is invalid".into()));
        }

        let bind_data = pe
            .get_section_data_by_name(".bind")
            .ok_or_else(|| Error::Unpack(".bind section data missing".into()))?;

        // Find the header information from the unpacker call.
        let offset = crate::pattern::find_pattern(bind_data, BIND_START_PATTERN)?;
        let header_pointer = bind_data.rd_u32(offset + 8).ok_or(Error::OutOfBounds)?;
        let header_size = bind_data.rd_u32(offset + 13).ok_or(Error::OutOfBounds)? as usize * 4;

        // Calculate the file offset from the pointer.
        let file_offset =
            pe.get_file_offset_from_rva(header_pointer as u64 - pe.optional.image_base);

        // Read and decrypt the header data.
        let mut header_data = common::read_range(pe, file_offset, header_size)?;
        for (x, b) in header_data.iter_mut().enumerate() {
            *b ^= (x * x) as u8;
        }

        // Validate the header via the unpacker function matching the file entry point.
        let bind_function = header_data.rd_u32(8).ok_or(Error::OutOfBounds)?;
        if bind_function as u64 - pe.optional.image_base
            != pe.optional.address_of_entry_point as u64
        {
            return Err(Error::Unpack(
                "header does not match the file entry point".into(),
            ));
        }

        // Find the OEP from the unpacker function.
        let offset = crate::pattern::find_pattern(bind_data, OEP_PATTERN)?;
        let original_entry_point = bind_data
            .rd_u32(offset + 2)
            .ok_or(Error::OutOfBounds)?
            .wrapping_sub(pe.optional.image_base as u32);

        Ok(original_entry_point)
    }

    /// Step 2: remove the .bind section if requested.
    fn step2(&self, pe: &mut PeFile, options: &Options, logger: &dyn Logger) -> Result<()> {
        if common::remove_bind_section(pe, options)? {
            logger.log(
                Level::Debug,
                " --> .bind section was removed from the file.",
            );
        } else {
            logger.log(Level::Debug, " --> .bind section was kept in the file.");
        }
        Ok(())
    }
}
