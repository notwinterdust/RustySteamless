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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logger::NullLogger;
    use crate::pe::Buf;
    use crate::variants::Unpacker;

    const IMAGE_BASE: u32 = 0x400000;
    const EP_RVA: u32 = 0x1000;
    const BIND_VA: u32 = 0x2000;
    const HEADER_RAW: u32 = 0xB00;
    const HEADER_SIZE: usize = 0x6A * 4;

    /// Assembles a minimal x86 PE32 carrying a synthetic SteamStub v1.0 stub.
    ///
    /// `.bind` holds the unpacker code patterns; the XOR-obfuscated header sits
    /// in the trailing bytes (`raw offset == RVA`, outside every section), which
    /// mirrors how `GetFileOffsetFromRva` resolves header pointers in real files.
    fn build_v10_pe() -> Vec<u8> {
        let text_raw = 0x300u32;
        let bind_raw = 0x500u32;
        let bind_size = 0x600u32;

        let mut bind = vec![0u8; bind_size as usize];
        // v1.0 bind unpacker header pattern (offset 0), header pointer VA and
        // the size byte that the stub multiplies by four.
        bind[0..8].copy_from_slice(&[0x60, 0x81, 0xEC, 0x00, 0x10, 0x00, 0x00, 0xBE]);
        bind.wr_u32(8, IMAGE_BASE + HEADER_RAW);
        bind[12..14].copy_from_slice(&[0xB9, 0x6A]);

        // SteamStub header plaintext, obfuscated with the `b ^= (x*x) as u8`
        // scheme, where BindFunction must equal image base + entry point.
        let mut plain = vec![0u8; HEADER_SIZE];
        plain.wr_u32(8, IMAGE_BASE + EP_RVA);

        // OEP pattern near the end of the bind section (outside the header).
        let oep_va = IMAGE_BASE + 0x1234;
        bind[0x200..0x202].copy_from_slice(&[0x61, 0xB8]);
        bind.wr_u32(0x202, oep_va);
        bind[0x206..0x208].copy_from_slice(&[0xFF, 0xE0]);

        let mut file = vec![0u8; (HEADER_RAW as usize) + HEADER_SIZE];
        // DOS header.
        file[0] = b'M';
        file[1] = b'Z';
        file.wr_u32(0x3C, 0x100); // e_lfanew
                                  // NT headers.
        file[0x100..0x104].copy_from_slice(b"PE\0\0");
        file.wr_u16(0x104, 0x014C); // IMAGE_FILE_MACHINE_I386
        file.wr_u16(0x106, 2); // number of sections
        file.wr_u16(0x114, 0xE0); // size of optional header
                                  // Optional header (PE32).
        file.wr_u16(0x118, 0x10B); // PE32 magic
        file.wr_u32(0x128, EP_RVA); // address of entry point
        file.wr_u32(0x12C, EP_RVA); // base of code
        file.wr_u64(0x134, IMAGE_BASE as u64);
        file.wr_u32(0x138, 0x1000); // section alignment
        file.wr_u32(0x13C, 0x200); // file alignment
        file.wr_u32(0x150, 0x3000); // size of image
        file.wr_u32(0x154, 0x300); // size of headers

        let sections = 0x118 + 0xE0;
        // ".text"
        file[sections..sections + 8].copy_from_slice(b".text\0\0\0");
        file.wr_u32(sections + 12, EP_RVA); // virtual address
        file.wr_u32(sections + 16, 0x200); // size of raw data
        file.wr_u32(sections + 20, text_raw); // pointer to raw data
                                              // ".bind"
        file[sections + 40..sections + 48].copy_from_slice(b".bind\0\0\0");
        file.wr_u32(sections + 52, BIND_VA);
        file.wr_u32(sections + 56, bind_size);
        file.wr_u32(sections + 60, bind_raw);

        file[text_raw as usize..(text_raw + 0x200) as usize].fill(0x90);
        file[bind_raw as usize..(bind_raw + bind_size) as usize].copy_from_slice(&bind);
        let obfuscated: Vec<u8> = plain
            .iter()
            .enumerate()
            .map(|(i, byte)| *byte ^ ((i * i) as u8))
            .collect();
        file[HEADER_RAW as usize..(HEADER_RAW as usize) + HEADER_SIZE].copy_from_slice(&obfuscated);
        file
    }

    #[test]
    fn v10_round_trips_synthetic_packed_pe() {
        let temp = std::env::temp_dir();
        let input = temp.join(format!("rusty_v10_{}.exe", std::process::id()));
        let output = temp.join(format!("rusty_v10_{}.exe.unpacked.exe", std::process::id()));

        std::fs::write(&input, build_v10_pe()).unwrap();
        let mut pe = PeFile::from_bytes(std::fs::read(&input).unwrap(), input.clone()).unwrap();

        let unpacker = Variant10;
        assert!(unpacker.can_process(&pe), "synthetic file must be v1.0");
        unpacker
            .process(&mut pe, &Options::default(), &NullLogger)
            .unwrap();

        let unpacked = std::fs::read(&output).unwrap();
        // Entry point rewritten to the original entry point.
        assert_eq!(unpacked.rd_u32(0x128), Some(0x1234));
        // .bind section removed.
        assert_eq!(unpacked.rd_u16(0x106), Some(1));

        let _ = std::fs::remove_file(input);
        let _ = std::fs::remove_file(output);
    }
}
