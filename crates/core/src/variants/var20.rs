//! SteamStub DRM Variant 2.0 (x86) unpacker.
//!
//! Byte-exact port of `Steamless.Unpacker.Variant20.x86.Main.cs`.

use crate::crypto::xtea::steam_xor;
use crate::logger::{Level, Logger};
use crate::options::Options;
use crate::pe::{Buf, PeFile};
use crate::variants::common::{self, is_mov_reg_imm};
use crate::{Error, Result};

/// SteamStub Variant 2.0 unpacker (x86).
pub struct Variant20;

/// Signature found in the v2.0 bind section used for detection.
const BIND_PATTERN: &str = "53 51 52 56 57 55 8B EC 81 EC 00 10 00 00 BE";
/// Base decode length when scanning the stub for header information.
const SCAN_LENGTH: usize = 4096;

/// Header sizes this variant supports, with the field offsets that apply to
/// each layout (fields differ between the 856 and 884/952 byte structures).
struct HeaderOffsets {
    flags: usize,
    oep: usize,
    code_section_va: usize,
    code_section_size: usize,
    code_section_xor_key: usize,
}

impl HeaderOffsets {
    fn for_size(size: u32) -> Option<Self> {
        Some(match size {
            856 => Self {
                flags: 20,
                oep: 40,
                code_section_va: 44,
                code_section_size: 48,
                code_section_xor_key: 52,
            },
            884 | 952 => Self {
                flags: 24,
                oep: 44,
                code_section_va: 48,
                code_section_size: 52,
                code_section_xor_key: 56,
            },
            _ => return None,
        })
    }
}

struct Header {
    flags: u32,
    oep: u32,
    code_section_va: u32,
    code_section_size: u32,
    code_section_xor_key: u32,
}

impl crate::variants::Unpacker for Variant20 {
    fn name(&self) -> &'static str {
        "SteamStub Variant 2.0 Unpacker (x86)"
    }

    fn can_process(&self, pe: &PeFile) -> bool {
        if pe.is_file_64() || !pe.has_section(".bind") {
            return false;
        }
        common::find_pattern_in_section(pe, ".bind", BIND_PATTERN).is_ok()
    }

    fn process(&self, pe: &mut PeFile, options: &Options, logger: &dyn Logger) -> Result<()> {
        logger.log(Level::Info, "File is packed with SteamStub Variant 2.0!");

        logger.log(
            Level::Info,
            "Step 1 - Read, disassemble and decode the SteamStub DRM header.",
        );
        let header = self.step1(pe)?;

        logger.log(
            Level::Info,
            "Step 2 - Read, decrypt and process the main code section.",
        );
        let code_index = self.step2(pe, options, &header)?;

        logger.log(Level::Info, "Step 3 - Prepare the file sections.");
        self.step3(pe, options, logger)?;

        logger.log(Level::Info, "Step 4 - Rebuild and save the unpacked file.");
        let entry_point = pe.get_rva_from_va(header.oep as u64) as u32;
        let target = common::save(pe, options, entry_point)?;

        logger.log(Level::Success, " --> Unpacked file saved to disk!");
        logger.log(
            Level::Success,
            &format!(" --> File Saved As: {}", target.display()),
        );
        logger.log(
            Level::Debug,
            &format!(" --> Code section index: {code_index}"),
        );
        Ok(())
    }
}

impl Variant20 {
    /// Step 1: read, disassemble and decode the SteamStub DRM header.
    fn step1(&self, pe: &PeFile) -> Result<Header> {
        // Obtain the file entry offset.
        let file_offset = pe.get_file_offset_from_rva(pe.optional.address_of_entry_point as u64);

        // Validate the DRM header.
        let sig_off = file_offset
            .checked_sub(4)
            .ok_or_else(|| Error::Unpack("entry point is too small".into()))?;
        let signature = pe.data.rd_u32(sig_off as usize).ok_or(Error::OutOfBounds)?;
        if signature != 0xC0DEC0DE {
            return Err(Error::Unpack("missing 0xC0DEC0DE signature".into()));
        }

        // Disassemble the file to locate the needed DRM information.
        let (struct_offset, struct_size) = self.disassemble_file(pe)?;
        let header_offsets = HeaderOffsets::for_size(struct_size).ok_or_else(|| {
            Error::Unpack(format!(
                "invalid/unknown variant header size: {struct_size}"
            ))
        })?;

        // Obtain the DRM header data.
        let header_rva = struct_offset as u64;
        let struct_file_offset = pe.get_file_offset_from_rva(header_rva);
        let mut header_data = common::read_range(pe, struct_file_offset, struct_size as usize)?;

        // Xor decode the header data.
        let size = header_data.len() as u32;
        steam_xor(&mut header_data, size, 0);

        let header = Header {
            flags: header_data
                .rd_u32(header_offsets.flags)
                .ok_or(Error::OutOfBounds)?,
            oep: header_data
                .rd_u32(header_offsets.oep)
                .ok_or(Error::OutOfBounds)?,
            code_section_va: header_data
                .rd_u32(header_offsets.code_section_va)
                .ok_or(Error::OutOfBounds)?,
            code_section_size: header_data
                .rd_u32(header_offsets.code_section_size)
                .ok_or(Error::OutOfBounds)?,
            code_section_xor_key: header_data
                .rd_u32(header_offsets.code_section_xor_key)
                .ok_or(Error::OutOfBounds)?,
        };

        Ok(header)
    }

    /// Disassembles the stub to find the header struct offset and size.
    ///
    /// Mirrors `DisassembleFile`: the first `mov reg, imm` yields the struct
    /// RVA, the second yields its dword count (size = imm * 4).
    fn disassemble_file(&self, pe: &PeFile) -> Result<(u32, u32)> {
        let entry_offset = pe.get_file_offset_from_rva(pe.optional.address_of_entry_point as u64);

        let mut struct_offset = 0u64;
        let mut struct_size = 0u64;

        for insn in common::decode_block(&pe.data, entry_offset as usize, SCAN_LENGTH, entry_offset)
        {
            if struct_offset > 0 && struct_size > 0 {
                return Ok((struct_offset as u32, struct_size as u32));
            }

            // Looks for: mov reg, immediate
            if let Some(imm) = is_mov_reg_imm(&insn) {
                if struct_offset == 0 {
                    struct_offset = imm - pe.optional.image_base;
                    continue;
                }
            }

            // Looks for: mov reg, immediate
            if let Some(imm) = is_mov_reg_imm(&insn) {
                struct_size = imm * 4;
            }
        }

        Err(Error::Unpack(
            "failed to locate the DRM header information".into(),
        ))
    }

    /// Step 2: read, decrypt and process the main code section.
    fn step2(&self, pe: &mut PeFile, options: &Options, header: &Header) -> Result<usize> {
        // Determine the code section RVA.
        let mut code_section_rva = pe.optional.base_of_code as u64;

        // This is not really ideal to do but this breaks support for other
        // variants of this version when disabled (mirrors the C# TODO).
        if options.use_experimental_features && header.code_section_va != 0 {
            code_section_rva = pe.get_rva_from_va(header.code_section_va as u64);
        }

        // Get the code section.
        let code_section = pe
            .get_owner_section(code_section_rva)
            .ok_or_else(|| Error::Unpack("code section not found".into()))?;
        if code_section.pointer_to_raw_data == 0 || code_section.size_of_raw_data == 0 {
            return Err(Error::Unpack("code section is invalid".into()));
        }

        let code_index = pe
            .section_index_of(code_section)
            .ok_or_else(|| Error::Unpack("code section not found".into()))?;

        // Get the code section data.
        let section_offset = pe.get_file_offset_from_rva(code_section.virtual_address as u64);
        let mut code_section_data =
            common::read_range(pe, section_offset, code_section.size_of_raw_data as usize)?;

        // Skip the code section encoding if we do not need to process it.
        if (header.flags & 0x04) == 0 {
            return Ok(code_index);
        }

        // Decode the code section data (rolling XOR).
        let mut key = header.code_section_xor_key;
        let mut off = 0usize;
        for _ in 0..(header.code_section_size >> 2) {
            let val1 = code_section_data
                .get(off..off + 4)
                .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                .ok_or(Error::OutOfBounds)?;
            let val2 = val1 ^ key;
            key = val1;
            code_section_data[off..off + 4].copy_from_slice(&val2.to_le_bytes());
            off += 4;
        }

        pe.section_data[code_index] = code_section_data;
        Ok(code_index)
    }

    /// Step 3: prepare the file sections.
    fn step3(&self, pe: &mut PeFile, options: &Options, logger: &dyn Logger) -> Result<()> {
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
