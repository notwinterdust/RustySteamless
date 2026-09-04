//! Shared implementation for the SteamStub 3.x variants.
//!
//! Variants 3.0 and 3.1 (x86 and x64) differ only in the header layout and a
//! handful of per-variant behaviors; everything else is shared here. This is a
//! byte-exact port of the corresponding C# `Main.cs` files.

use crate::crypto::aes::{AesHelper, AesMode};
use crate::crypto::xtea::{steam_drmp_pass1, steam_xor};
use crate::logger::{Level, Logger};
use crate::options::Options;
use crate::pe::{Buf, PeFile};
use crate::variants::common::{self, DRM_FLAG_NO_ENCRYPTION};
use crate::{Error, Result};

/// Which Variant 3.x family a file belongs to.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Variant {
    V30,
    V31,
}

/// The decoded SteamStub 3.x DRM header.
pub(crate) struct Var3xHeader {
    /// Key dword stored at header offset 0 (after XOR decode).
    pub xor_key: u32,
    /// Structure signature (0xC0DEC0DE for v3.0, 0xC0DEC0DF for v3.1).
    pub signature: u32,
    pub bind_section_offset: u32,
    pub original_entry_point: u32,
    pub payload_size: u32,
    pub drmp_dll_offset: u32,
    pub drmp_dll_size: u32,
    pub flags: u32,
    pub code_section_virtual_address: u64,
    pub code_section_raw_size: u64,
    pub aes_key: [u8; 32],
    pub aes_iv: [u8; 16],
    pub code_section_stolen_data: [u8; 16],
    pub encryption_keys: [u32; 4],
    pub has_tls_callback: u32,
}

/// Per-file state threaded through the unpacker steps.
pub(crate) struct State {
    pub header: Var3xHeader,
    /// The XOR key carried from the header decode into the payload decode.
    pub xor_key: u32,
    pub tls_as_oep: bool,
    pub tls_oep_rva: u64,
    pub tls_oep_override: u32,
    pub code_index: Option<usize>,
    pub code_section_data: Option<Vec<u8>>,
}

/// v3.0/v3.1 x86 shared stub signature.
const X86_VARIANT: &str =
    "E8 00 00 00 00 50 53 51 52 56 57 55 8B 44 24 1C 2D 05 00 00 00 8B CC 83 E4 F0 51 51 51 50";
/// v3.0/v3.1 x64 shared stub signature.
const X64_VARIANT: &str = "E8 00 00 00 00 50 53 51 52 56 57 55 41 50";

/// v3.0 header size pattern (the `lea eax, [mem+headerSize]` prologue).
const X86_V30_HEADER_SIZE_PATTERN: &str = "55 8B EC 81 EC ?? ?? ?? ?? 53 ?? ?? ?? ?? ?? 68";
const X86_V30_HEADER_SIZE_PATTERN_2: &str = "55 8B EC 81 EC ?? ?? ?? ?? 53 ?? ?? ?? ?? ?? 8D 83";
/// v3.x x64 header size patterns (lea with an absolute displacement).
const X64_HEADER_SIZE_48: &str = "48 8D 91 ?? ?? ?? ?? 48";
const X64_HEADER_SIZE_41: &str = "48 8D 91 ?? ?? ?? ?? 41";
/// v3.1 x86 version patterns (v3.1 / v3.1.1 / v3.1.2).
const X86_V31_HEADER_SIZE_68: &str = "55 8B EC 81 EC ?? ?? ?? ?? 53 ?? ?? ?? ?? ?? 68";
const X86_V31_HEADER_SIZE_8D83: &str = "55 8B EC 81 EC ?? ?? ?? ?? 53 ?? ?? ?? ?? ?? 8D 83";
const X86_V31_HEADER_SIZE_8D: &str =
    "55 8B EC 81 EC ?? ?? ?? ?? 56 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8D";
/// v3.1.2 x64 header size pattern.
const X64_V31_HEADER_SIZE_C7: &str = "48 C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 48";
/// Pattern used to recover the true OEP when the TLS callback hides it (v3.0 x64).
const TLS_OEP_KEY_PATTERN: &str = "48 81 EA ?? ?? ?? ?? 8B 12 81 F2";

/// Reads a little-endian i32 as-is (C# `BitConverter.ToInt32`).
fn rd_i32(data: &[u8], off: usize) -> Option<i32> {
    data.get(off..off + 4)
        .map(|b| i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn rd_u32(data: &[u8], off: usize) -> Result<u32> {
    data.rd_u32(off).ok_or(Error::OutOfBounds)
}

fn rd_u64(data: &[u8], off: usize) -> Result<u64> {
    data.rd_u64(off).ok_or(Error::OutOfBounds)
}

fn read_array<const N: usize>(data: &[u8], off: usize) -> Result<[u8; N]> {
    data.rd_bytes(off, N)
        .ok_or(Error::OutOfBounds)?
        .try_into()
        .map_err(|_| Error::OutOfBounds)
}

fn parse_header(data: &[u8], variant: Variant) -> Result<Var3xHeader> {
    Ok(match variant {
        Variant::V30 => Var3xHeader {
            xor_key: rd_u32(data, 0)?,
            signature: rd_u32(data, 4)?,
            bind_section_offset: rd_u32(data, 20)?,
            original_entry_point: rd_u32(data, 28)?,
            payload_size: rd_u32(data, 36)?,
            drmp_dll_offset: rd_u32(data, 40)?,
            drmp_dll_size: rd_u32(data, 44)?,
            flags: rd_u32(data, 52)?,
            code_section_virtual_address: rd_u32(data, 64)? as u64,
            code_section_raw_size: rd_u32(data, 68)? as u64,
            aes_key: read_array(data, 72)?,
            aes_iv: read_array(data, 120)?,
            code_section_stolen_data: read_array(data, 136)?,
            encryption_keys: [
                rd_u32(data, 152)?,
                rd_u32(data, 156)?,
                rd_u32(data, 160)?,
                rd_u32(data, 164)?,
            ],
            has_tls_callback: rd_u32(data, 168)?,
        },
        Variant::V31 => Var3xHeader {
            xor_key: rd_u32(data, 0)?,
            signature: rd_u32(data, 4)?,
            bind_section_offset: rd_u32(data, 24)?,
            original_entry_point: rd_u32(data, 32)? as u32,
            payload_size: rd_u32(data, 44)?,
            drmp_dll_offset: rd_u32(data, 48)?,
            drmp_dll_size: rd_u32(data, 52)?,
            flags: rd_u32(data, 60)?,
            code_section_virtual_address: rd_u64(data, 72)?,
            code_section_raw_size: rd_u64(data, 80)?,
            aes_key: read_array(data, 88)?,
            aes_iv: read_array(data, 168)?,
            code_section_stolen_data: read_array(data, 184)?,
            encryption_keys: [
                rd_u32(data, 200)?,
                rd_u32(data, 204)?,
                rd_u32(data, 208)?,
                rd_u32(data, 212)?,
            ],
            has_tls_callback: 0,
        },
    })
}

/// Header size the variant is looking for, when the struct layout is fixed.
pub(crate) fn expected_size(variant: Variant) -> u32 {
    match variant {
        Variant::V30 => 0x00, // dynamic (0xB0 or 0xD0)
        Variant::V31 => 0xF0,
    }
}

/// True when the header size matches a known v3.0 layout (0xB0/0xD0).
pub(crate) fn is_v30_size(size: u32) -> bool {
    size == 0xB0 || size == 0xD0
}

/// Locates the SteamStub header size inside the `.bind` section.
pub(crate) fn get_header_size(pe: &PeFile, variant: Variant, is64: bool) -> Result<u32> {
    let bind = pe
        .get_section_data_by_name(".bind")
        .ok_or_else(|| Error::Unpack("bind section data missing".into()))?;
    // The x64 3.1 search is limited to the first 0x3000 bytes of .bind.
    let bind = if is64 && variant == Variant::V31 {
        let n = bind.len().min(0x3000);
        &bind[..n]
    } else {
        bind
    };

    match (variant, is64) {
        (Variant::V30, false) => {
            if crate::pattern::find_pattern(bind, X86_VARIANT).is_err() {
                return Err(Error::Unpack("v3.0 x86 signature not found".into()));
            }
            let (offset, add) =
                match crate::pattern::find_pattern(bind, X86_V30_HEADER_SIZE_PATTERN) {
                    Ok(o) => (o, 16usize),
                    Err(_) => (
                        crate::pattern::find_pattern(bind, X86_V30_HEADER_SIZE_PATTERN_2).map_err(
                            |_| Error::Unpack("v3.0 x86 header size pattern not found".into()),
                        )?,
                        22usize,
                    ),
                };
            Ok(rd_i32(bind, offset + add).ok_or(Error::OutOfBounds)? as u32)
        }
        (Variant::V30, true) => {
            if crate::pattern::find_pattern(bind, X64_VARIANT).is_err() {
                return Err(Error::Unpack("v3.0 x64 signature not found".into()));
            }
            let offset = crate::pattern::find_pattern(bind, X64_HEADER_SIZE_48)
                .ok()
                .or_else(|| crate::pattern::find_pattern(bind, X64_HEADER_SIZE_41).ok())
                .ok_or_else(|| Error::Unpack("v3.0 x64 header size pattern not found".into()))?;
            Ok(rd_i32(bind, offset + 3)
                .ok_or(Error::OutOfBounds)?
                .unsigned_abs())
        }
        (Variant::V31, false) => {
            if crate::pattern::find_pattern(bind, X86_VARIANT).is_err() {
                return Err(Error::Unpack("v3.1 x86 signature not found".into()));
            }
            for (pat, add) in [
                (X86_V31_HEADER_SIZE_68, 0x10),
                (X86_V31_HEADER_SIZE_8D83, 0x16),
                (X86_V31_HEADER_SIZE_8D, 0x10),
            ] {
                if let Ok(offset) = crate::pattern::find_pattern(bind, pat) {
                    return Ok(rd_i32(bind, offset + add).ok_or(Error::OutOfBounds)? as u32);
                }
            }
            Err(Error::Unpack("v3.1 x86 version pattern not found".into()))
        }
        (Variant::V31, true) => {
            if crate::pattern::find_pattern(bind, X64_VARIANT).is_err() {
                return Err(Error::Unpack("v3.1 x64 signature not found".into()));
            }
            let offset = crate::pattern::find_pattern(bind, X64_HEADER_SIZE_48)
                .ok()
                .or_else(|| crate::pattern::find_pattern(bind, X64_HEADER_SIZE_41).ok())
                .map(Ok::<_, Error>)
                .unwrap_or_else(|| {
                    crate::pattern::find_pattern(bind, X64_V31_HEADER_SIZE_C7)
                        .map(|o| o + usize::from(o > 0) * 5)
                        .map_err(|_| Error::Unpack("v3.1 x64 header size pattern not found".into()))
                })?;
            Ok(rd_i32(bind, offset + 3)
                .ok_or(Error::OutOfBounds)?
                .unsigned_abs())
        }
    }
}

/// Whether the code section validity is enforced for this variant.
fn validates_code_section(variant: Variant, is64: bool) -> bool {
    !(variant == Variant::V31 && is64)
}

/// Step 1 - Read, decode and validate the SteamStub DRM header.
pub(crate) fn step1(pe: &mut PeFile, variant: Variant, is64: bool) -> Result<State> {
    // The v3.0 header location is size dependent; v3.1 always uses 0xF0.
    let header_size = if variant == Variant::V30 {
        get_header_size(pe, variant, is64)?
    } else {
        0xF0
    };

    let read_header = |f: &PeFile, file_offset: u64| -> Result<(Vec<u8>, u32, Var3xHeader)> {
        let start = file_offset
            .checked_sub(header_size as u64)
            .ok_or_else(|| Error::Unpack("header extends below the file start".into()))?;
        let mut data = common::read_range(f, start, header_size as usize)?;
        let xor_key = steam_xor(&mut data, header_size, 0);
        let header = parse_header(&data, variant)?;
        Ok((data, xor_key, header))
    };

    let expected = match variant {
        Variant::V30 => 0xC0DEC0DE,
        Variant::V31 => 0xC0DEC0DF,
    };

    let (_, xor_key, header) = read_header(
        pe,
        pe.get_file_offset_from_rva(pe.optional.address_of_entry_point as u64),
    )?;
    if header.signature == expected {
        return Ok(State {
            header,
            xor_key,
            tls_as_oep: false,
            tls_oep_rva: 0,
            tls_oep_override: 0,
            code_index: None,
            code_section_data: None,
        });
    }

    // Try again using the TLS callback (if any) as the OEP instead..
    let first_callback =
        pe.tls_callbacks.first().copied().ok_or_else(|| {
            Error::Unpack("header signature mismatch and no TLS callbacks".into())
        })?;

    let (_, xor_key, header) = read_header(
        pe,
        pe.get_file_offset_from_rva(pe.get_rva_from_va(first_callback)),
    )?;

    // The v3.1 (and v3.0 x64) TLS paths require a matching signature; the
    // original v3.0 x86 plugin accepts the TLS location unconditionally.
    if (variant == Variant::V31 || is64) && header.signature != expected {
        return Err(Error::Unpack("header signature mismatch".into()));
    }

    let tls_oep_rva = pe.get_rva_from_va(first_callback);
    let mut tls_oep_override = 0u32;

    // v3.0 x64 only: when the TLS callback replaces the OEP, rebuild it.
    if variant == Variant::V30 && is64 && header.has_tls_callback == 1 && first_callback != 0 {
        tls_oep_override = rebuild_tls_callback_information(pe, &header)?;
    }

    Ok(State {
        header,
        xor_key,
        tls_as_oep: true,
        tls_oep_rva,
        tls_oep_override,
        code_index: None,
        code_section_data: None,
    })
}

/// Rebuilds the file TLS callback information and repairs the proper OEP
/// (v3.0 x64 `RebuildTlsCallbackInformation`).
fn rebuild_tls_callback_information(pe: &mut PeFile, header: &Var3xHeader) -> Result<u32> {
    // Ensure the modified main TLS callback is within the .bind section..
    let section = pe
        .get_owner_section(pe.get_rva_from_va(pe.tls_callbacks[0]))
        .ok_or_else(|| Error::Unpack("TLS callback outside of any section".into()))?;
    if !section.is_valid() || !section.name_str().eq_ignore_ascii_case(".bind") {
        return Err(Error::Unpack(
            "TLS callback is not within the .bind section".into(),
        ));
    }

    // Obtain the section that holds the TLS directory information..
    let tlsd = pe
        .tls_directory
        .ok_or_else(|| Error::Unpack("missing TLS directory".into()))?;
    let mut addr = pe.get_file_offset_from_rva(pe.get_rva_from_va(tlsd.address_of_callbacks));
    let tlsd_section = pe
        .get_owner_section(addr)
        .ok_or_else(|| Error::Unpack("TLS directory outside of any section".into()))?;
    if !tlsd_section.is_valid() {
        return Err(Error::Unpack("TLS directory section is invalid".into()));
    }

    addr -= tlsd_section.pointer_to_raw_data as u64;
    let tlsd_index = pe
        .section_index_of(tlsd_section)
        .ok_or_else(|| Error::Unpack("TLS directory section not found".into()))?;

    // Restore the true original TLS callback address (8 bytes for x64)..
    let callback = (pe.optional.image_base + header.original_entry_point as u64).to_le_bytes();
    let start = addr as usize;
    let end = start
        .checked_add(callback.len())
        .ok_or(Error::OutOfBounds)?;
    let section_data = pe
        .section_data
        .get_mut(tlsd_index)
        .ok_or(Error::OutOfBounds)?;
    if end > section_data.len() {
        return Err(Error::OutOfBounds);
    }
    section_data[start..end].copy_from_slice(&callback);

    // Find the original entry point function..
    let entry = pe.get_file_offset_from_rva(pe.optional.address_of_entry_point as u64);
    let take = 0x100usize;
    let data = pe
        .data
        .get(entry as usize..)
        .map(|d| &d[..d.len().min(take)])
        .ok_or(Error::OutOfBounds)?;

    // Find the XOR key from within the function..
    let res = crate::pattern::find_pattern(data, TLS_OEP_KEY_PATTERN)?;

    // Decrypt and recalculate the true OEP address..
    let intv = i32::from_le_bytes(
        data.get(res + 0x0B..res + 0x0F)
            .ok_or(Error::OutOfBounds)?
            .try_into()
            .map_err(|_| Error::OutOfBounds)?,
    );
    let key = ((header.xor_key as u64 as i64) ^ (intv as i64)) as u64;
    let off = pe
        .optional
        .image_base
        .wrapping_add(pe.optional.address_of_entry_point as u64)
        .wrapping_add(key);

    Ok((off - pe.optional.image_base) as u32)
}

/// Step 2 - Read, decode and process the payload data.
pub(crate) fn step2(
    pe: &PeFile,
    options: &Options,
    state: &mut State,
    logger: &dyn Logger,
) -> Result<()> {
    let payload_addr = pe.get_file_offset_from_rva(payload_base_rva(state, pe));
    let payload_size = (state.header.payload_size.wrapping_add(0x0F)) & 0xFFFF_FFF0;

    // Do nothing if there is no payload..
    if payload_size == 0 {
        return Ok(());
    }

    logger.log(Level::Debug, " --> File has payload data!");

    // Obtain and decode the payload..
    let mut payload = common::read_range(pe, payload_addr, payload_size as usize)?;
    state.xor_key = steam_xor(&mut payload, payload_size, state.xor_key);

    if options.dump_payload_to_disk {
        common::maybe_dump_payload(pe, options, &payload);
        logger.log(Level::Debug, " --> Saved payload to disk!");
    }

    Ok(())
}

/// Step 3 - Read, decode and dump the SteamDRMP.dll file.
pub(crate) fn step3(
    pe: &PeFile,
    options: &Options,
    state: &State,
    logger: &dyn Logger,
) -> Result<()> {
    // Ensure there is a dll to process..
    if state.header.drmp_dll_size == 0 {
        logger.log(
            Level::Debug,
            " --> File does not contain a SteamDRMP.dll file.",
        );
        return Ok(());
    }

    logger.log(Level::Debug, " --> File has SteamDRMP.dll file!");

    // Obtain the SteamDRMP.dll file address and data..
    let drmp_addr = pe.get_file_offset_from_rva(
        payload_base_rva(state, pe).wrapping_add(state.header.drmp_dll_offset as u64),
    );
    let mut drmp_data = common::read_range(pe, drmp_addr, state.header.drmp_dll_size as usize)?;

    // Decrypt the data (xtea decryption)..
    steam_drmp_pass1(
        &mut drmp_data,
        state.header.drmp_dll_size,
        &state.header.encryption_keys,
    );

    if options.dump_steam_drmp_to_disk {
        common::maybe_dump_drmp(pe, options, &drmp_data);
        logger.log(Level::Debug, " --> Saved SteamDRMP.dll to disk!");
    }

    Ok(())
}

/// Step 4 - Handle .bind section. Find the code section.
pub(crate) fn step4(
    pe: &mut PeFile,
    options: &Options,
    state: &mut State,
    variant: Variant,
    is64: bool,
    logger: &dyn Logger,
) -> Result<()> {
    // Remove the bind section if its not requested to be saved..
    if common::remove_bind_section(pe, options)? {
        logger.log(
            Level::Debug,
            " --> .bind section was removed from the file.",
        );
    } else {
        logger.log(Level::Debug, " --> .bind section was kept in the file.");
    }

    // Skip finding the code section if the file is not encrypted..
    if (state.header.flags & DRM_FLAG_NO_ENCRYPTION) != 0 {
        return Ok(());
    }

    // Find the code section..
    let code_section = pe
        .get_owner_section(state.header.code_section_virtual_address)
        .ok_or_else(|| Error::Unpack("code section not found".into()))?;
    if validates_code_section(variant, is64)
        && (code_section.pointer_to_raw_data == 0 || code_section.size_of_raw_data == 0)
    {
        return Err(Error::Unpack("code section is invalid".into()));
    }

    state.code_index = pe.section_index_of(code_section);
    Ok(())
}

/// Step 5 - Read, decrypt and process code section.
pub(crate) fn step5(
    pe: &mut PeFile,
    state: &mut State,
    variant: Variant,
    is64: bool,
    logger: &dyn Logger,
) -> Result<()> {
    // Skip decryption if the code section is not encrypted..
    if (state.header.flags & DRM_FLAG_NO_ENCRYPTION) != 0 {
        logger.log(Level::Debug, " --> Code section is not encrypted.");
        return Ok(());
    }

    let code_index = state
        .code_index
        .ok_or_else(|| Error::Unpack("code section not found".into()))?;
    let code_section = pe.sections[code_index];
    logger.log(
        Level::Debug,
        &format!(
            " --> {} linked as main code section.",
            code_section.name_str()
        ),
    );
    logger.log(
        Level::Debug,
        &format!(" --> {} section is encrypted.", code_section.name_str()),
    );

    // v3.1 x64 skips empty code sections entirely..
    if variant == Variant::V31 && is64 && code_section.size_of_raw_data == 0 {
        logger.log(
            Level::Debug,
            &format!(
                " --> {} section is empty; skipping decryption.",
                code_section.name_str()
            ),
        );
        state.code_section_data = Some(Vec::new());
        return Ok(());
    }

    // v3.1 x86 reads `CodeSectionRawSize` bytes; the rest use `SizeOfRawData`.
    let code_len = if variant == Variant::V31 && !is64 {
        state.header.code_section_raw_size as usize
    } else {
        code_section.size_of_raw_data as usize
    };

    // Obtain the code section data (stolen bytes + section data)..
    let section_offset = pe.get_file_offset_from_rva(code_section.virtual_address as u64);
    let mut merged = state.header.code_section_stolen_data.to_vec();
    merged.extend(common::read_range(pe, section_offset, code_len)?);

    // Create the AES decryption helper and decrypt the section..
    let mut aes = AesHelper::new(&state.header.aes_key, &state.header.aes_iv);
    aes.rebuild_iv(Some(&state.header.aes_iv));
    let data = aes.decrypt(&merged, AesMode::Cbc);

    // v3.1 x86 merges the decrypted data into the existing section data; the
    // other variants replace the whole section at save time.
    if variant == Variant::V31 && !is64 {
        let n = (state.header.code_section_raw_size as usize)
            .min(data.len())
            .min(pe.section_data[code_index].len());
        pe.section_data[code_index][..n].copy_from_slice(&data[..n]);
    } else {
        state.code_section_data = Some(data);
    }

    Ok(())
}

/// Step 6 - Rebuild and save the unpacked file.
pub(crate) fn step6(
    pe: &mut PeFile,
    options: &Options,
    state: &State,
    variant: Variant,
    is64: bool,
) -> Result<std::path::PathBuf> {
    let entry_point = if variant == Variant::V30 && is64 && state.header.has_tls_callback == 1 {
        state.tls_oep_override
    } else {
        state.header.original_entry_point
    };

    match (&state.code_section_data, state.code_index) {
        (Some(data), Some(index)) => {
            common::save_full(pe, options, entry_point, Some((index, data.as_slice())))
        }
        _ => common::save_full(pe, options, entry_point, None),
    }
}

/// The base RVA payload and SteamDRMP.dll offsets are relative to (paying
/// attention to the TLS fallback).
fn payload_base_rva(state: &State, pe: &PeFile) -> u64 {
    let bind_offset = state.header.bind_section_offset as u64;
    if state.tls_as_oep {
        state.tls_oep_rva.wrapping_sub(bind_offset)
    } else {
        (pe.optional.address_of_entry_point as u64).wrapping_sub(bind_offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_v30_header() -> Vec<u8> {
        let mut h = vec![0u8; 0xD0];
        h[0..4].copy_from_slice(&0x1122_3344u32.to_le_bytes()); // xor key
        h[4..8].copy_from_slice(&0xC0DEC0DEu32.to_le_bytes()); // signature
        h[8..16].copy_from_slice(&0x400000u64.to_le_bytes()); // image base
        h[16..20].copy_from_slice(&0x1000u32.to_le_bytes()); // AEP
        h[20..24].copy_from_slice(&0x1000u32.to_le_bytes()); // bind section offset
        h[28..32].copy_from_slice(&0x1234u32.to_le_bytes()); // OEP
        h[36..40].copy_from_slice(&0u32.to_le_bytes()); // payload size
        h[40..44].copy_from_slice(&0x400u32.to_le_bytes()); // drmp offset
        h[44..48].copy_from_slice(&0u32.to_le_bytes()); // drmp size
        h[52..56].copy_from_slice(&0u32.to_le_bytes()); // flags
        h[64..68].copy_from_slice(&0x1000u32.to_le_bytes()); // code section va
        h[72..104].fill(0x01); // aes key
        h[120..136].fill(0x02); // aes iv
        h[136..152].fill(0x03); // stolen
        h[152..168].fill(0x04); // encryption keys
        h
    }

    #[test]
    fn parses_v30_header() {
        let h = parse_header(&build_v30_header(), Variant::V30).unwrap();
        assert_eq!(h.signature, 0xC0DEC0DE);
        assert_eq!(h.code_section_virtual_address, 0x1000);
        assert_eq!(h.original_entry_point, 0x1234);
        assert_eq!(h.aes_key, [0x01; 32]);
        assert_eq!(h.encryption_keys, [0x0404_0404; 4]);
    }

    #[test]
    fn v30_header_sizes_are_known() {
        assert!(is_v30_size(0xB0));
        assert!(is_v30_size(0xD0));
        assert!(!is_v30_size(0xF0));
    }
}
