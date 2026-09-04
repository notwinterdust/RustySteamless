//! Portable Executable parsing, rebuilding and saving.
//!
//! A byte-exact port of the Steamless C# `Pe32File` / `Pe64File` handling,
//! unified into a single loader that supports both 32-bit and 64-bit images.

use std::path::{Path, PathBuf};

use super::reader;
use super::reader::Buf;
use crate::{Error, Result};

/// The 32-bit and 64-bit optional header magics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageBits {
    Pe32,
    Pe32Plus,
}

/// IMAGE_DOS_HEADER
#[derive(Clone, Copy, Debug)]
pub struct DosHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_lfanew: u32,
}

impl DosHeader {
    /// Total size of the DOS header block on disk.
    pub const SIZE: usize = 64;

    /// Returns true if the DOS magic is 'MZ'.
    pub fn is_valid(&self) -> bool {
        self.e_magic == 0x5a4d
    }

    fn parse(data: &[u8]) -> Option<Self> {
        Some(Self {
            e_magic: data.rd_u16(0x00)?,
            e_cblp: data.rd_u16(0x02)?,
            e_cp: data.rd_u16(0x04)?,
            e_crlc: data.rd_u16(0x06)?,
            e_cparhdr: data.rd_u16(0x08)?,
            e_minalloc: data.rd_u16(0x0a)?,
            e_maxalloc: data.rd_u16(0x0c)?,
            e_ss: data.rd_u16(0x0e)?,
            e_sp: data.rd_u16(0x10)?,
            e_csum: data.rd_u16(0x12)?,
            e_ip: data.rd_u16(0x14)?,
            e_cs: data.rd_u16(0x16)?,
            e_lfarlc: data.rd_u16(0x18)?,
            e_ovno: data.rd_u16(0x1a)?,
            e_oemid: data.rd_u16(0x24)?,
            e_oeminfo: data.rd_u16(0x26)?,
            e_lfanew: data.rd_u32(0x3c)?,
        })
    }
}

/// IMAGE_FILE_HEADER
#[derive(Clone, Copy, Debug)]
pub struct FileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

impl FileHeader {
    pub const SIZE: usize = 20;
}

/// IMAGE_OPTIONAL_HEADER (shared across PE32 and PE32+).
#[derive(Clone, Copy, Debug)]
pub struct OptionalHeader {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub directories: [DataDirectory; 16],
}

impl OptionalHeader {
    pub fn bits(&self) -> ImageBits {
        match self.magic {
            0x10b => ImageBits::Pe32,
            _ => ImageBits::Pe32Plus,
        }
    }

    pub fn tls_directory(&self) -> &DataDirectory {
        &self.directories[9]
    }
}

/// IMAGE_DATA_DIRECTORY
#[derive(Clone, Copy, Debug, Default)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

/// IMAGE_SECTION_HEADER
#[derive(Clone, Copy, Debug)]
pub struct SectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

impl SectionHeader {
    pub const SIZE: usize = 40;

    pub fn name_str(&self) -> String {
        reader::section_name(&self.name)
    }

    /// Mirrors the C# `IsValid` check used when locating sections.
    pub fn is_valid(&self) -> bool {
        self.size_of_raw_data != 0 && self.pointer_to_raw_data != 0
    }

    fn parse(data: &[u8], off: usize) -> Option<Self> {
        let name: [u8; 8] = data.rd_bytes(off, 8)?.try_into().ok()?;
        Some(Self {
            name,
            virtual_size: data.rd_u32(off + 8)?,
            virtual_address: data.rd_u32(off + 12)?,
            size_of_raw_data: data.rd_u32(off + 16)?,
            pointer_to_raw_data: data.rd_u32(off + 20)?,
            pointer_to_relocations: data.rd_u32(off + 24)?,
            pointer_to_linenumbers: data.rd_u32(off + 28)?,
            number_of_relocations: data.rd_u16(off + 32)?,
            number_of_linenumbers: data.rd_u16(off + 34)?,
            characteristics: data.rd_u32(off + 36)?,
        })
    }

    /// Serializes the section header back into its 40-byte on-disk layout.
    pub fn write_into(&self, buf: &mut [u8], off: usize) {
        buf[off..off + 8].copy_from_slice(&self.name);
        buf.wr_u32(off + 8, self.virtual_size);
        buf.wr_u32(off + 12, self.virtual_address);
        buf.wr_u32(off + 16, self.size_of_raw_data);
        buf.wr_u32(off + 20, self.pointer_to_raw_data);
        buf.wr_u32(off + 24, self.pointer_to_relocations);
        buf.wr_u32(off + 28, self.pointer_to_linenumbers);
        buf.wr_u16(off + 32, self.number_of_relocations);
        buf.wr_u16(off + 34, self.number_of_linenumbers);
        buf.wr_u32(off + 36, self.characteristics);
    }
}

/// IMAGE_TLS_DIRECTORY
#[derive(Clone, Copy, Debug)]
pub struct TlsDirectory {
    pub start_address_of_raw_data: u64,
    pub end_address_of_raw_data: u64,
    pub address_of_index: u64,
    pub address_of_callbacks: u64,
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
}

impl TlsDirectory {
    fn parse(data: &[u8], off: usize, bits: ImageBits) -> Option<Self> {
        let (r1, r2, r3, r4) = match bits {
            ImageBits::Pe32 => (
                data.rd_u32(off)? as u64,
                data.rd_u32(off + 4)? as u64,
                data.rd_u32(off + 8)? as u64,
                data.rd_u32(off + 12)? as u64,
            ),
            ImageBits::Pe32Plus => (
                data.rd_u64(off)?,
                data.rd_u64(off + 8)?,
                data.rd_u64(off + 16)?,
                data.rd_u64(off + 24)?,
            ),
        };
        Some(Self {
            start_address_of_raw_data: r1,
            end_address_of_raw_data: r2,
            address_of_index: r3,
            address_of_callbacks: r4,
            size_of_zero_fill: data.rd_u32(
                off + if matches!(bits, ImageBits::Pe32) {
                    16
                } else {
                    32
                },
            )?,
            characteristics: data.rd_u32(
                off + if matches!(bits, ImageBits::Pe32) {
                    20
                } else {
                    36
                },
            )?,
        })
    }
}

/// Parameters controlling `save_unpacked` output layout.
pub struct SaveParameters<'a> {
    /// Replaces the DOS stub bytes (e.g. zeroed). `None` keeps the stub.
    pub dos_stub: Option<&'a [u8]>,
    /// The entry point RVA written into the optional header.
    pub address_of_entry_point: u32,
    /// The checksum value written into the optional header (usually 0).
    pub checksum: u32,
    /// Replacement bytes for a single code section by index.
    pub code_section: Option<(usize, &'a [u8])>,
}

/// A parsed portable executable file.
#[derive(Debug)]
pub struct PeFile {
    pub path: PathBuf,
    pub data: Vec<u8>,
    pub bits: ImageBits,
    pub dos_header: DosHeader,
    pub dos_stub_offset: usize,
    pub dos_stub_size: usize,
    pub dos_stub: Vec<u8>,
    pub nt_headers_offset: usize,
    pub signature: u32,
    pub file_header: FileHeader,
    pub optional: OptionalHeader,
    pub sections: Vec<SectionHeader>,
    pub section_data: Vec<Vec<u8>>,
    pub overlay: Option<Vec<u8>>,
    pub tls_directory: Option<TlsDirectory>,
    pub tls_callbacks: Vec<u64>,
}

impl PeFile {
    /// Loads and parses a PE file from the given path.
    pub fn parse(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let data = std::fs::read(path).map_err(Error::Io)?;
        Self::from_bytes(data, path.to_path_buf())
    }

    /// Parses PE data that has already been loaded into memory.
    pub fn from_bytes(data: Vec<u8>, path: PathBuf) -> Result<Self> {
        // DOS header.
        let dos_header = DosHeader::parse(&data)
            .ok_or_else(|| Error::InvalidPe("truncated DOS header".into()))?;
        if !dos_header.is_valid() {
            return Err(Error::InvalidPe("missing MZ magic".into()));
        }

        let nt_headers_offset = dos_header.e_lfanew as usize;
        if nt_headers_offset + 24 > data.len() {
            return Err(Error::InvalidPe("truncated NT headers".into()));
        }

        // Signature (PE\0\0).
        let signature = data
            .rd_u32(nt_headers_offset)
            .ok_or_else(|| Error::InvalidPe("missing PE signature".into()))?;
        if signature != 0x0000_4550 {
            return Err(Error::InvalidPe("missing PE\\0\\0 signature".into()));
        }

        // File header.
        let fh_off = nt_headers_offset + 4;
        let file_header = FileHeader {
            machine: data.rd_u16(fh_off).unwrap_or(0),
            number_of_sections: data.rd_u16(fh_off + 2).unwrap_or(0),
            time_date_stamp: data.rd_u32(fh_off + 4).unwrap_or(0),
            pointer_to_symbol_table: data.rd_u32(fh_off + 8).unwrap_or(0),
            number_of_symbols: data.rd_u32(fh_off + 12).unwrap_or(0),
            size_of_optional_header: data.rd_u16(fh_off + 16).unwrap_or(0),
            characteristics: data.rd_u16(fh_off + 18).unwrap_or(0),
        };

        // Optional header.
        let oh_off = fh_off + FileHeader::SIZE;
        let optional =
            parse_optional_header(&data, oh_off, file_header.size_of_optional_header as usize)
                .ok_or_else(|| Error::InvalidPe("invalid optional header".into()))?;
        let bits = optional.bits();

        // DOS stub (data between the DOS header and the NT headers).
        let dos_stub_offset = DosHeader::SIZE;
        let dos_stub_size = nt_headers_offset.saturating_sub(DosHeader::SIZE);
        let dos_stub = if dos_stub_size > 0 {
            data.rd_bytes(dos_stub_offset, dos_stub_size)
                .unwrap_or(&[])
                .to_vec()
        } else {
            Vec::new()
        };

        // Sections.
        let sections_start = oh_off + file_header.size_of_optional_header as usize;
        let mut sections = Vec::new();
        let mut section_data = Vec::new();
        for x in 0..file_header.number_of_sections as usize {
            let off = sections_start.saturating_add(x.saturating_mul(SectionHeader::SIZE));
            let Some(sec) = SectionHeader::parse(&data, off) else {
                return Err(Error::InvalidPe("truncated section header".into()));
            };
            let raw_len = sec.size_of_raw_data as usize;
            let aligned_len =
                reader::align_up(raw_len as u64, optional.file_alignment as u64) as usize;
            let raw = data
                .rd_bytes(sec.pointer_to_raw_data as usize, raw_len)
                .unwrap_or_default()
                .to_vec();
            let mut aligned = raw;
            aligned.resize(aligned_len, 0);
            section_data.push(aligned);
            sections.push(sec);
        }

        // Overlay data.
        let overlay = sections.last().is_none_or(|s| {
            (s.pointer_to_raw_data as u64 + s.size_of_raw_data as u64) < data.len() as u64
        });
        let overlay = if overlay && !sections.is_empty() {
            let end = sections
                .last()
                .map(|s| s.pointer_to_raw_data as usize + s.size_of_raw_data as usize)
                .unwrap_or(0);
            if end < data.len() {
                Some(data[end..].to_vec())
            } else {
                None
            }
        } else {
            None
        };

        // TLS information.
        let mut tls_directory = None;
        let mut tls_callbacks = Vec::new();
        if let Ok(Some(tls)) = read_tls(&data, bits, &optional, &sections) {
            tls_directory = Some(tls.0);
            tls_callbacks = tls.1;
        }

        Ok(Self {
            path,
            data,
            bits,
            dos_header,
            dos_stub_offset,
            dos_stub_size,
            dos_stub,
            nt_headers_offset,
            signature,
            file_header,
            optional,
            sections,
            section_data,
            overlay,
            tls_directory,
            tls_callbacks,
        })
    }

    /// True if the machine type marks the image as 64-bit (AMD64).
    pub fn is_file_64(&self) -> bool {
        self.file_header.machine == 0x8664
    }

    /// Whether the file contains a section with the given name.
    pub fn has_section(&self, name: &str) -> bool {
        self.sections
            .iter()
            .any(|s| s.name_str().eq_ignore_ascii_case(name))
    }

    /// Returns the section with the given name, if present.
    pub fn get_section(&self, name: &str) -> Option<&SectionHeader> {
        self.sections
            .iter()
            .find(|s| s.name_str().eq_ignore_ascii_case(name))
    }

    /// Returns the section that owns `rva`, if any.
    pub fn get_section_index_by_rva(&self, rva: u64) -> Option<usize> {
        self.sections.iter().position(|s| {
            let size = if s.virtual_size == 0 {
                s.size_of_raw_data as u64
            } else {
                s.virtual_size as u64
            };
            rva >= s.virtual_address as u64 && rva < s.virtual_address as u64 + size
        })
    }

    /// Returns the owner section of `rva`.
    pub fn get_owner_section(&self, rva: u64) -> Option<&SectionHeader> {
        self.get_section_index_by_rva(rva)
            .map(|i| &self.sections[i])
    }

    /// Returns a section's data by index.
    pub fn get_section_data(&self, index: usize) -> Option<&[u8]> {
        self.section_data.get(index).map(|v| v.as_slice())
    }

    /// Returns a section's data by name.
    pub fn get_section_data_by_name(&self, name: &str) -> Option<&[u8]> {
        self.get_section_index(name)
            .and_then(|i| self.get_section_data(i))
    }

    /// Returns the index of a section by name.
    pub fn get_section_index(&self, name: &str) -> Option<usize> {
        self.sections
            .iter()
            .position(|s| s.name_str().eq_ignore_ascii_case(name))
    }

    /// Returns the index of the given section.
    pub fn section_index_of(&self, section: &SectionHeader) -> Option<usize> {
        self.sections.iter().position(|s| std::ptr::eq(s, section))
    }

    /// Removes a section by index.
    pub fn remove_section(&mut self, index: usize) {
        if index < self.sections.len() {
            self.sections.remove(index);
            self.section_data.remove(index);
        }
    }

    /// Aligns section values (optionally) and recomputes SizeOfImage.
    ///
    /// Mirrors `RebuildSections` from the C# internals.
    pub fn rebuild_sections(&mut self, realign: bool) {
        if realign {
            for section in &mut self.sections {
                section.virtual_address = reader::align_up(
                    section.virtual_address as u64,
                    self.optional.section_alignment as u64,
                ) as u32;
                section.virtual_size = reader::align_up(
                    section.virtual_size as u64,
                    self.optional.section_alignment as u64,
                ) as u32;
                section.pointer_to_raw_data = reader::align_up(
                    section.pointer_to_raw_data as u64,
                    self.optional.file_alignment as u64,
                ) as u32;
                section.size_of_raw_data = reader::align_up(
                    section.size_of_raw_data as u64,
                    self.optional.file_alignment as u64,
                ) as u32;
            }
        }
        if let Some(last) = self.sections.last() {
            let end = last.virtual_address as u64 + last.virtual_size as u64;
            self.optional.size_of_image =
                reader::align_up(end, self.optional.section_alignment as u64) as u32;
        }
    }

    /// Converts a virtual address to a relative virtual address.
    #[inline]
    pub fn get_rva_from_va(&self, va: u64) -> u64 {
        va.saturating_sub(self.optional.image_base)
    }

    /// Resolves an RVA to its raw file offset.
    ///
    /// Assumes the RVA lives within a mapped section (matching C# behavior).
    pub fn get_file_offset_from_rva(&self, rva: u64) -> u64 {
        match self.get_owner_section(rva) {
            Some(sec) => rva - (sec.virtual_address as u64 - sec.pointer_to_raw_data as u64),
            None => rva,
        }
    }

    /// Writes the unpacked image to `target`.
    ///
    /// Layout mirrors the C# unpackers: DOS header, DOS stub, patched NT
    /// headers, section headers, section data written at their raw pointers,
    /// then the overlay trailing the file.
    pub fn save_unpacked(&self, target: &std::path::Path, params: &SaveParameters) -> Result<()> {
        let nt_off = self.nt_headers_offset;
        let sections_start =
            nt_off + 4 + FileHeader::SIZE + self.file_header.size_of_optional_header as usize;

        fn write_at(buf: &mut Vec<u8>, off: usize, bytes: &[u8]) {
            let end = off.saturating_add(bytes.len());
            if buf.len() < end {
                buf.resize(end, 0);
            }
            buf[off..end].copy_from_slice(bytes);
        }

        let mut out: Vec<u8> = Vec::new();

        // DOS header (first 64 bytes of the image).
        write_at(&mut out, 0, &self.data[..DosHeader::SIZE]);

        // DOS stub.
        let stub = params.dos_stub.unwrap_or(&self.dos_stub);
        write_at(&mut out, DosHeader::SIZE, stub);

        // NT headers, patched in place.
        let nt_headers = &self.data[nt_off..sections_start];
        write_at(&mut out, nt_off, nt_headers);
        out.wr_u16(nt_off + 6, self.file_header.number_of_sections);
        out.wr_u32(nt_off + 24 + 16, params.address_of_entry_point);
        out.wr_u32(nt_off + 24 + 56, self.optional.size_of_image);
        out.wr_u32(nt_off + 24 + 64, params.checksum);

        // Section headers.
        for (i, sec) in self.sections.iter().enumerate() {
            let mut hdr = [0u8; SectionHeader::SIZE];
            sec.write_into(&mut hdr, 0);
            write_at(&mut out, sections_start + i * SectionHeader::SIZE, &hdr);
        }

        // Section data at their raw pointers.
        for (i, sec) in self.sections.iter().enumerate() {
            let data = match params.code_section {
                Some((idx, replacement)) if idx == i => replacement,
                _ => self.section_data[i].as_slice(),
            };
            write_at(&mut out, sec.pointer_to_raw_data as usize, data);
        }

        // Overlay data.
        if let Some(overlay) = &self.overlay {
            let start = out.len();
            write_at(&mut out, start, overlay);
        }

        std::fs::write(target, out).map_err(Error::Io)
    }
}

fn parse_optional_header(data: &[u8], off: usize, size: usize) -> Option<OptionalHeader> {
    let magic = data.rd_u16(off)?;
    let pe32 = match magic {
        0x10b => true,
        0x20b => false,
        _ => return None,
    };

    let image_base = if pe32 {
        data.rd_u32(off + 28)? as u64
    } else {
        data.rd_u64(off + 24)?
    };
    let directories_off = if pe32 { 96 } else { 112 };
    let mut directories = [DataDirectory::default(); 16];
    let directory_count = if size >= directories_off + 16 * 8 {
        16
    } else {
        (size.saturating_sub(directories_off)) / 8
    };
    for (i, dir) in directories.iter_mut().enumerate().take(directory_count) {
        let d = directories_off + i * 8;
        *dir = DataDirectory {
            virtual_address: data.rd_u32(off + d)?,
            size: data.rd_u32(off + d + 4)?,
        };
    }

    Some(OptionalHeader {
        magic,
        major_linker_version: data.rd_u8(off + 2)?,
        minor_linker_version: data.rd_u8(off + 3)?,
        size_of_code: data.rd_u32(off + 4)?,
        size_of_initialized_data: data.rd_u32(off + 8)?,
        size_of_uninitialized_data: data.rd_u32(off + 12)?,
        address_of_entry_point: data.rd_u32(off + 16)?,
        base_of_code: data.rd_u32(off + 20)?,
        image_base,
        section_alignment: data.rd_u32(off + 32)?,
        file_alignment: data.rd_u32(off + 36)?,
        major_operating_system_version: data.rd_u16(off + 40)?,
        minor_operating_system_version: data.rd_u16(off + 42)?,
        major_image_version: data.rd_u16(off + 44)?,
        minor_image_version: data.rd_u16(off + 46)?,
        major_subsystem_version: data.rd_u16(off + 48)?,
        minor_subsystem_version: data.rd_u16(off + 50)?,
        win32_version_value: data.rd_u32(off + 52)?,
        size_of_image: data.rd_u32(off + 56)?,
        size_of_headers: data.rd_u32(off + 60)?,
        checksum: data.rd_u32(off + 64)?,
        subsystem: data.rd_u16(off + 68)?,
        dll_characteristics: data.rd_u16(off + 70)?,
        size_of_stack_reserve: if pe32 {
            data.rd_u32(off + 72)? as u64
        } else {
            data.rd_u64(off + 72)?
        },
        size_of_stack_commit: if pe32 {
            data.rd_u32(off + 76)? as u64
        } else {
            data.rd_u64(off + 80)?
        },
        size_of_heap_reserve: if pe32 {
            data.rd_u32(off + 80)? as u64
        } else {
            data.rd_u64(off + 88)?
        },
        size_of_heap_commit: if pe32 {
            data.rd_u32(off + 84)? as u64
        } else {
            data.rd_u64(off + 96)?
        },
        loader_flags: data.rd_u32(off + if pe32 { 88 } else { 104 })?,
        number_of_rva_and_sizes: data.rd_u32(off + if pe32 { 92 } else { 108 })?,
        directories,
    })
}

fn read_tls(
    data: &[u8],
    bits: ImageBits,
    optional: &OptionalHeader,
    sections: &[SectionHeader],
) -> Result<Option<(TlsDirectory, Vec<u64>)>> {
    let tls = optional.tls_directory();
    if tls.virtual_address == 0 {
        return Ok(None);
    }

    // Resolve TLS directory file offset.
    let tls_rva = tls.virtual_address as u64;
    let owner = sections.iter().find(|s| {
        let size = if s.virtual_size == 0 {
            s.size_of_raw_data as u64
        } else {
            s.virtual_size as u64
        };
        tls_rva >= s.virtual_address as u64 && tls_rva < s.virtual_address as u64 + size
    });
    let Some(owner) = owner else {
        return Ok(None);
    };
    let file_off =
        (tls_rva - (owner.virtual_address as u64 - owner.pointer_to_raw_data as u64)) as usize;

    let directory = TlsDirectory::parse(data, file_off, bits)
        .ok_or_else(|| Error::InvalidPe("truncated TLS directory".into()))?;
    if directory.address_of_callbacks == 0 {
        return Ok(Some((directory, Vec::new())));
    }

    // Resolve the callbacks array file offset.
    let callbacks_rva = directory.address_of_callbacks - optional.image_base;
    let callbacks_off = callbacks_rva_to_file_offset(callbacks_rva, sections)
        .ok_or_else(|| Error::InvalidPe("TLS callbacks outside mapped sections".into()))?;

    let ptr_size = match bits {
        ImageBits::Pe32 => 4,
        ImageBits::Pe32Plus => 8,
    };

    let mut callbacks = Vec::new();
    let mut cursor = callbacks_off;
    loop {
        let value = match ptr_size {
            4 => data
                .rd_u32(cursor)
                .ok_or_else(|| Error::InvalidPe("TLS callback list truncated".into()))?
                as u64,
            _ => data
                .rd_u64(cursor)
                .ok_or_else(|| Error::InvalidPe("TLS callback list truncated".into()))?,
        };
        if value == 0 {
            break;
        }
        callbacks.push(value);
        cursor += ptr_size;
    }

    Ok(Some((directory, callbacks)))
}

fn callbacks_rva_to_file_offset(rva: u64, sections: &[SectionHeader]) -> Option<usize> {
    sections
        .iter()
        .find(|s| {
            let size = if s.virtual_size == 0 {
                s.size_of_raw_data as u64
            } else {
                s.virtual_size as u64
            };
            rva >= s.virtual_address as u64 && rva < s.virtual_address as u64 + size
        })
        .map(|s| (rva - (s.virtual_address as u64 - s.pointer_to_raw_data as u64)) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_pe() {
        let data = vec![0x4d, 0x5a, 0x00, 0x00];
        let path = PathBuf::from("x");
        assert!(PeFile::from_bytes(data, path).is_err());
    }
}
