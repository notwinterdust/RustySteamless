//! Pure-Rust PE checksum, replacing the Windows `imagehlp!MapFileAndCheckSum` call.
//!
//! The checksum is the sum of all 16-bit words of the image (with the embedded
//! checksum field treated as zeroed) plus the file size, folded through the
//! standard carry-reduce step.

/// The value of a 16-bit word folded into `sum` with carry propagation.
#[inline]
fn fold_word(sum: u32, word: u32) -> u32 {
    let sum = sum + word;
    (sum & 0xffff) + (sum >> 16)
}

/// Computes the PE checksum for the given image data.
///
/// `checksum_offset` is the file offset of the 4-byte `CheckSum` field in the
/// optional header; those bytes are ignored during summation.
pub fn compute_checksum(data: &[u8], checksum_offset: usize) -> u32 {
    let field_end = checksum_offset.saturating_add(4);
    let mut sum: u32 = 0;

    let mut w = 0usize;
    while w + 1 < data.len() {
        let mut a = data[w];
        let mut b = data[w + 1];
        if w >= checksum_offset && w < field_end {
            a = 0;
        }
        if w + 1 >= checksum_offset && w + 1 < field_end {
            b = 0;
        }
        let word = (a as u32) | ((b as u32) << 8);
        sum = fold_word(sum, word);
        w += 2;
    }

    // Trailing lone byte is treated as a word with a zero high byte.
    if data.len() % 2 != 0 {
        let mut byte = data[w];
        if w >= checksum_offset && w < field_end {
            byte = 0;
        }
        sum = fold_word(sum, byte as u32);
    }

    // Add the file size, little-endian, then reduce.
    let len = data.len() as u32;
    sum = fold_word(sum, len & 0xffff);
    sum = fold_word(sum, (len >> 16) & 0xffff);

    // Final carry reduction to 16 bits.
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    sum & 0xffff
}

/// Updates the checksum of a PE image held in memory, in place.
///
/// Returns the computed checksum value.
pub fn update_checksum_in_buffer(data: &mut [u8]) -> Option<u32> {
    let nt_headers_offset = checksum_argument_offset(data)?;
    let checksum_offset = nt_headers_offset + 24 + 64;
    let sum = compute_checksum(data, checksum_offset);
    data[checksum_offset] = (sum & 0xff) as u8;
    data[checksum_offset + 1] = ((sum >> 8) & 0xff) as u8;
    data[checksum_offset + 2] = ((sum >> 16) & 0xff) as u8;
    data[checksum_offset + 3] = ((sum >> 24) & 0xff) as u8;
    Some(sum)
}

/// Updates the checksum of a PE file on disk via a temp buffer, in place on the file.
pub fn update_checksum(path: &std::path::Path) -> std::io::Result<u32> {
    let mut data = std::fs::read(path)?;
    let sum = update_checksum_in_buffer(&mut data)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "not a PE image"))?;
    std::fs::write(path, data)?;
    Ok(sum)
}

/// Reads the `e_lfanew` field from a DOS header.
fn checksum_argument_offset(data: &[u8]) -> Option<usize> {
    if data.len() < 0x40 || data[0] != b'M' || data[1] != b'Z' {
        return None;
    }
    let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    if data.get(e_lfanew..e_lfanew + 2)?[0..2] == [0x50, 0x45] {
        Some(e_lfanew)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal valid PE image used to exercise the checksum routine.
    #[test]
    fn compute_folds_carries() {
        // Words: 0xbbaa, 0xddcc; checksum field lives at offset 4 (words at 4/6 zeroed).
        let data = vec![0xaau8, 0xbb, 0xcc, 0xdd, 0x00, 0x00, 0x00, 0x00];
        let sum = compute_checksum(&data, 4);
        // fold(0xbbaa + 0xddcc = 0x19976) = 0x9977, then + length (8) = 0x997f.
        assert_eq!(sum, 0x997f);
    }

    #[test]
    fn rejects_truncated_dos_header() {
        assert!(checksum_argument_offset(&[0u8; 8]).is_none());
    }
}
