//! Little-endian binary helpers used when parsing and rebuilding PE files.

/// Bounds-checked little-endian read/write helpers over a byte slice.
pub trait Buf {
    fn rd_u8(&self, off: usize) -> Option<u8>;
    fn rd_i16(&self, off: usize) -> Option<i16>;
    fn rd_u16(&self, off: usize) -> Option<u16>;
    fn rd_u32(&self, off: usize) -> Option<u32>;
    fn rd_u64(&self, off: usize) -> Option<u64>;
    fn rd_bytes(&self, off: usize, len: usize) -> Option<&[u8]>;

    fn wr_u16(&mut self, off: usize, value: u16);
    fn wr_u32(&mut self, off: usize, value: u32);
    fn wr_u64(&mut self, off: usize, value: u64);
}

impl Buf for [u8] {
    fn rd_u8(&self, off: usize) -> Option<u8> {
        self.get(off).copied()
    }

    fn rd_i16(&self, off: usize) -> Option<i16> {
        let b = self.rd_bytes(off, 2)?;
        Some(i16::from_le_bytes([b[0], b[1]]))
    }

    fn rd_u16(&self, off: usize) -> Option<u16> {
        let b = self.rd_bytes(off, 2)?;
        Some(u16::from_le_bytes([b[0], b[1]]))
    }

    fn rd_u32(&self, off: usize) -> Option<u32> {
        let b = self.rd_bytes(off, 4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn rd_u64(&self, off: usize) -> Option<u64> {
        let b = self.rd_bytes(off, 8)?;
        Some(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn rd_bytes(&self, off: usize, len: usize) -> Option<&[u8]> {
        self.get(off..off.saturating_add(len))
    }

    fn wr_u16(&mut self, off: usize, value: u16) {
        if let Some(b) = self.get_mut(off..off + 2) {
            b.copy_from_slice(&value.to_le_bytes());
        }
    }

    fn wr_u32(&mut self, off: usize, value: u32) {
        if let Some(b) = self.get_mut(off..off + 4) {
            b.copy_from_slice(&value.to_le_bytes());
        }
    }

    fn wr_u64(&mut self, off: usize, value: u64) {
        if let Some(b) = self.get_mut(off..off + 8) {
            b.copy_from_slice(&value.to_le_bytes());
        }
    }
}

/// Aligns `value` up to the next multiple of `align`.
#[inline]
pub fn align_up(value: u64, align: u64) -> u64 {
    if align == 0 {
        return value;
    }
    value.div_ceil(align) * align
}

/// Reads a null-terminated section name buffer (8 bytes) into a string.
pub fn section_name(raw: &[u8]) -> String {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    let s = &raw[..end];
    String::from_utf8_lossy(s).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_le_values() {
        let data: Vec<u8> = vec![0x4d, 0x5a, 0x00, 0x01, 0xac, 0xde, 0x00, 0x00, 0xff];
        assert_eq!(data.rd_u16(0), Some(0x5a4d));
        assert_eq!(data.rd_u16(2), Some(0x0100));
        assert_eq!(data.rd_u32(0), Some(0x0100_5a4d));
        assert_eq!(data.rd_u32(4), Some(0x0000deac));
        assert_eq!(data.rd_u8(8), Some(0xff));
        assert_eq!(data.rd_u64(0), Some(0x0000_deac_0100_5a4d));
        assert_eq!(data.rd_u64(2), None);
    }

    #[test]
    fn writes_le_values_in_place() {
        let mut data = [0u8; 8];
        data.wr_u16(0, 0x5a4d);
        data.wr_u32(2, 0x12345678);
        data.wr_u64(0, 0);
        data.wr_u64(0, 0x0102030405060708);
        assert_eq!(data.rd_u64(0), Some(0x0102030405060708));
    }

    #[test]
    fn aligns_values() {
        assert_eq!(align_up(0x1000, 0x1000), 0x1000);
        assert_eq!(align_up(0x1001, 0x1000), 0x2000);
        assert_eq!(align_up(0xfff, 0x100), 0x1000);
        assert_eq!(align_up(5, 0), 5);
    }

    #[test]
    fn trims_section_name() {
        let raw = [b'.', b't', b'e', b'x', b't', 0, 0, 0];
        assert_eq!(section_name(&raw), ".text");
    }
}
