//! Byte pattern scanning with `??` wildcards (`PeHelpers.FindPattern` port).

use crate::{Error, Result};

/// A parsed search pattern with its wildcard mask.
struct Pattern {
    bytes: Vec<u8>,
    mask: Vec<bool>,
}

impl Pattern {
    fn parse(input: &str) -> Result<Self> {
        let trimmed: String = input.chars().filter(|c| !c.is_whitespace()).collect();
        if trimmed.len() % 2 != 0 {
            return Err(Error::Unpack("malformed pattern length".into()));
        }

        let mut bytes = Vec::with_capacity(trimmed.len() / 2);
        let mut mask = Vec::with_capacity(trimmed.len() / 2);

        let chars: Vec<char> = trimmed.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            let hi = chars[i];
            let lo = chars[i + 1];
            i += 2;

            let wildcard = hi == '?' || lo == '?';
            let byte = if wildcard {
                0
            } else {
                let hex = format!("{hi}{lo}");
                u8::from_str_radix(&hex, 16)
                    .map_err(|_| Error::Unpack(format!("invalid pattern byte '{hex}'")))?
            };
            bytes.push(byte);
            mask.push(!wildcard);
        }

        Ok(Self { bytes, mask })
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }
}

/// Scans `data` for `pattern`, returning the first matching offset.
///
/// Patterns use two-hex-digit bytes separated by spaces; `??` is a wildcard.
pub fn find_pattern(data: &[u8], pattern: &str) -> Result<usize> {
    let pat = Pattern::parse(pattern)?;
    if pat.len() == 0 || data.len() < pat.len() {
        return Err(Error::PatternNotFound);
    }

    'outer: for x in 0..=(data.len() - pat.len()) {
        for (y, &byte) in pat.bytes.iter().enumerate() {
            if pat.mask[y] && data[x + y] != byte {
                continue 'outer;
            }
        }
        return Ok(x);
    }

    Err(Error::PatternNotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_exact_pattern() {
        let data = [0x00u8, 0x01, 0x60, 0x81, 0xaa, 0xbb, 0xcc];
        let off = find_pattern(&data, "60 81 AA BB CC").unwrap();
        assert_eq!(off, 2);
    }

    #[test]
    fn finds_wildcard_pattern() {
        let data = [0x00u8, 0x01, 0x60, 0x81, 0xaa, 0xbb, 0xcc];
        let off = find_pattern(&data, "60 ?? AA BB ??");
        assert!(matches!(off, Ok(2)));
    }

    #[test]
    fn missing_pattern_is_error() {
        let data = [0x00u8; 8];
        assert!(find_pattern(&data, "DE AD BE EF").is_err());
    }

    #[test]
    fn empty_pattern_is_error() {
        assert!(find_pattern(&[0u8; 4], "").is_err());
    }
}
