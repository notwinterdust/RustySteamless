//! SteamStub XOR and XTEA decryption helpers (`SteamStubHelpers` port).

/// XOR-decodes `data` starting with `key` (or the first dword when `key == 0`).
///
/// Returns the resulting XOR key so it can be chained into the next stage.
pub fn steam_xor(data: &mut [u8], size: u32, mut key: u32) -> u32 {
    let mut offset = 0usize;

    // Read the first key as the base XOR key if none was given.
    if key == 0 && size >= 4 {
        offset += 4;
        key = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    }

    let size = size as usize;
    let mut x = offset;
    while x + 4 <= size {
        let val = u32::from_le_bytes([data[x], data[x + 1], data[x + 2], data[x + 3]]);
        let enc = val ^ key;
        data[x..x + 4].copy_from_slice(&enc.to_le_bytes());
        key = val;
        x += 4;
    }

    key
}

const DELTA: u32 = 0x9e37_79b9;

/// Second pass of SteamDRMP.dll decryption (XTEA).
pub fn steam_drmp_pass2(res: &mut [u32; 2], keys: &[u32], mut v1: u32, mut v2: u32, n: u32) {
    let mut sum = DELTA.wrapping_mul(n);

    for _ in 0..n {
        v2 = v2.wrapping_sub(
            ((v1 << 4 ^ v1 >> 5).wrapping_add(v1))
                ^ (sum.wrapping_add(keys[(sum >> 11 & 3) as usize])),
        );
        sum = sum.wrapping_sub(DELTA);
        v1 = v1.wrapping_sub(
            ((v2 << 4 ^ v2 >> 5).wrapping_add(v2)) ^ (sum.wrapping_add(keys[(sum & 3) as usize])),
        );
    }

    res[0] = v1;
    res[1] = v2;
}

/// First pass of SteamDRMP.dll decryption (modded XTEA with XOR chaining).
pub fn steam_drmp_pass1(data: &mut [u8], size: u32, keys: &[u32]) {
    let mut v1: u32 = 0x5555_5555;
    let mut v2: u32 = 0x5555_5555;

    let size = size as usize;
    let mut x = 0usize;
    while x + 8 <= size {
        let d1 = u32::from_le_bytes([data[x], data[x + 1], data[x + 2], data[x + 3]]);
        let d2 = u32::from_le_bytes([data[x + 4], data[x + 5], data[x + 6], data[x + 7]]);

        let mut res = [0u32; 2];
        steam_drmp_pass2(&mut res, keys, d1, d2, 32);

        data[x..x + 4].copy_from_slice(&(res[0] ^ v1).to_le_bytes());
        data[x + 4..x + 8].copy_from_slice(&(res[1] ^ v2).to_le_bytes());

        v1 = d1;
        v2 = d2;
        x += 8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_roundtrip() {
        let mut data = [0x11u8, 0x22, 0x33, 0x44, 0xaa, 0xbb, 0xcc, 0xdd];
        let orig = data;
        // First call derives the key from the first dword and returns the last.
        let key = steam_xor(&mut data, 8, 0);
        assert_eq!(
            key,
            u32::from_le_bytes([orig[4], orig[5], orig[6], orig[7]])
        );
        // The first dword remains the plaintext key source for the second pass.
        assert_eq!(data[0..4], orig[0..4]);
        // Second pass restores the original stream.
        steam_xor(&mut data, 8, 0);
        assert_eq!(data, orig);
    }
}
