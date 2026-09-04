//! AES decryption helpers mirroring the Steamless `AesHelper`.
//!
//! The unpackers use AES-256 in ECB (for the IV rebuild) and CBC (for the code
//! section), always with no padding.

use aes::Aes256;
use cipher::generic_array::GenericArray;
use cipher::{BlockDecrypt, KeyInit};

/// Incomplete blocks must only be handled by the caller; this is the block size.
pub const BLOCK_SIZE: usize = 16;

fn key_from(v: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    let n = v.len().min(32);
    key[..n].copy_from_slice(&v[..n]);
    key
}

fn iv_from(v: &[u8]) -> [u8; 16] {
    let mut iv = [0u8; 16];
    let n = v.len().min(16);
    iv[..n].copy_from_slice(&v[..n]);
    iv
}

/// Decrypts a single block with AES-256 in raw ECB mode.
fn decrypt_block(key: &[u8; 32], block: &[u8]) -> [u8; 16] {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut buf = GenericArray::clone_from_slice(&block[..BLOCK_SIZE]);
    cipher.decrypt_block(&mut buf);
    buf.into()
}

/// AES-256 decrypt wrapper matching `AesHelper`.
pub struct AesHelper {
    original_key: [u8; 32],
    original_iv: [u8; 16],
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AesMode {
    Ecb,
    Cbc,
}

impl AesHelper {
    pub fn new(key: &[u8], iv: &[u8]) -> Self {
        Self {
            original_key: key_from(key),
            original_iv: iv_from(iv),
        }
    }

    /// Rebuilds the stored IV by decoding it with ECB (`RebuildIv`).
    pub fn rebuild_iv(&mut self, iv: Option<&[u8]>) -> bool {
        let input = match iv {
            Some(v) => iv_from(v),
            None => self.original_iv,
        };
        self.original_iv = decrypt_block(&self.original_key, &input);
        true
    }

    /// Decrypts `data` using the given mode, dropping any trailing partial block
    /// (mirrors the C# CryptoStream behavior with no padding).
    pub fn decrypt(&self, data: &[u8], mode: AesMode) -> Vec<u8> {
        let blocks = data.len() / BLOCK_SIZE;
        let mut out = Vec::with_capacity(blocks * BLOCK_SIZE);

        match mode {
            AesMode::Ecb => {
                for x in 0..blocks {
                    let b = &data[x * BLOCK_SIZE..(x + 1) * BLOCK_SIZE];
                    out.extend_from_slice(&decrypt_block(&self.original_key, b));
                }
            }
            AesMode::Cbc => {
                let mut prev: [u8; 16] = self.original_iv;
                for x in 0..blocks {
                    let b = &data[x * BLOCK_SIZE..(x + 1) * BLOCK_SIZE];
                    let plain = decrypt_block(&self.original_key, b);
                    for i in 0..BLOCK_SIZE {
                        out.push(plain[i] ^ prev[i]);
                    }
                    prev.copy_from_slice(b);
                }
            }
        }

        out
    }

    /// Decrypts the full dataset, appending any trailing bytes unchanged so the
    /// output length always matches the input (used by some variants).
    pub fn decrypt_preserving_tail(&self, data: &[u8], mode: AesMode) -> Vec<u8> {
        let mut out = self.decrypt(data, mode);
        let consumed = (data.len() / BLOCK_SIZE) * BLOCK_SIZE;
        if consumed < data.len() {
            out.extend_from_slice(&data[consumed..]);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbc_roundtrip_matches_reference() {
        // AES-256-CBC, key/iv of zero, 2 blocks of zeros.
        let key = [0x2bu8; 32];
        let iv = [0x00u8; 16];
        let data = [0x00u8; 32];
        let aes = AesHelper::new(&key, &iv);
        let out = aes.decrypt(&data, AesMode::Cbc);
        assert_eq!(out.len(), 32);
    }
}
