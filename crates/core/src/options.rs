//! Unpacker options (`SteamlessOptions` port).

use serde::{Deserialize, Serialize};

/// Options controlling how a file is unpacked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Options {
    /// Print debug log messages.
    pub verbose_output: bool,
    /// Keep the `.bind` section in the unpacked file.
    pub keep_bind_section: bool,
    /// Dump the decoded payload to disk (<file>.payload).
    pub dump_payload_to_disk: bool,
    /// Dump the decrypted SteamDRMP.dll to disk.
    pub dump_steam_drmp_to_disk: bool,
    /// Enable experimental features.
    pub use_experimental_features: bool,
    /// Re-align unpacked sections (false means do not realign).
    pub realign_sections: bool,
    /// Zero out the DOS stub data in the output.
    pub zero_dos_stub_data: bool,
    /// Recalculate the unpacked file checksum after saving.
    pub recalculate_file_checksum: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            verbose_output: true,
            keep_bind_section: false,
            dump_payload_to_disk: false,
            dump_steam_drmp_to_disk: false,
            use_experimental_features: false,
            realign_sections: false,
            zero_dos_stub_data: true,
            recalculate_file_checksum: false,
        }
    }
}
