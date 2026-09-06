# RustySteamless

A cross-platform rewrite of [Steamless](https://github.com/atom0s/Steamless) in Rust.
It removes SteamStub DRM from executable files, so they can be analyzed and modified after unpacking.

Rusty-Steamless ships as a Tauri app plus a CLI version for automatable or scripted use.

## Install

Grab the packager for your platform from the [latest release](https://github.com/notwinterdust/RustySteamless/releases/latest):

| Platform | Package | Link |
|---|---|---|
| Windows | `rusty-steamless-windows-x86.exe` (GUI) | [Download](https://github.com/notwinterdust/RustySteamless/releases/download/v0.1.0/rusty-steamless-windows-x86.exe) |
| macOS | `rusty-steamless-macos-arm64.dmg` (GUI) | [Download](https://github.com/notwinterdust/RustySteamless/releases/download/v0.1.0/rusty-steamless-macos-arm64.dmg) |
| Linux | `rusty-steamless-linux-x86.AppImage` (GUI) | [Download](https://github.com/notwinterdust/RustySteamless/releases/download/v0.1.0/rusty-steamless-linux-x86.AppImage) |

Need a bare binary instead of the GUI? Use the matching `rusty-steamless-cli-*` asset:

| Platform | CLI binary |
|---|---|
| Windows | [rusty-steamless-cli-windows-x86.exe](https://github.com/notwinterdust/RustySteamless/releases/download/v0.1.0/rusty-steamless-cli-windows-x86.exe) |
| macOS | [rusty-steamless-cli-macos-arm64](https://github.com/notwinterdust/RustySteamless/releases/download/v0.1.0/rusty-steamless-cli-macos-arm64) |
| Linux x86 | [rusty-steamless-cli-linux-x86](https://github.com/notwinterdust/RustySteamless/releases/download/v0.1.0/rusty-steamless-cli-linux-x86) |
| Linux arm64 | [rusty-steamless-cli-linux-arm64](https://github.com/notwinterdust/RustySteamless/releases/download/v0.1.0/rusty-steamless-cli-linux-arm64) |

## CLI usage

```
rusty-steamless <FILE> [--keepbind] [--keepstub] [--dumppayload] [--dumpdrmp] [--realign] [--recalcchecksum] [--exp]
```

## Credits

Rusty-Steamless is a port of **Steamless**, written by [Atom0s](https://github.com/atom0s).
All unpacking logic is derived from the original [Steamless C# project](https://github.com/atom0s/Steamless).

## Feedback

Found a bug or have a suggestion? Please [open an issue](https://github.com/notwinterdust/RustySteamless/issues).
