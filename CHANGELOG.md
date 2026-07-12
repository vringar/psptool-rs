# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- Design doc: .design/psptool-core/address.md (address-mode / ROM-masking) (#67)
- Design doc: .design/psptool-core/writer.md (diff-and-patch byte-exact writer) (#65)
- acto-critic audit: psptool-core/directory.rs vs directory.py (#50)
- Translation unit: psptool-core/directory.rs (#49)
- acto-critic audit: psptool-core/entry.rs vs entry.py+file.py (#47)
- Translation unit: psptool-core/entry.rs (#46)
- acto-critic audit: psptool-core/fletcher.rs vs utils.fletcher32 (#44)
- Translation unit: psptool-core/fletcher.rs (#42)

### Fixed
- psptool-core: entry address-mode divergence on upper-half (>16MB) directories — SP5 EPYC (#52)
- psptool-core: follow tertiary (0x48/0x4A) L2 directory pointers — Zen 4 double-indirection (#51)

### Changed
- Latent divergence in fet.rs scan_fet_candidates ordering: upstream blob.py:126-131 yields ALL 0xFFFFFFFF-padded FETs first then ALL 0x00000000-padded (two separate re.finditer passes); Rust scan_fet_candidates (fet.rs:310-316) yields both patterns interleaved in file-position order. For a blob mixing both pad kinds this changes ROM .nth(rom_index) selection order (load.rs:41). Not exercised by current corpus (differential green); pin a fixture + align ordering. (#63)
- psptool-core: compressed entry whose directory size overruns the ROM is rejected (#40)
- Divergence: psptool-core entry.rs resolve_body drops compressed BIOS entries whose directory size overruns the ROM (upstream sizes them via the zlib header) (#59)
- Divergence: psptool_core::fletcher32 silently accepts odd-length input; upstream utils.py:291 raises struct.error (#45)
- integration: differential test vs reference Python PSPTool (#18)
