# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- Python bindings (`crates/psptool-py`, pyo3 abi3 + maturin): a drop-in `psptool` module with PSPTool's classes, read API (upstream `(rom, dir, file)` order, `get_decrypted_decompressed_body`, `decode_verification`, `plaintext_identity_ok`) and edit/re-sign API; `default.nix` `python` / `pythonFor`; reference oracle repinned to vringar/PSPTool 241629b (#95)
- Design doc: .design/psptool-core/address.md (address-mode / ROM-masking) (#67)
- Design doc: .design/psptool-core/writer.md (diff-and-patch byte-exact writer) (#65)
- acto-critic audit: psptool-core/directory.rs vs directory.py (#50)
- Translation unit: psptool-core/directory.rs (#49)
- acto-critic audit: psptool-core/entry.rs vs entry.py+file.py (#47)
- Translation unit: psptool-core/entry.rs (#46)
- acto-critic audit: psptool-core/fletcher.rs vs utils.fletcher32 (#44)
- Translation unit: psptool-core/fletcher.rs (#42)

### Fixed
- psptool-py: Python subclasses of the parsed model classes (PSP-DB's ROM-less `FakeHeaderFile(HeaderFile)`) instantiate without ROM arguments, and the `HeaderFile` decode ladder (`decode_verification`, `decode_verified`, `plaintext_identity_ok`, ...) runs upstream's call structure over their overrides and attributes; psptool-core exposes `body::decrypt` / `body::zlib_decompress` (`utils.py` primitives) (#97)
- Version skew: differential oracle (psptool 3.4) != translation source (git HEAD ~3.6) — needs alignment decision (#61)
- psptool-core: #59 zlib-recovery overrun check uses whole-file blob_end, upstream uses the ROM window (multi-ROM divergence) (#72)
- psptool-ops: replace.rs rewrite_size_field .expect can panic when zlib-recovered original_len exceeds u32 (R-CODE-2) (#71)
- psptool-core: #51 tertiary walk discards block[20:24] Zen generation id (ls Generation column diverges) (#70)
- psptool-core: entry address-mode divergence on upper-half (>16MB) directories — SP5 EPYC (#52)
- psptool-core: follow tertiary (0x48/0x4A) L2 directory pointers — Zen 4 double-indirection (#51)

### Changed
- Divergence: list.rs ls verbose 'MD5' column is full 32-char lowercase, upstream psptool.py:180 renders md5()[:4].upper() (4-char uppercase) (#87)
- Divergence: list.rs ls verbose 'flags' column populated (0x..), upstream psptool.py:179 renders it empty ('') (#86)
- Spillover: extract.rs:156-157 build_encrypted_header_body stamps header-inclusive size_signed (stale convention) (#80)
- Blocker for REQ-7 of extract.md: -u/-c single-file output must match upstream get_signed_bytes/to_decrypted_file_bytes envelope (#88)
- Differential divergence: AORUS_X570 entry 26 type 0x5c named SPI_ROM_CONFIG vs upstream WMOS (HeaderFile) (#60)
- Divergence: list.rs ls text renders Subprogram/Instance as decimal, upstream psptool.py:174-175 uses hex() (#85)
- Divergence: find_zlib_start (body.rs:486) scans whole plaintext, not plaintext[..zlib_size] as upstream zlib_find_header(output[:zlib_size]) (#84)
- Divergence: HeaderEntry::signature_bytes (body.rs:222) ignores is_signed — returns last signature_len bytes for an unsigned HeaderFile (#83)
- Divergence: body.rs get_decompressed_body treats zlib_size as length-from-magic, not absolute end offset (over-reads with pre-magic prefix) vs utils.py:245-252 / header_file.py:171 (#82)
- Divergence: body.rs data_region ignores is_signed (drops signature_len bytes for unsigned HeaderFiles) vs header_file.py:83-84,100 (#81)
- Blocker for REQ-8 of sign: needs real-corpus/upstream cross-validation of re-signed HeaderFile output. sign_entry reverses the on-disk signature bytes (sign.rs:174-175, per firmware-layout §7.1 PubkeyFile convention) and target verify (body.rs:393) reverses to match — internally self-consistent (synthetic sign->verify roundtrip verify.rs:360). But upstream HeaderFile verifies via a PLAIN non-reversed Signature (cert_tree.py:63 wraps hf.signature as Signature, not ReversedSignature), so a re-signed HeaderFile may not verify under upstream PSPTool. No psptool-ops test re-signs a real corpus entry and checks it verifies under the reference tool. (#78)
- Divergence: psptool-core HeaderEntry::get_signed_bytes signs 0x100 too few bytes vs upstream (body.rs:333-349 vs header_file.py:162-164) (#79)
- psptool-core: multi-ROM blob directory parsing diverges from reference (BIOS entry base + entry 3 type) (#41)
- Blocker for REQ-6 of psptool-core/fletcher: no production consumer recomputes fletcher32 — writer.rs is diff-and-patch only (writer.rs:15) and never calls psptool_core::fletcher32; a mutation path that recomputes the directory checksum and writes it LE into header [0x04..0x08] does not exist (#43)
- Divergence: psptool-ops replace leaves directory fletcher32 stale; upstream recomputes (directory.py:241) (#66)
- Divergence: directory.rs::tertiary_actual_offset masks L2 target with PhysicalX86 window override instead of plain addr_mask (directory.py:105) (#68)
- Latent divergence in fet.rs scan_fet_candidates ordering: upstream blob.py:126-131 yields ALL 0xFFFFFFFF-padded FETs first then ALL 0x00000000-padded (two separate re.finditer passes); Rust scan_fet_candidates (fet.rs:310-316) yields both patterns interleaved in file-position order. For a blob mixing both pad kinds this changes ROM .nth(rom_index) selection order (load.rs:41). Not exercised by current corpus (differential green); pin a fixture + align ordering. (#63)
- psptool-core: compressed entry whose directory size overruns the ROM is rejected (#40)
- Divergence: psptool-core entry.rs resolve_body drops compressed BIOS entries whose directory size overruns the ROM (upstream sizes them via the zlib header) (#59)
- Divergence: psptool_core::fletcher32 silently accepts odd-length input; upstream utils.py:291 raises struct.error (#45)
- integration: differential test vs reference Python PSPTool (#18)
