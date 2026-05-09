//! Handcrafted micro-fixtures for the PSP firmware on-disk layout.
//!
//! Each accessor returns the bytes of a small, hand-built blob committed at
//! `crates/psptool-fixtures/data/`. The fixtures are designed to be the
//! smallest valid input that exercises a particular parser branch from the
//! spec at `docs/firmware-layout.md`.
//!
//! The committed bytes are the source of truth at runtime. They are
//! produced (and reproducible) via `cargo run --example build_fixtures
//! -p psptool-fixtures`, which runs the construction logic in
//! `examples/build_fixtures.rs` and writes the same bytes back into
//! `data/`.
//!
//! ## Index of fixtures
//!
//! | Accessor                  | Parser branch covered                                           |
//! | ------------------------- | --------------------------------------------------------------- |
//! | [`fet`]                   | Firmware Entry Table (§1.2): magic, sentinel skip, terminator   |
//! | [`psp_directory`]         | `$PSP` directory header + 1 NO_HDR entry + body (§2.1, §3.1)    |
//! | [`bhd_directory`]         | `$BHD` directory header + 1 entry (§2.1, §3.2)                  |
//! | [`combo_psp`]              | `2PSP` combo directory header + 1 generation→pointer (§2.3)     |
//! | [`header_signed`]          | Signed `HeaderFile` (§4) — RSA-2048 sig, no enc/comp           |
//! | [`header_encrypted`]       | `HeaderFile` with `is_encrypted = 1` (§4, §5)                   |
//! | [`header_compressed`]      | `HeaderFile` with `is_compressed = 1`, real zlib body (§4, §6)  |
//! | [`pubkey_v1`]              | `PubkeyFile` version 1, RSA-2048, no signature (§7.1)           |

/// FET fixture: magic + skip-sentinel slot + 4-dword terminator.
///
/// Covers the FET parser's magic-recognition, sentinel-skip
/// (`0xFFFFFFFE`), and termination logic (§1.2). Does not include the
/// `0xFFFFFFFF` / `0x00000000` 4-byte pad that precedes the magic during
/// FET *discovery* (§1.1) — that is the scanner's job, not the FET parser's.
pub fn fet() -> &'static [u8] {
    include_bytes!("../data/fet.bin")
}

/// `$PSP` directory header + 1 entry + entry body, addressed via mode `10`
/// (offset from directory header) so the fixture is self-contained.
///
/// Covers §2.1 (directory header), §2.2 (address mode `10`), §2.4 (Fletcher-32),
/// and §3.1 (PSP entry record). The single entry is type `0x21` (WRAPPED_IKEK,
/// a NO_HDR type), which exercises the "no header" entry-kind branch.
pub fn psp_directory() -> &'static [u8] {
    include_bytes!("../data/psp_directory.bin")
}

/// `$BHD` directory header + 1 entry + entry body.
///
/// Covers the BIOS variant of §2.1 with the wider 24-byte entry record
/// (§3.2), including the 64-bit `destination` field set to the
/// "unused" sentinel `0xFFFFFFFFFFFFFFFF`.
pub fn bhd_directory() -> &'static [u8] {
    include_bytes!("../data/bhd_directory.bin")
}

/// `2PSP` combo directory header + 1 combo entry.
///
/// Covers §2.3 (combo header layout, 16-byte reserved, 16-byte combo entry)
/// with the Zen 2 generation ID (`0xBC0B0500`).
pub fn combo_psp() -> &'static [u8] {
    include_bytes!("../data/combo_psp.bin")
}

/// Signed `HeaderFile`: 0x100-byte header, 16-byte plaintext body, 0x100-byte
/// RSA-2048 signature placeholder. Total length 0x210.
///
/// Covers §4 with `is_signed = 1`, `is_encrypted = 0`, `is_compressed = 0`,
/// `signature_type = 0` (RSA-2048). The signature bytes themselves are
/// filler — verification is out of scope for this fixture.
pub fn header_signed() -> &'static [u8] {
    include_bytes!("../data/header_signed.bin")
}

/// `HeaderFile` with `is_encrypted = 1`: non-zero IV at +0x20 and non-zero
/// wrapped key at +0x80.
///
/// Covers §4 + §5: the parser must recognise the encrypted flag and route
/// the body through AES-128-CBC. The body bytes are not actually encrypted
/// (we don't ship the IKEK in the test bundle); the fixture tests the
/// *structural* parse path only.
pub fn header_encrypted() -> &'static [u8] {
    include_bytes!("../data/header_encrypted.bin")
}

/// `HeaderFile` with `is_compressed = 1`: body contains a real zlib stream
/// (the bytes `b"hello, psptool-rs"` compressed at default compression).
///
/// Covers §4 + §6: the body is shorter than the body region; `zlib_size`
/// gives the exact compressed length, `size_uncompressed` gives the
/// expected output length. The zlib stream sits at body offset 0, well
/// inside PSPTool's first-0x500-bytes search window.
pub fn header_compressed() -> &'static [u8] {
    include_bytes!("../data/header_compressed.bin")
}

/// `PubkeyFile`, version 1, RSA-2048 modulus, no embedded signature.
///
/// Covers §7.1: 64-byte fixed header, `pubexp_bits == modulus_bits == 2048`,
/// pubexp = `0x10001` little-endian, modulus is a deterministic byte
/// pattern. Signature length is 0 — `signature_size = total - 0x40 -
/// pubexp_size - modulus_size = 0`.
pub fn pubkey_v1() -> &'static [u8] {
    include_bytes!("../data/pubkey_v1.bin")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u32_le(buf: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
    }

    #[test]
    fn fet_starts_with_magic_and_terminates_with_four_ff_dwords() {
        let bytes = fet();
        assert_eq!(&bytes[0..4], &[0xAA, 0x55, 0xAA, 0x55], "FET magic");
        // Last 16 bytes are the 4-dword 0xFFFFFFFF terminator.
        let tail = &bytes[bytes.len() - 16..];
        assert_eq!(tail, &[0xFF; 16], "FET terminator");
    }

    #[test]
    fn psp_directory_has_dollar_psp_magic_and_one_entry() {
        let bytes = psp_directory();
        assert_eq!(&bytes[0..4], b"$PSP");
        assert_eq!(u32_le(bytes, 0x08), 1, "count == 1");
        // Body sits past header (0x10) + 1 entry (0x10) = 0x20.
        assert!(bytes.len() >= 0x20);
    }

    #[test]
    fn bhd_directory_has_dollar_bhd_magic_and_24byte_entry() {
        let bytes = bhd_directory();
        assert_eq!(&bytes[0..4], b"$BHD");
        assert_eq!(u32_le(bytes, 0x08), 1, "count == 1");
        // Header (0x10) + 1 BIOS entry (0x18) = 0x28; body sits past that.
        assert!(bytes.len() >= 0x28);
    }

    #[test]
    fn combo_psp_has_combo_magic_and_one_entry() {
        let bytes = combo_psp();
        assert_eq!(&bytes[0..4], b"2PSP");
        assert_eq!(u32_le(bytes, 0x08), 1, "count == 1");
        // Combo header is 0x20 bytes (4 dwords + 16-byte reserved); 1 combo
        // entry is 0x10 bytes.
        assert_eq!(bytes.len(), 0x20 + 0x10);
        // 16-byte reserved at +0x10..+0x20 must be zero (PSPTool asserts).
        assert!(bytes[0x10..0x20].iter().all(|&b| b == 0));
    }

    #[test]
    fn header_signed_has_signed_flag_and_correct_total_length() {
        let bytes = header_signed();
        assert_eq!(bytes.len(), 0x100 + 0x10 + 0x100, "header + body + sig");
        assert_eq!(u32_le(bytes, 0x18), 0, "is_encrypted == 0");
        assert_eq!(u32_le(bytes, 0x30), 1, "is_signed == 1");
        assert_eq!(u32_le(bytes, 0x34), 0, "signature_type == RSA-2048");
        assert_eq!(u32_le(bytes, 0x48), 0, "is_compressed == 0");
    }

    #[test]
    fn header_encrypted_has_iv_and_wrapped_key_set() {
        let bytes = header_encrypted();
        assert_eq!(u32_le(bytes, 0x18), 1, "is_encrypted == 1");
        // IV (0x20..0x30) and wrapped_key (0x80..0x90) MUST be non-zero per §5.
        assert!(bytes[0x20..0x30].iter().any(|&b| b != 0), "non-zero IV");
        assert!(
            bytes[0x80..0x90].iter().any(|&b| b != 0),
            "non-zero wrapped key"
        );
    }

    #[test]
    fn header_compressed_has_zlib_magic_in_body() {
        let bytes = header_compressed();
        assert_eq!(u32_le(bytes, 0x48), 1, "is_compressed == 1");
        let zlib_size = u32_le(bytes, 0x54) as usize;
        let size_unc = u32_le(bytes, 0x50) as usize;
        assert!(zlib_size > 0 && size_unc > 0);
        // Body starts at 0x100; first two bytes are a zlib header.
        let zlib_first = bytes[0x100];
        let zlib_magics = [0x78u8];
        assert!(
            zlib_magics.contains(&zlib_first),
            "zlib magic at body start"
        );
        let zlib_second = bytes[0x101];
        assert!(matches!(zlib_second, 0xDA | 0x9C | 0x5E | 0x01));
    }

    #[test]
    fn pubkey_v1_has_correct_version_and_sizes() {
        let bytes = pubkey_v1();
        assert_eq!(u32_le(bytes, 0x00), 1, "version == 1");
        let pubexp_bits = u32_le(bytes, 0x38);
        let modulus_bits = u32_le(bytes, 0x3C);
        assert_eq!(pubexp_bits, 2048);
        assert_eq!(modulus_bits, 2048);
        let pubexp_size = (pubexp_bits as usize) / 8;
        let modulus_size = (modulus_bits as usize) / 8;
        // No embedded signature.
        assert_eq!(bytes.len(), 0x40 + pubexp_size + modulus_size);
        // pubexp low 4 bytes = 0x10001 little-endian, rest zero.
        assert_eq!(&bytes[0x40..0x44], &[0x01, 0x00, 0x01, 0x00]);
        assert!(bytes[0x44..0x40 + pubexp_size].iter().all(|&b| b == 0));
    }
}
