//! Entry-body parser and entry-kind taxonomy.
//!
//! A `PspEntry` or `BiosEntry` (see `directory.rs`) is the 16/24-byte directory
//! *record*. This module turns each record into an [`Entry`] — the record plus
//! the body bytes it points at plus a classification of the body's structural
//! shape. The taxonomy mirrors PSPTool's `File` hierarchy (`psptool/file.py`):
//!
//! | Rust variant                          | PSPTool class      |
//! | ------------------------------------- | ------------------ |
//! | [`EntryClass::Plain`]                 | `File` (base)      |
//! | [`EntryClass::Header`]                | `HeaderFile` (§4)  |
//! | [`EntryClass::Pubkey`]                | `PubkeyFile` (§7.1)|
//! | [`EntryClass::KeyStore`]              | `KeyStoreFile` (§7.2) |
//! | [`EntryClass::Microcode`]             | `MicrocodeFile`    |
//! | [`EntryClass::SecondaryDirectoryPointer`] | sub-dir entry types `0x40 / 0x49 / 0x70` |
//! | [`EntryClass::TertiaryDirectoryPointer`]  | tertiary types `0x48 / 0x4A` (§3.3) |
//! | [`EntryClass::SoftFuseChain`]         | type `0x0B` (§3.4) |
//!
//! Classification dispatch reuses the existing [`EntryType`] `is_*` predicates
//! (the broader "EntryKind enum vs is_* predicates" redesign tracked as L9 is
//! deferred — this module does not relitigate it).
//!
//! Out of scope (deferred to issues #8 / #9):
//!
//! * Actually decompressing or decrypting a [`HeaderEntry`] body.
//! * Parsing the `$KDB` body inside a [`EntryClass::KeyStore`].
//! * Following [`EntryClass::TertiaryDirectoryPointer`] indirection records.
//! * Writer-side mutation.
//!
//! Every parsed sub-structure ([`HeaderEntry`], [`PubkeyEntry`]) retains its
//! own [`SourceBytes`] window. Combined with [`Entry::body`] this preserves
//! the byte-exact roundtrip rule (`docs/firmware-layout.md` §8): the parser
//! never copies, and the writer can patch through the original blob using the
//! same windows.

use crate::address::{Address, AddressMode, FlashOffset, ResolveContext, RomSize};
use crate::directory::{BiosDirectory, BiosEntry, PspDirectory, PspEntry};
use crate::error::ParseError;
use crate::id::EntryType;
use crate::source::SourceBytes;

/// Length of the PSP "blob header" prefixed to signed-entry bodies (§4).
pub const HEADER_FILE_LEN: usize = 0x100;

/// Length of the fixed `PubkeyFile` header (§7.1).
pub const PUBKEY_HEADER_LEN: usize = 0x40;

/// Directory-record half of an [`Entry`].
///
/// PSP-family and BIOS-family directories carry slightly different record
/// layouts (16 vs 24 bytes — see `docs/firmware-layout.md` §3.1, §3.2). The
/// enum lets downstream code branch on family without having to thread the
/// distinction through every signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EntryRecord {
    Psp(PspEntry),
    Bios(BiosEntry),
}

impl EntryRecord {
    #[inline]
    pub fn entry_type(&self) -> EntryType {
        match self {
            Self::Psp(p) => p.entry_type,
            Self::Bios(b) => b.entry_type,
        }
    }

    #[inline]
    pub fn size(&self) -> u32 {
        match self {
            Self::Psp(p) => p.size,
            Self::Bios(b) => b.size,
        }
    }

    #[inline]
    pub fn offset(&self) -> Address {
        match self {
            Self::Psp(p) => p.offset,
            Self::Bios(b) => b.offset,
        }
    }

    #[inline]
    pub fn entry_address_mode(&self) -> AddressMode {
        match self {
            Self::Psp(p) => p.entry_address_mode(),
            Self::Bios(b) => b.entry_address_mode(),
        }
    }

    /// Source bytes of the directory record itself (16/24 bytes).
    #[inline]
    pub fn source(&self) -> &SourceBytes {
        match self {
            Self::Psp(p) => &p.source,
            Self::Bios(b) => &b.source,
        }
    }
}

/// Parsed PSP "blob header" (§4): the 0x100-byte fixed prefix on signed-entry
/// bodies. All multi-byte fields are little-endian unless noted.
///
/// `source` covers exactly the 0x100 header bytes (a sub-window of the entry
/// body). Decompression/decryption are deferred to #8 — this struct exposes
/// only the fields the parser can read straight off the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderEntry {
    /// 0x100-byte source slice covering the header.
    pub source: SourceBytes,
    /// 4-byte tag at +0x10 (e.g. `$PS1`, `\x05\0\0\0`, vendor-specific).
    pub magic: [u8; 4],
    /// `size_signed` at +0x14 — length of `header || decrypted_decompressed_body`
    /// covered by the RSA signature.
    pub size_signed: u32,
    pub is_encrypted: bool,
    /// AES-128-CBC IV at +0x20..+0x30 (significant only when `is_encrypted`).
    pub iv: [u8; 16],
    /// Raw `signed` u32 at +0x30. PSPTool considers any non-zero value
    /// "signed" but only `{0, 1, 0xFFFF_0000}` are documented; we surface the
    /// raw value so callers can decide policy.
    pub signed_raw: u32,
    /// `signature_type` at +0x34 (`0` = RSA-2048, `2` = RSA-4096).
    pub signature_type: u32,
    /// 16-byte fingerprint at +0x38..+0x48 of the certifying key.
    pub signature_fingerprint: [u8; 16],
    pub is_compressed: bool,
    /// `size_uncompressed` at +0x50.
    pub size_uncompressed: u32,
    /// `zlib_size` at +0x54 — length of the zlib stream within the body.
    pub zlib_size: u32,
    /// Bitfield at +0x58 read **big-endian** per §4. Bit 0 = sha256,
    /// bit 1 = sha384.
    pub bitfield: u32,
    /// 4 raw bytes at +0x60..+0x64. Display order is reversed (§4 note); the
    /// on-disk ordering must be preserved verbatim.
    pub version: [u8; 4],
    /// `load_addr` at +0x68.
    pub load_addr: u32,
    /// `rom_size` at +0x6c — total in-flash size of the entry. `0` means "use
    /// the parent entry's `size`" per §4.
    pub rom_size: u32,
    /// AES-128 wrapped-key at +0x80..+0x90 (significant only when `is_encrypted`).
    pub wrapped_key: [u8; 16],
}

impl HeaderEntry {
    /// Parse a `HeaderFile` from the start of `body`. The header consumes the
    /// first 0x100 bytes; the rest of `body` is the (possibly encrypted /
    /// compressed) data plus trailing signature bytes.
    pub fn parse(body: &SourceBytes) -> Result<Self, ParseError> {
        if body.len() < HEADER_FILE_LEN {
            return Err(ParseError::Truncated {
                what: "PSP header",
                offset: body.offset(),
                expected: HEADER_FILE_LEN,
                available: body.len(),
            });
        }
        let source = body.slice(0, HEADER_FILE_LEN).expect("len checked above");
        let h = source.as_bytes();

        let magic = [h[0x10], h[0x11], h[0x12], h[0x13]];
        let size_signed = u32::from_le_bytes(h[0x14..0x18].try_into().unwrap());
        let is_encrypted = u32::from_le_bytes(h[0x18..0x1C].try_into().unwrap()) == 1;
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&h[0x20..0x30]);
        let signed_raw = u32::from_le_bytes(h[0x30..0x34].try_into().unwrap());
        let signature_type = u32::from_le_bytes(h[0x34..0x38].try_into().unwrap());
        let mut signature_fingerprint = [0u8; 16];
        signature_fingerprint.copy_from_slice(&h[0x38..0x48]);
        let is_compressed = u32::from_le_bytes(h[0x48..0x4C].try_into().unwrap()) == 1;
        let size_uncompressed = u32::from_le_bytes(h[0x50..0x54].try_into().unwrap());
        let zlib_size = u32::from_le_bytes(h[0x54..0x58].try_into().unwrap());
        let bitfield = u32::from_be_bytes(h[0x58..0x5C].try_into().unwrap());
        let version = [h[0x60], h[0x61], h[0x62], h[0x63]];
        let load_addr = u32::from_le_bytes(h[0x68..0x6C].try_into().unwrap());
        let rom_size = u32::from_le_bytes(h[0x6C..0x70].try_into().unwrap());
        let mut wrapped_key = [0u8; 16];
        wrapped_key.copy_from_slice(&h[0x80..0x90]);

        Ok(Self {
            source,
            magic,
            size_signed,
            is_encrypted,
            iv,
            signed_raw,
            signature_type,
            signature_fingerprint,
            is_compressed,
            size_uncompressed,
            zlib_size,
            bitfield,
            version,
            load_addr,
            rom_size,
            wrapped_key,
        })
    }

    /// Whether this header records a signature. Mirrors PSPTool's
    /// `HeaderFile.is_signed` (any nonzero `signed_raw`).
    #[inline]
    pub fn is_signed(&self) -> bool {
        self.signed_raw != 0
    }

    /// `signed_raw` is one of the documented values `{0, 1, 0xFFFF_0000}`.
    /// PSPTool raises if not — we let callers decide whether to enforce.
    #[inline]
    pub fn signed_value_is_documented(&self) -> bool {
        matches!(self.signed_raw, 0 | 1 | 0xFFFF_0000)
    }

    #[inline]
    pub fn has_sha256_checksum(&self) -> bool {
        (self.bitfield & 0b01) != 0
    }

    #[inline]
    pub fn has_sha384_checksum(&self) -> bool {
        (self.bitfield & 0b10) != 0
    }

    /// Trailing RSA-signature length in bytes, when the header is signed.
    /// Returns `None` for unsupported `signature_type` values.
    #[inline]
    pub fn signature_len(&self) -> Option<usize> {
        match self.signature_type {
            0 => Some(0x100),
            2 => Some(0x200),
            _ => None,
        }
    }
}

/// Parsed `PubkeyFile` fixed header (§7.1).
///
/// The 0x40-byte fixed header and the public-exponent/modulus *bit widths* are
/// extracted; the modulus, exponent bytes, and trailing signature are NOT
/// copied — callers can read them out of [`PubkeyEntry::source`] when needed.
/// This keeps the entry roundtrip-safe and avoids touching crypto material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PubkeyEntry {
    /// Source slice covering the entire pubkey blob (header + crypto + sig).
    pub source: SourceBytes,
    pub version: u32,
    /// 16-byte fingerprint of the contained key — the "magic" PSPTool prints.
    pub key_id: [u8; 16],
    /// 16-byte fingerprint of the key that signed THIS pubkey.
    pub certifying_id: [u8; 16],
    pub key_usage: u32,
    pub security_features: u16,
    pub pubexp_bits: u32,
    pub modulus_bits: u32,
}

impl PubkeyEntry {
    /// Parse a `PubkeyFile` from the start of `body`.
    pub fn parse(body: &SourceBytes) -> Result<Self, ParseError> {
        if body.len() < PUBKEY_HEADER_LEN {
            return Err(ParseError::Truncated {
                what: "PubkeyFile header",
                offset: body.offset(),
                expected: PUBKEY_HEADER_LEN,
                available: body.len(),
            });
        }
        let h = body.as_bytes();
        let version = u32::from_le_bytes(h[0x00..0x04].try_into().unwrap());
        let mut key_id = [0u8; 16];
        key_id.copy_from_slice(&h[0x04..0x14]);
        let mut certifying_id = [0u8; 16];
        certifying_id.copy_from_slice(&h[0x14..0x24]);
        let key_usage = u32::from_le_bytes(h[0x24..0x28].try_into().unwrap());
        let security_features = u16::from_le_bytes(h[0x2A..0x2C].try_into().unwrap());
        let pubexp_bits = u32::from_le_bytes(h[0x38..0x3C].try_into().unwrap());
        let modulus_bits = u32::from_le_bytes(h[0x3C..0x40].try_into().unwrap());

        Ok(Self {
            source: body.clone(),
            version,
            key_id,
            certifying_id,
            key_usage,
            security_features,
            pubexp_bits,
            modulus_bits,
        })
    }

    /// `pubexp` size in bytes (= `pubexp_bits / 8`).
    #[inline]
    pub fn pubexp_size(&self) -> usize {
        (self.pubexp_bits as usize) / 8
    }

    /// `modulus` size in bytes (= `modulus_bits / 8`).
    #[inline]
    pub fn modulus_size(&self) -> usize {
        (self.modulus_bits as usize) / 8
    }
}

/// Classification of an entry's body. See module docs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EntryClass {
    /// Generic body, no structural prefix (`File` base class).
    Plain,
    /// Body starts with a PSP 0x100-byte signed-entry header (`HeaderFile`).
    Header(HeaderEntry),
    /// Body is a `PubkeyFile` (§7.1).
    Pubkey(PubkeyEntry),
    /// Body is a `KeyStoreFile` (§7.2). The leading PSP header is parsed; the
    /// embedded `$KDB` body is deferred to a later issue.
    KeyStore(HeaderEntry),
    /// BIOS directory entry type `0x66`. Compressed-microcode handling is
    /// deferred to #8; classification is exposed so callers can branch on it.
    Microcode,
    /// Sub-directory pointer (`0x40 / 0x49 / 0x70`) — body is another directory
    /// header. The directory walker (`directory::walk_directories`) follows
    /// these; the entry-level parser only labels them.
    SecondaryDirectoryPointer,
    /// Tertiary sub-directory pointer (`0x48 / 0x4A`, Zen 4) — body is a
    /// 32-byte indirection record (§3.3). Following is deferred.
    TertiaryDirectoryPointer,
    /// Soft-fuse chain (`0x0B`) — the entry record itself encodes the fuse
    /// mask; there is no separate body file (§3.4).
    SoftFuseChain,
}

impl EntryClass {
    /// True iff the variant carries a parsed [`HeaderEntry`].
    pub fn header(&self) -> Option<&HeaderEntry> {
        match self {
            Self::Header(h) | Self::KeyStore(h) => Some(h),
            _ => None,
        }
    }

    /// True iff the variant carries a parsed [`PubkeyEntry`].
    pub fn pubkey(&self) -> Option<&PubkeyEntry> {
        match self {
            Self::Pubkey(p) => Some(p),
            _ => None,
        }
    }
}

/// A directory entry resolved into (record, body, classification).
///
/// `body` always covers the bytes the directory record points at. For
/// soft-fuse-chain entries (§3.4) the body is the 16-byte entry record itself
/// — PSPTool models this the same way (`File.from_entry` + `NO_SIZE_ENTRY_TYPES`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub record: EntryRecord,
    pub body: SourceBytes,
    pub class: EntryClass,
}

impl Entry {
    /// PSPTool-compatible accessor: returns the entry body source bytes
    /// (`File.get_bytes()`). Callers needing the *decompressed* or *decrypted*
    /// view should wait for #8.
    #[inline]
    pub fn get_bytes(&self) -> &SourceBytes {
        &self.body
    }

    /// Convenience: the entry's `type` byte.
    #[inline]
    pub fn entry_type(&self) -> EntryType {
        self.record.entry_type()
    }

    /// Parse a single PSP-family entry record into a full [`Entry`].
    ///
    /// `parent` is the parent `$PSP` / `$PL2` directory — its address mode and
    /// header offset feed [`AddressMode::resolve_with_entry`]. `index` is the
    /// position of the record within `parent.entries`.
    pub fn parse_psp(
        blob: &SourceBytes,
        parent: &PspDirectory,
        index: usize,
        rom_size: RomSize,
        rom_origin: FlashOffset,
    ) -> Result<Self, ParseError> {
        let record =
            parent
                .entries
                .get(index)
                .cloned()
                .ok_or(ParseError::EntryIndexOutOfRange {
                    offset: parent.source.offset(),
                    index,
                    count: parent.entries.len(),
                })?;
        let dir_mode = parent.header.address_mode();
        let dir_base = parent.source.offset();
        let body = resolve_body(
            blob,
            dir_mode,
            dir_base,
            &record.source,
            record.entry_type,
            record.offset,
            record.entry_address_mode(),
            record.size,
            rom_size,
            rom_origin,
        )?;
        let class = classify(record.entry_type, /* is_bios */ false, &body);
        Ok(Self {
            record: EntryRecord::Psp(record),
            body,
            class,
        })
    }

    /// Parse a single BIOS-family entry record into a full [`Entry`].
    pub fn parse_bios(
        blob: &SourceBytes,
        parent: &BiosDirectory,
        index: usize,
        rom_size: RomSize,
        rom_origin: FlashOffset,
    ) -> Result<Self, ParseError> {
        let record =
            parent
                .entries
                .get(index)
                .cloned()
                .ok_or(ParseError::EntryIndexOutOfRange {
                    offset: parent.source.offset(),
                    index,
                    count: parent.entries.len(),
                })?;
        let dir_mode = parent.header.address_mode();
        let dir_base = parent.source.offset();
        let body = resolve_body(
            blob,
            dir_mode,
            dir_base,
            &record.source,
            record.entry_type,
            record.offset,
            record.entry_address_mode(),
            record.size,
            rom_size,
            rom_origin,
        )?;
        let class = classify(record.entry_type, /* is_bios */ true, &body);
        Ok(Self {
            record: EntryRecord::Bios(record),
            body,
            class,
        })
    }
}

/// Resolve the body byte slice for an entry.
///
/// * Soft-fuse-chain (`type == 0x0B`): per §3.4, the "body" is the entry
///   record itself — `record_source` is returned unchanged.
/// * Anything else: resolve the body's flash offset using the directory's
///   address mode (with the entry-level `rsv0[31:30]` override when the
///   directory mode is `10`/`11`) and then carve out `size` bytes from `blob`.
#[allow(clippy::too_many_arguments)]
fn resolve_body(
    blob: &SourceBytes,
    dir_mode: AddressMode,
    dir_base: FlashOffset,
    record_source: &SourceBytes,
    entry_type: EntryType,
    entry_offset: Address,
    entry_mode: AddressMode,
    entry_size: u32,
    rom_size: RomSize,
    rom_origin: FlashOffset,
) -> Result<SourceBytes, ParseError> {
    if entry_type.is_soft_fuse_chain() {
        // §3.4: no separate body — fuse mask is encoded in the entry record's
        // offset/rsv0 fields. Mirror PSPTool by exposing the entry record
        // bytes as the body.
        return Ok(record_source.clone());
    }
    let ctx = ResolveContext {
        rom_size,
        directory_base: dir_base,
        rom_origin,
    };
    let body_offset = dir_mode.resolve_with_entry(entry_mode, entry_offset, ctx);
    let size = entry_size as u64;
    let blob_start = blob.offset().get();
    let blob_end = blob_start.saturating_add(blob.len() as u64);
    let body_end = body_offset.get().saturating_add(size);
    if body_offset.get() < blob_start || body_end > blob_end {
        return Err(ParseError::Truncated {
            what: "entry body",
            offset: body_offset,
            expected: entry_size as usize,
            available: blob_end.saturating_sub(body_offset.get().max(blob_start)) as usize,
        });
    }
    let local = (body_offset.get() - blob_start) as usize;
    blob.slice(local, entry_size as usize)
        .ok_or(ParseError::Truncated {
            what: "entry body",
            offset: body_offset,
            expected: entry_size as usize,
            available: blob.len().saturating_sub(local),
        })
}

/// Classify an entry body by `entry_type`. See [`EntryClass`].
///
/// Order mirrors PSPTool's `File.from_entry` decisions, but special-cases the
/// sub-directory-pointer / soft-fuse-chain types up front so callers see
/// richer information than just `Plain` for those.
fn classify(t: EntryType, is_bios: bool, body: &SourceBytes) -> EntryClass {
    if t.is_secondary_directory_pointer() {
        return EntryClass::SecondaryDirectoryPointer;
    }
    if t.is_tertiary_directory_pointer() {
        return EntryClass::TertiaryDirectoryPointer;
    }
    if t.is_soft_fuse_chain() {
        return EntryClass::SoftFuseChain;
    }
    if t.is_pubkey() {
        // Fall back to Plain on parse failure — keeps the byte-exact roundtrip
        // sound even on malformed corpus inputs.
        return PubkeyEntry::parse(body)
            .map(EntryClass::Pubkey)
            .unwrap_or(EntryClass::Plain);
    }
    if t.is_key_store() {
        return HeaderEntry::parse(body)
            .map(EntryClass::KeyStore)
            .unwrap_or(EntryClass::Plain);
    }
    if is_bios && t.get() == 0x66 {
        return EntryClass::Microcode;
    }
    if !t.has_no_header() {
        return HeaderEntry::parse(body)
            .map(EntryClass::Header)
            .unwrap_or(EntryClass::Plain);
    }
    EntryClass::Plain
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::{BIOS_ENTRY_SIZE, DIRECTORY_HEADER_SIZE, Directory, PSP_ENTRY_SIZE};
    use crate::magic::{PS1_MAGIC, PSP_MAGIC};

    // ------------------------------------------------------------------
    // HeaderEntry: parse the committed `header_signed` fixture.
    // ------------------------------------------------------------------

    #[test]
    fn header_entry_parses_signed_fixture() {
        let bytes = psptool_fixtures::micro::header_signed().to_vec();
        let body = SourceBytes::from_blob(bytes);
        let h = HeaderEntry::parse(&body).expect("parse signed header");
        assert_eq!(&h.magic, b"$PS1");
        assert_eq!(h.signed_raw, 1);
        assert!(h.is_signed());
        assert!(h.signed_value_is_documented());
        assert_eq!(h.signature_type, 0);
        assert_eq!(h.signature_len(), Some(0x100));
        assert!(!h.is_encrypted);
        assert!(!h.is_compressed);
        // `size_signed` per the build script: HEADER_LEN + BODY_LEN = 0x110.
        assert_eq!(h.size_signed, 0x110);
        // `rom_size` = total = HEADER + BODY + SIG = 0x210.
        assert_eq!(h.rom_size, 0x210);
        // No SHA bits set in the fixture.
        assert!(!h.has_sha256_checksum());
        assert!(!h.has_sha384_checksum());
        // Source covers exactly the 0x100 header.
        assert_eq!(h.source.len(), HEADER_FILE_LEN);
    }

    #[test]
    fn header_entry_parses_encrypted_fixture() {
        let bytes = psptool_fixtures::micro::header_encrypted().to_vec();
        let body = SourceBytes::from_blob(bytes);
        let h = HeaderEntry::parse(&body).expect("parse encrypted header");
        assert!(h.is_encrypted);
        assert!(h.iv.iter().any(|&b| b != 0), "IV must be non-zero (§5)");
        assert!(
            h.wrapped_key.iter().any(|&b| b != 0),
            "wrapped_key non-zero",
        );
    }

    #[test]
    fn header_entry_parses_compressed_fixture() {
        let bytes = psptool_fixtures::micro::header_compressed().to_vec();
        let body = SourceBytes::from_blob(bytes);
        let h = HeaderEntry::parse(&body).expect("parse compressed header");
        assert!(h.is_compressed);
        assert!(h.zlib_size > 0);
        assert!(h.size_uncompressed > 0);
    }

    #[test]
    fn header_entry_truncated_returns_truncated() {
        let body = SourceBytes::from_blob(vec![0u8; 0x80]); // half a header
        let err = HeaderEntry::parse(&body).unwrap_err();
        assert!(matches!(
            err,
            ParseError::Truncated {
                what: "PSP header",
                ..
            }
        ));
    }

    // ------------------------------------------------------------------
    // PubkeyEntry: parse the committed `pubkey_v1` fixture.
    // ------------------------------------------------------------------

    #[test]
    fn pubkey_entry_parses_v1_fixture() {
        let bytes = psptool_fixtures::micro::pubkey_v1().to_vec();
        let body = SourceBytes::from_blob(bytes);
        let p = PubkeyEntry::parse(&body).expect("parse pubkey v1");
        assert_eq!(p.version, 1);
        assert_eq!(p.pubexp_bits, 2048);
        assert_eq!(p.modulus_bits, 2048);
        assert_eq!(p.pubexp_size(), 256);
        assert_eq!(p.modulus_size(), 256);
        assert_eq!(p.key_usage, 0); // AMD_CODE_SIGN
        // The fixture writes deterministic byte patterns into key_id and
        // certifying_id; just verify they are parsed (non-zero and distinct).
        assert!(p.key_id.iter().any(|&b| b != 0));
        assert!(p.certifying_id.iter().any(|&b| b != 0));
        assert_ne!(p.key_id, p.certifying_id);
    }

    #[test]
    fn pubkey_entry_truncated_returns_truncated() {
        let body = SourceBytes::from_blob(vec![0u8; 0x20]);
        let err = PubkeyEntry::parse(&body).unwrap_err();
        assert!(matches!(
            err,
            ParseError::Truncated {
                what: "PubkeyFile header",
                ..
            }
        ));
    }

    // ------------------------------------------------------------------
    // Entry::parse_psp — committed psp_directory fixture (type 0x21).
    // ------------------------------------------------------------------

    #[test]
    fn parse_psp_entry_from_fixture_classifies_plain_and_preserves_body() {
        let bytes = psptool_fixtures::micro::psp_directory().to_vec();
        let original_body = bytes[0x20..0x30].to_vec();
        let blob = SourceBytes::from_blob(bytes);
        let dir = match Directory::parse_at(&blob, FlashOffset(0)).unwrap() {
            Directory::Psp(p) => p,
            other => panic!("expected PSP, got {other:?}"),
        };
        let entry = Entry::parse_psp(&blob, &dir, 0, RomSize::MIB_16, FlashOffset::ZERO)
            .expect("parse entry");
        // Type 0x21 is WRAPPED_IKEK — a NO_HDR type → Plain.
        assert!(matches!(entry.class, EntryClass::Plain));
        assert_eq!(entry.entry_type(), EntryType(0x21));
        // Body is the 16 bytes immediately after the entry record.
        assert_eq!(entry.get_bytes().len(), 0x10);
        assert_eq!(entry.get_bytes().offset(), FlashOffset(0x20));
        // Byte-exact preservation: the body slice equals the original input.
        assert_eq!(entry.get_bytes().as_bytes(), original_body.as_slice());
    }

    // ------------------------------------------------------------------
    // Entry::parse_bios — committed bhd_directory fixture (type 0x62).
    // ------------------------------------------------------------------

    #[test]
    fn parse_bios_entry_from_fixture_classifies_plain_and_preserves_body() {
        let bytes = psptool_fixtures::micro::bhd_directory().to_vec();
        let original_body = bytes[0x28..0x38].to_vec();
        let blob = SourceBytes::from_blob(bytes);
        let dir = match Directory::parse_at(&blob, FlashOffset(0)).unwrap() {
            Directory::Bios(b) => b,
            other => panic!("expected BIOS, got {other:?}"),
        };
        let entry = Entry::parse_bios(&blob, &dir, 0, RomSize::MIB_16, FlashOffset::ZERO)
            .expect("parse entry");
        // Type 0x62 is BIOS — NO_HDR.
        assert!(matches!(entry.class, EntryClass::Plain));
        assert_eq!(entry.entry_type(), EntryType(0x62));
        assert_eq!(entry.get_bytes().len(), 0x10);
        assert_eq!(entry.get_bytes().offset(), FlashOffset(0x28));
        assert_eq!(entry.get_bytes().as_bytes(), original_body.as_slice());
    }

    // ------------------------------------------------------------------
    // Synthetic blobs: drive each EntryClass branch end-to-end.
    // ------------------------------------------------------------------

    /// Build a minimal `$PSP` directory with a single entry described by
    /// (`type`, `size`, `offset`, `body`) where `offset` is dir-relative
    /// (additional_info v1, mode 10). Body sits right after the directory.
    fn psp_dir_with_entry(entry_type: u8, body: &[u8]) -> Vec<u8> {
        let body_off = (DIRECTORY_HEADER_SIZE + PSP_ENTRY_SIZE) as u32;
        let size = body.len() as u32;
        // additional_info: v1 (bit 31 = 1), mode bits[25:24] = 10.
        let additional_info = (1u32 << 31) | (0b10u32 << 24);
        let mut entry = [0u8; PSP_ENTRY_SIZE];
        entry[0x00] = entry_type;
        entry[0x04..0x08].copy_from_slice(&size.to_le_bytes());
        entry[0x08..0x0C].copy_from_slice(&body_off.to_le_bytes());
        // Entry-level mode 10 too so resolve picks dir_base + offset.
        let entry_rsv0: u32 = 0b10u32 << 30;
        entry[0x0C..0x10].copy_from_slice(&entry_rsv0.to_le_bytes());

        let mut out = Vec::new();
        out.extend_from_slice(b"$PSP");
        out.extend_from_slice(&0u32.to_le_bytes()); // checksum (unused by parser at this layer)
        out.extend_from_slice(&1u32.to_le_bytes()); // count
        out.extend_from_slice(&additional_info.to_le_bytes());
        out.extend_from_slice(&entry);
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn classifies_pubkey_entry_type() {
        let body = psptool_fixtures::micro::pubkey_v1().to_vec();
        let blob_bytes = psp_dir_with_entry(0x00, &body); // 0x00 = AMD_PUBLIC_KEY
        let blob = SourceBytes::from_blob(blob_bytes);
        let dir = match Directory::parse_at(&blob, FlashOffset(0)).unwrap() {
            Directory::Psp(p) => p,
            _ => unreachable!(),
        };
        let entry = Entry::parse_psp(&blob, &dir, 0, RomSize::MIB_16, FlashOffset::ZERO).unwrap();
        let pk = match &entry.class {
            EntryClass::Pubkey(p) => p,
            other => panic!("expected Pubkey, got {other:?}"),
        };
        assert_eq!(pk.version, 1);
        assert_eq!(pk.pubexp_bits, 2048);
        // Body slice is byte-identical to the original pubkey fixture.
        assert_eq!(entry.get_bytes().as_bytes(), body.as_slice());
    }

    #[test]
    fn classifies_header_entry_type() {
        let body = psptool_fixtures::micro::header_signed().to_vec();
        // Type 0x01 (PSP_FW_BOOT_LOADER) is not in NO_HDR → HeaderEntry.
        let blob_bytes = psp_dir_with_entry(0x01, &body);
        let blob = SourceBytes::from_blob(blob_bytes);
        let dir = match Directory::parse_at(&blob, FlashOffset(0)).unwrap() {
            Directory::Psp(p) => p,
            _ => unreachable!(),
        };
        let entry = Entry::parse_psp(&blob, &dir, 0, RomSize::MIB_16, FlashOffset::ZERO).unwrap();
        let h = match &entry.class {
            EntryClass::Header(h) => h,
            other => panic!("expected Header, got {other:?}"),
        };
        assert_eq!(&h.magic, PS1_MAGIC.as_bytes());
        assert!(h.is_signed());
        assert_eq!(entry.get_bytes().len(), body.len());
    }

    #[test]
    fn classifies_keystore_entry_type() {
        let body = psptool_fixtures::micro::header_signed().to_vec();
        // Type 0x50 → KeyStore (BL_PUBLIC_KEY).
        let blob_bytes = psp_dir_with_entry(0x50, &body);
        let blob = SourceBytes::from_blob(blob_bytes);
        let dir = match Directory::parse_at(&blob, FlashOffset(0)).unwrap() {
            Directory::Psp(p) => p,
            _ => unreachable!(),
        };
        let entry = Entry::parse_psp(&blob, &dir, 0, RomSize::MIB_16, FlashOffset::ZERO).unwrap();
        match &entry.class {
            EntryClass::KeyStore(h) => {
                assert_eq!(&h.magic, PS1_MAGIC.as_bytes());
            }
            other => panic!("expected KeyStore, got {other:?}"),
        }
    }

    #[test]
    fn classifies_secondary_directory_pointer() {
        // Type 0x40 → SecondaryDirectoryPointer; body bytes are arbitrary —
        // the directory walker is what dereferences them. We give a 16-byte
        // placeholder so the body slice fits.
        let body = vec![0u8; 0x10];
        let blob_bytes = psp_dir_with_entry(0x40, &body);
        let blob = SourceBytes::from_blob(blob_bytes);
        let dir = match Directory::parse_at(&blob, FlashOffset(0)).unwrap() {
            Directory::Psp(p) => p,
            _ => unreachable!(),
        };
        let entry = Entry::parse_psp(&blob, &dir, 0, RomSize::MIB_16, FlashOffset::ZERO).unwrap();
        assert!(matches!(entry.class, EntryClass::SecondaryDirectoryPointer));
        assert_eq!(entry.get_bytes().len(), 0x10);
    }

    #[test]
    fn classifies_tertiary_directory_pointer() {
        let body = vec![0u8; 0x20];
        let blob_bytes = psp_dir_with_entry(0x48, &body);
        let blob = SourceBytes::from_blob(blob_bytes);
        let dir = match Directory::parse_at(&blob, FlashOffset(0)).unwrap() {
            Directory::Psp(p) => p,
            _ => unreachable!(),
        };
        let entry = Entry::parse_psp(&blob, &dir, 0, RomSize::MIB_16, FlashOffset::ZERO).unwrap();
        assert!(matches!(entry.class, EntryClass::TertiaryDirectoryPointer));
    }

    #[test]
    fn classifies_soft_fuse_chain_uses_record_as_body() {
        // Build a directory whose only entry has type 0x0B with size = 0xFFFFFFFF
        // (the §3.4 sentinel). The parser must NOT try to slice 0xFFFFFFFF
        // bytes out of the blob — it must return the entry record's source
        // bytes as the body.
        let mut entry = [0u8; PSP_ENTRY_SIZE];
        entry[0x00] = 0x0B;
        // size = 0xFFFFFFFF (the §3.4 sentinel)
        entry[0x04..0x08].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        // offset & rsv0: arbitrary fuse-mask payload
        entry[0x08..0x0C].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        entry[0x0C..0x10].copy_from_slice(&0xCAFE_BABEu32.to_le_bytes());

        let additional_info: u32 = (1u32 << 31) | (0b10u32 << 24);
        let mut blob_bytes = Vec::new();
        blob_bytes.extend_from_slice(b"$PSP");
        blob_bytes.extend_from_slice(&0u32.to_le_bytes());
        blob_bytes.extend_from_slice(&1u32.to_le_bytes());
        blob_bytes.extend_from_slice(&additional_info.to_le_bytes());
        blob_bytes.extend_from_slice(&entry);
        let original_record = entry.to_vec();
        let blob = SourceBytes::from_blob(blob_bytes);
        let dir = match Directory::parse_at(&blob, FlashOffset(0)).unwrap() {
            Directory::Psp(p) => p,
            _ => unreachable!(),
        };
        let parsed = Entry::parse_psp(&blob, &dir, 0, RomSize::MIB_16, FlashOffset::ZERO).unwrap();
        assert!(matches!(parsed.class, EntryClass::SoftFuseChain));
        // Body is the entry record itself — preserves byte-exact roundtrip.
        assert_eq!(parsed.get_bytes().as_bytes(), original_record.as_slice());
        assert_eq!(parsed.get_bytes().len(), PSP_ENTRY_SIZE);
        assert_eq!(
            parsed.get_bytes().offset(),
            FlashOffset(DIRECTORY_HEADER_SIZE as u64)
        );
    }

    #[test]
    fn classifies_microcode_only_for_bios_directory() {
        // BIOS dir + type 0x66 → Microcode.
        let body_off = (DIRECTORY_HEADER_SIZE + BIOS_ENTRY_SIZE) as u32;
        let size = 0x10u32;
        let additional_info: u32 = (1u32 << 31) | (0b10u32 << 24);
        let mut entry = [0u8; BIOS_ENTRY_SIZE];
        entry[0x00] = 0x66;
        entry[0x04..0x08].copy_from_slice(&size.to_le_bytes());
        entry[0x08..0x0C].copy_from_slice(&body_off.to_le_bytes());
        let entry_rsv0: u32 = 0b10u32 << 30;
        entry[0x0C..0x10].copy_from_slice(&entry_rsv0.to_le_bytes());
        // destination = unused sentinel
        entry[0x10..0x18].copy_from_slice(&[0xFF; 8]);

        let mut blob_bytes = Vec::new();
        blob_bytes.extend_from_slice(b"$BHD");
        blob_bytes.extend_from_slice(&0u32.to_le_bytes());
        blob_bytes.extend_from_slice(&1u32.to_le_bytes());
        blob_bytes.extend_from_slice(&additional_info.to_le_bytes());
        blob_bytes.extend_from_slice(&entry);
        blob_bytes.extend_from_slice(&[0xAA; 0x10]); // body
        let blob = SourceBytes::from_blob(blob_bytes);
        let dir = match Directory::parse_at(&blob, FlashOffset(0)).unwrap() {
            Directory::Bios(b) => b,
            _ => unreachable!(),
        };
        let parsed = Entry::parse_bios(&blob, &dir, 0, RomSize::MIB_16, FlashOffset::ZERO).unwrap();
        assert!(matches!(parsed.class, EntryClass::Microcode));
    }

    #[test]
    fn psp_directory_type_0x66_is_not_microcode() {
        // PSP dir + type 0x66: 0x66 is in NO_HDR but PSPTool only routes to
        // MicrocodeFile for BIOS dirs. Should fall to Plain.
        let body = vec![0xAA; 0x10];
        let blob_bytes = psp_dir_with_entry(0x66, &body);
        let blob = SourceBytes::from_blob(blob_bytes);
        let dir = match Directory::parse_at(&blob, FlashOffset(0)).unwrap() {
            Directory::Psp(p) => p,
            _ => unreachable!(),
        };
        let parsed = Entry::parse_psp(&blob, &dir, 0, RomSize::MIB_16, FlashOffset::ZERO).unwrap();
        assert!(matches!(parsed.class, EntryClass::Plain));
    }

    #[test]
    fn entry_index_out_of_range_errors() {
        let bytes = psptool_fixtures::micro::psp_directory().to_vec();
        let blob = SourceBytes::from_blob(bytes);
        let dir = match Directory::parse_at(&blob, FlashOffset(0)).unwrap() {
            Directory::Psp(p) => p,
            _ => unreachable!(),
        };
        let err = Entry::parse_psp(&blob, &dir, 5, RomSize::MIB_16, FlashOffset::ZERO).unwrap_err();
        assert!(matches!(err, ParseError::EntryIndexOutOfRange { .. }));
    }

    // ------------------------------------------------------------------
    // Roundtrip preservation: rebuilding the original bytes from Entry
    // sub-windows produces the original input.
    // ------------------------------------------------------------------

    #[test]
    fn entry_subwindows_roundtrip_to_original_bytes() {
        // Place the PSP fixture inside a larger buffer so absolute offsets are
        // exercised — the entry body's source must still byte-match the input.
        let dir_bytes = psptool_fixtures::micro::psp_directory();
        let mut buf = vec![0xCC; 0x4000];
        let dir_off = 0x1000usize;
        buf[dir_off..dir_off + dir_bytes.len()].copy_from_slice(dir_bytes);
        let original = buf.clone();
        let blob = SourceBytes::from_blob(buf);
        let dir = match Directory::parse_at(&blob, FlashOffset(dir_off as u64)).unwrap() {
            Directory::Psp(p) => p,
            _ => unreachable!(),
        };
        let entry = Entry::parse_psp(&blob, &dir, 0, RomSize::MIB_16, FlashOffset::ZERO).unwrap();

        // 1) The directory record's source is at the record's flash offset.
        let rec_src = entry.record.source();
        let rec_start = rec_src.offset().get() as usize;
        assert_eq!(
            rec_src.as_bytes(),
            &original[rec_start..rec_start + rec_src.len()]
        );
        // 2) The body source is at the resolved body flash offset.
        let body = entry.get_bytes();
        let body_start = body.offset().get() as usize;
        assert_eq!(
            body.as_bytes(),
            &original[body_start..body_start + body.len()]
        );
        // 3) Header magic verifies offset arithmetic across the whole image.
        assert_eq!(&original[dir_off..dir_off + 4], PSP_MAGIC.as_bytes());
    }

    #[test]
    fn header_entry_source_is_subwindow_of_body() {
        // The HeaderEntry source covers exactly the first 0x100 bytes of the
        // entry body — preserves byte-exact roundtrip even when the body has
        // a longer trailing region.
        let body_bytes = psptool_fixtures::micro::header_signed().to_vec();
        let original_first_0x100 = body_bytes[..0x100].to_vec();
        let body = SourceBytes::with_offset(body_bytes, FlashOffset(0xA7000));
        let h = HeaderEntry::parse(&body).unwrap();
        assert_eq!(h.source.len(), HEADER_FILE_LEN);
        assert_eq!(h.source.offset(), FlashOffset(0xA7000));
        assert_eq!(h.source.as_bytes(), original_first_0x100.as_slice());
    }
}
