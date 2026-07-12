//! Divergence pins for `psptool-core/src/entry.rs` sub-parser dispatch vs the
//! reference PSPTool (`/tmp/psptool-ref/psptool`).
//!
//! When a typed sub-parser (`HeaderFile._parse`) rejects a body with
//! `File.ParseError`, upstream's `File.from_entry` DROPS the entry — it returns
//! `None`, `create_file_if_not_exists` returns `None`, and the directory loop
//! never appends it to `self.files` (the entry produces no listed file):
//!
//!   `file.py:259-272` (`File.from_entry`):
//!     ```
//!     try:
//!         ...
//!         elif entry.type not in cls.NO_HDR_ENTRY_TYPES + SECONDARY_...:
//!             return HeaderFile(*file_args)   # __init__ -> self._parse()
//!         ...
//!     except File.ParseError as e:
//!         psptool.ph.print_warning(...)
//!         return None                          # <-- entry DROPPED
//!     ```
//!   `file.py:52-55` (`create_file_if_not_exists`):
//!     `file = cls.from_entry(...); if file is not None: ...; return file`
//!   `directory.py:150-153`:
//!     `file = ...create_file_if_not_exists(self, entry)
//!      if file is not None: self.files.append(file)`   # None => not appended
//!
//! The Rust `classify` (`entry.rs:639-643`) instead calls `HeaderEntry::parse`
//! and, on ANY parse failure, `.unwrap_or(EntryClass::Plain)` — it KEEPS the
//! entry (as `Plain`, or, because the Rust sub-parser is weaker than upstream's
//! and does not even implement these semantic checks, as a live `Header`).
//! Either way the entry survives, where upstream drops it.
//!
//! The Rust "drop" mechanism is `Entry::parse_*` returning `Err` — the same
//! signal `resolve_body` already emits for the uncompressed-overrun drop that
//! `entry.md` maps to upstream's `File.ParseError -> return None`. So the
//! upstream-faithful outcome for a body upstream rejects with `File.ParseError`
//! is that `Entry::parse_psp` returns `Err` (the entry does not survive).
//!
//! Expected values are derived from upstream's own raise sites
//! (`header_file.py:63-64` and `header_file.py:126-128`), NOT copied from the
//! target (R-CHAR-3). Both are `#[ignore]`d with tracking #48; per R-DEFER-3 the
//! fixer flips them to plain `#[test]` when the fix lands.

use psptool_core::{Directory, Entry, EntryClass, FlashOffset, RomSize, SourceBytes};

// PSP directory layout constants (format-fixed): `directory.rs:42` / `:44`.
const DIRECTORY_HEADER_SIZE: usize = 0x10;
const PSP_ENTRY_SIZE: usize = 0x10;
const HEADER_FILE_LEN: usize = 0x100;

/// Build a single-entry `$PSP` directory whose one entry has the given `type`
/// and points at `body` (placed immediately after the entry table). Address
/// mode is `10` (dir-relative) at both directory and entry level so the body
/// resolves to `dir_base + (HEADER + ENTRY_SIZE)`.
fn psp_dir_with_entry(entry_type: u8, body: &[u8]) -> Vec<u8> {
    let body_off = (DIRECTORY_HEADER_SIZE + PSP_ENTRY_SIZE) as u32;
    let size = body.len() as u32;
    // additional_info: v1 (bit 31 = 1), directory mode bits[25:24] = 10.
    let additional_info = (1u32 << 31) | (0b10u32 << 24);
    let mut entry = [0u8; PSP_ENTRY_SIZE];
    entry[0x00] = entry_type;
    entry[0x04..0x08].copy_from_slice(&size.to_le_bytes());
    entry[0x08..0x0C].copy_from_slice(&body_off.to_le_bytes());
    // Entry-level mode 10 (rsv0[31:30] = 10) so resolve picks dir_base + offset.
    let entry_rsv0: u32 = 0b10u32 << 30;
    entry[0x0C..0x10].copy_from_slice(&entry_rsv0.to_le_bytes());

    let mut out = Vec::new();
    out.extend_from_slice(b"$PSP");
    out.extend_from_slice(&0u32.to_le_bytes()); // checksum (unused at this layer)
    out.extend_from_slice(&1u32.to_le_bytes()); // count
    out.extend_from_slice(&additional_info.to_le_bytes());
    out.extend_from_slice(&entry);
    out.extend_from_slice(body);
    out
}

/// A minimal but otherwise-valid PSP signed-header body (>= 0x100 bytes) with
/// `$PS1` magic and a documented `signed` value. Callers mutate individual
/// fields to trip a specific upstream `File.ParseError`.
fn valid_header_body() -> Vec<u8> {
    let mut body = vec![0u8; 0x210];
    body[0x10..0x14].copy_from_slice(b"$PS1"); // magic @0x10
    body[0x30..0x34].copy_from_slice(&1u32.to_le_bytes()); // signed = 1 (documented)
    body[0x34..0x38].copy_from_slice(&0u32.to_le_bytes()); // signature_type = 0
    body[0x6C..0x70].copy_from_slice(&0x210u32.to_le_bytes()); // rom_size = total
    body
}

/// Divergence: a header-type entry whose body sets BOTH the sha256 and sha384
/// checksum bits trips upstream's `File.ParseError`, so upstream DROPS the entry
/// (`from_entry` returns `None`). The Rust keeps it as a live entry.
///
/// Upstream raise site (`header_file.py:60-64`):
///   ```
///   self.has_sha256_checksum = self.bitfield & 0b01
///   self.has_sha384_checksum = self.bitfield & 0b10
///   if self.has_sha256_checksum and self.has_sha384_checksum:
///       raise File.ParseError('File should not have both sha256 and sha384 ...')
///   ```
/// `bitfield` is read BIG-endian from `header[0x58:0x5c]` (`header_file.py:54`),
/// so the low two bits live in byte `0x5b`; setting `body[0x5b] = 0b11` sets
/// both checksum bits. Reaching this raise (line 63) happens BEFORE any other
/// raise in `_parse`, so it fires regardless of the other fields.
///
/// Upstream returns `None` from `from_entry` (`file.py:270-272`) => the entry is
/// never appended to `self.files` (`directory.py:150-153`). The Rust
/// `HeaderEntry::parse` does not implement this check at all and returns
/// `Ok`, so `classify` yields `EntryClass::Header` and `Entry::parse_psp`
/// returns `Ok` — the entry survives.
///
/// Tracking: #48
#[test]
#[ignore = "divergence: sub-parser File.ParseError drops entry upstream, Rust keeps it; tracking #48"]
fn header_with_both_sha_bits_is_dropped_like_upstream() {
    let mut body = valid_header_body();
    // Set both sha256 (bit0) and sha384 (bit1) of the big-endian bitfield.
    body[0x5B] = 0b0000_0011;

    let blob_bytes = psp_dir_with_entry(0x01, &body); // 0x01 = PSP_FW_BOOT_LOADER (header type)
    let blob = SourceBytes::from_blob(blob_bytes);
    let dir = match Directory::parse_at(&blob, FlashOffset(0)).unwrap() {
        Directory::Psp(p) => p,
        other => panic!("expected PSP directory, got {other:?}"),
    };

    let result = Entry::parse_psp(&blob, &dir, 0, RomSize::MIB_16, FlashOffset::ZERO);

    // Upstream drops the entry (from_entry -> None; header_file.py:63-64 raises
    // File.ParseError). The Rust-faithful "drop" is an Err from parse_psp; any
    // Ok(..) (Header or Plain) means the entry wrongly survives.
    assert!(
        result.is_err(),
        "upstream drops this entry (both-sha-bits => File.ParseError \
         header_file.py:63-64 => from_entry returns None); Rust kept it as {:?}",
        result.as_ref().map(|e| &e.class)
    );
}

/// Divergence: a header-type entry whose `signed` field (`header[0x30:0x34]`,
/// little-endian) holds an UNDOCUMENTED value trips upstream's `File.ParseError`
/// via the `is_signed` property, evaluated during `_parse`. Upstream DROPS it.
///
/// Upstream raise site (`header_file.py:124-129`, reached from `_parse` at
/// `header_file.py:77` — `if self.is_signed:`):
///   ```
///   @property
///   def is_signed(self) -> bool:
///       signed = int.from_bytes(self._signed.get_bytes(), 'little')
///       if signed not in {0, 1, 0xffff0000}:
///           raise self.ParseError(f'Did not expect signed to be 0x{signed:x}')
///       return signed != 0
///   ```
/// A `signed` value of `0x2` is not in `{0, 1, 0xffff0000}` => `File.ParseError`
/// => `from_entry` returns `None` (`file.py:270-272`) => entry dropped
/// (`directory.py:150-153`). The Rust `HeaderEntry::parse` reads `signed_raw`
/// but never validates it in the classify path, so the entry survives as
/// `EntryClass::Header`.
///
/// Tracking: #48
#[test]
#[ignore = "divergence: sub-parser File.ParseError drops entry upstream, Rust keeps it; tracking #48"]
fn header_with_undocumented_signed_value_is_dropped_like_upstream() {
    let mut body = valid_header_body();
    // signed = 0x2: nonzero (so is_signed is consulted) but undocumented =>
    // upstream raises File.ParseError before returning. sha bits left 0 so the
    // both-sha raise (line 63) does not pre-empt this path.
    body[0x30..0x34].copy_from_slice(&0x2u32.to_le_bytes());
    assert!(body.len() >= HEADER_FILE_LEN);

    let blob_bytes = psp_dir_with_entry(0x01, &body);
    let blob = SourceBytes::from_blob(blob_bytes);
    let dir = match Directory::parse_at(&blob, FlashOffset(0)).unwrap() {
        Directory::Psp(p) => p,
        other => panic!("expected PSP directory, got {other:?}"),
    };

    let result = Entry::parse_psp(&blob, &dir, 0, RomSize::MIB_16, FlashOffset::ZERO);

    assert!(
        result.is_err(),
        "upstream drops this entry (undocumented `signed` => File.ParseError \
         header_file.py:126-128 => from_entry returns None); Rust kept it as {:?}",
        result.as_ref().map(|e| &e.class)
    );
}

/// Control (regression guard, NOT a divergence pin): a WELL-FORMED header entry
/// — documented `signed`, at most one checksum bit — must survive as a live
/// `Header` under both upstream and the target. Guards against a future "fix"
/// that over-drops valid headers. Left un-ignored on purpose.
#[test]
fn well_formed_header_survives_as_header() {
    let mut body = valid_header_body();
    // Exactly one checksum bit (sha256) set — upstream does NOT raise.
    body[0x5B] = 0b0000_0001;

    let blob_bytes = psp_dir_with_entry(0x01, &body);
    let blob = SourceBytes::from_blob(blob_bytes);
    let dir = match Directory::parse_at(&blob, FlashOffset(0)).unwrap() {
        Directory::Psp(p) => p,
        other => panic!("expected PSP directory, got {other:?}"),
    };

    let entry = Entry::parse_psp(&blob, &dir, 0, RomSize::MIB_16, FlashOffset::ZERO)
        .expect("a well-formed header entry must survive");
    assert!(
        matches!(entry.class, EntryClass::Header(_)),
        "well-formed header must classify as Header, got {:?}",
        entry.class
    );
}
