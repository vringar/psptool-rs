//! Divergence pins for the zlib step of the `-X -u` extract path (#91).
//!
//! `extract_decompressed` is upstream's single-file `-X -u` accessor
//! `file.get_signed_bytes()` (`__main__.py:172`), which slices
//! `header + get_decrypted_decompressed_body()` to `0x100 + size_signed`
//! (`header_file.py:168-170`). At PSPTool `241629b` the decompressed body is
//! `_decrypted_decompressed_body()[0]` (`header_file.py:172-189`):
//!
//! ```python
//! output = self.get_decrypted_body()
//! if self.compressed:
//!     try:
//!         return zlib_decompress(output[:self.zlib_size]), True
//!     except Exception:
//!         ...print_warning("ZLIB decompression failed on file ...")
//!         return output, False
//! return output, True
//! ```
//!
//! and `utils.zlib_decompress` (`utils.py:241-254`) locates the stream with
//! `zlib_find_header` (`utils.py:218-234`, one magic at a time in `ZLIB_TYPES`
//! order `78DA, 789C, 785E, 7801`), inflates it with `zlib.decompress` (which
//! raises on a corrupt or truncated stream and ignores bytes after its end),
//! prepends the bytes before the magic, and returns its input unchanged when
//! no magic is found.
//!
//! Every expected value below is assembled from that algorithm over the
//! test's own input bytes — the header slice, the region, and
//! `FIXTURE_PLAINTEXT` (`build_fixtures.rs:352`) — never read back from the
//! `psptool-ops` side (R-CHAR-3). The live-oracle twin of these cases is
//! `crates/psptool-cli/tests/extract_oracle.rs`.

use psptool_core::directory::{DIRECTORY_HEADER_SIZE, PSP_ENTRY_SIZE};
use psptool_core::entry::HEADER_FILE_LEN;
use psptool_core::{Directory, Entry, EntryClass, FlashOffset, RomSize, SourceBytes};
use psptool_ops::extract_decompressed;

/// What the committed `header_compressed` fixture's zlib stream inflates to
/// (`PLAINTEXT`, `build_fixtures.rs:352`).
const FIXTURE_PLAINTEXT: &[u8] = b"hello, psptool-rs";

/// The committed `header_compressed` zlib stream: `zlib_size` bytes right after
/// its 0x100 header (`build_fixtures.rs`), magic `78 9C`.
fn fixture_stream() -> &'static [u8] {
    let fixture = psptool_fixtures::micro::header_compressed();
    let zlib_size =
        u32::from_le_bytes([fixture[0x54], fixture[0x55], fixture[0x56], fixture[0x57]]);
    &fixture[HEADER_FILE_LEN..HEADER_FILE_LEN + zlib_size as usize]
}

/// Bytes free of `0x78`, so no zlib magic appears by accident.
fn filler(len: usize) -> Vec<u8> {
    (0..len).map(|i| 0x20 + (i % 0x50) as u8).collect()
}

/// An unsigned, unencrypted, compressed HeaderFile whose data region is
/// `region` (`rom_size` = header + region, so the region is the whole body).
fn compressed_header_file(region: &[u8], zlib_size: u32, size_signed: u32) -> Vec<u8> {
    let mut h = [0u8; HEADER_FILE_LEN];
    h[0x10..0x14].copy_from_slice(b"$PS1");
    h[0x14..0x18].copy_from_slice(&size_signed.to_le_bytes());
    h[0x48..0x4C].copy_from_slice(&1u32.to_le_bytes()); // is_compressed
    h[0x50..0x54].copy_from_slice(&(FIXTURE_PLAINTEXT.len() as u32).to_le_bytes());
    h[0x54..0x58].copy_from_slice(&zlib_size.to_le_bytes());
    h[0x6C..0x70].copy_from_slice(&((HEADER_FILE_LEN + region.len()) as u32).to_le_bytes());
    let mut body = h.to_vec();
    body.extend_from_slice(region);
    body
}

/// Parse `body` as the single `PSP_FW_BOOT_LOADER` (HeaderFile-class) entry of
/// a `$PSP` directory addressed via mode `10`: the image and the entry.
fn header_entry(body: &[u8]) -> (SourceBytes, Entry) {
    let body_off = (DIRECTORY_HEADER_SIZE + PSP_ENTRY_SIZE) as u32;
    let mut record = [0u8; PSP_ENTRY_SIZE];
    record[0x00] = 0x01;
    record[0x04..0x08].copy_from_slice(&(body.len() as u32).to_le_bytes());
    record[0x08..0x0C].copy_from_slice(&body_off.to_le_bytes());
    record[0x0C..0x10].copy_from_slice(&(0b10u32 << 30).to_le_bytes());
    let mut blob = Vec::new();
    blob.extend_from_slice(b"$PSP");
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&1u32.to_le_bytes());
    blob.extend_from_slice(&((1u32 << 31) | (0b10u32 << 24)).to_le_bytes());
    blob.extend_from_slice(&record);
    blob.extend_from_slice(body);
    let blob = SourceBytes::from_blob(blob);
    let Ok(Directory::Psp(dir)) = Directory::parse_at(&blob, FlashOffset(0)) else {
        panic!("fixture is a $PSP directory");
    };
    let entry = Entry::parse_psp(&blob, &dir, 0, RomSize::MIB_16, FlashOffset::ZERO)
        .expect("synthetic entry parses");
    assert!(matches!(entry.class, EntryClass::Header(_)));
    (blob, entry)
}

/// `get_signed_bytes()` (`header_file.py:168-170`): `(header + ddb)[:0x100 +
/// size_signed]` — a Python slice, so a short `ddb` is not an error.
fn signed_bytes(file: &[u8], ddb: &[u8], size_signed: usize) -> Vec<u8> {
    let mut out = file[..HEADER_FILE_LEN].to_vec();
    out.extend_from_slice(&ddb[..size_signed.min(ddb.len())]);
    out
}

#[test]
fn magic_search_tries_each_magic_in_priority_order() {
    // A stray `78 5E` at 0x10 precedes the real `78 9C` stream at 0x40.
    // `zlib_find_header` tries `78 9C` before `78 5E` (`utils.py:211-213`,
    // `:224-232`) and finds the stream; the earliest-of-any scan finds the
    // stray magic and fails to inflate.
    let mut region = filler(0x40);
    region[0x10..0x12].copy_from_slice(&[0x78, 0x5E]);
    region.extend_from_slice(fixture_stream());
    let size_signed = 0x40 + FIXTURE_PLAINTEXT.len();
    let file = compressed_header_file(&region, region.len() as u32, size_signed as u32);

    // `uncompressed + decompressed` (`utils.py:248-252`).
    let mut ddb = region[..0x40].to_vec();
    ddb.extend_from_slice(FIXTURE_PLAINTEXT);
    let (blob, entry) = header_entry(&file);
    let got = extract_decompressed(&entry, &blob).ok();
    assert_eq!(got, Some(signed_bytes(&file, &ddb, size_signed)));
}

#[test]
fn truncated_stream_falls_back_to_the_still_compressed_body() {
    // `zlib_size` cuts the stream inside its adler32 trailer: `zlib.decompress`
    // raises "incomplete or truncated stream" (`utils.py:250`), so the body is
    // the untruncated `output` (`header_file.py:182-185`), not a partial
    // inflate.
    let region = fixture_stream().to_vec();
    let size_signed = FIXTURE_PLAINTEXT.len();
    let file = compressed_header_file(&region, region.len() as u32 - 2, size_signed as u32);

    let (blob, entry) = header_entry(&file);
    let got = extract_decompressed(&entry, &blob).ok();
    assert_eq!(got, Some(signed_bytes(&file, &region, size_signed)));
}

#[test]
fn fallback_body_shorter_than_size_signed_is_sliced_not_rejected() {
    // Real firmware signs the inflated length, which exceeds the compressed
    // fallback body; the Python slice (`header_file.py:170`) just stops at
    // the end of it.
    let region = fixture_stream().to_vec();
    let size_signed = 0x1000;
    let file = compressed_header_file(&region, region.len() as u32 - 2, size_signed as u32);

    let (blob, entry) = header_entry(&file);
    let got = extract_decompressed(&entry, &blob).ok();
    assert_eq!(got, Some(signed_bytes(&file, &region, size_signed)));
}

#[test]
fn corrupt_stream_falls_back_to_the_still_compressed_body() {
    // BTYPE = 11 (reserved) in the first deflate block header: corrupt.
    let mut region = fixture_stream().to_vec();
    region[2] = 0x07;
    let size_signed = 0x10;
    let file = compressed_header_file(&region, region.len() as u32, size_signed as u32);

    let (blob, entry) = header_entry(&file);
    let got = extract_decompressed(&entry, &blob).ok();
    assert_eq!(got, Some(signed_bytes(&file, &region, size_signed)));
}

#[test]
fn missing_magic_falls_back_to_the_still_compressed_body() {
    // No magic in `output[:zlib_size]`: `_decrypted_decompressed_body` raises
    // 'No zlib stream within the body' (`header_file.py:204-205`), so the body
    // is the untruncated `output`.
    let region = filler(0x40);
    let zlib_size = 0x20;
    let size_signed = 0x30;
    let file = compressed_header_file(&region, zlib_size as u32, size_signed as u32);

    let (blob, entry) = header_entry(&file);
    let got = extract_decompressed(&entry, &blob).ok();
    assert_eq!(got, Some(signed_bytes(&file, &region, size_signed)));
}

#[test]
fn zlib_size_past_the_data_region_falls_back_to_the_still_compressed_body() {
    // `self.zlib_size > len(output)` raises (`header_file.py:204-205`): the
    // slice no longer clamps, so the body is the untruncated `output`.
    let mut region = fixture_stream().to_vec();
    region.extend_from_slice(&[0xEE; 7]);
    let size_signed = FIXTURE_PLAINTEXT.len();
    let file = compressed_header_file(&region, 0x1000, size_signed as u32);

    let (blob, entry) = header_entry(&file);
    let got = extract_decompressed(&entry, &blob).ok();
    assert_eq!(got, Some(signed_bytes(&file, &region, size_signed)));
}

#[test]
fn prefixed_stream_control() {
    // Control: a well-formed stream after a magic-free prefix inflates under
    // both implementations.
    let mut region = filler(0x30);
    region.extend_from_slice(fixture_stream());
    let size_signed = 0x30 + FIXTURE_PLAINTEXT.len();
    let file = compressed_header_file(&region, region.len() as u32, size_signed as u32);

    let mut ddb = region[..0x30].to_vec();
    ddb.extend_from_slice(FIXTURE_PLAINTEXT);
    let (blob, entry) = header_entry(&file);
    let got = extract_decompressed(&entry, &blob).ok();
    assert_eq!(got, Some(signed_bytes(&file, &ddb, size_signed)));
}
