//! Robustness pins for HeaderFile body decoding (`body.rs`) on crafted,
//! untrusted images. Synthetic bytes only.

use std::io::Write;

use flate2::Compression;
use flate2::write::ZlibEncoder;
use psptool_core::body::{CertifyingKeys, Ikek, ZLIB_MAGICS};
use psptool_core::{Directory, Entry, FlashOffset, RomSize, SourceBytes};

const HEADER_FILE_LEN: usize = 0x100;

/// Severity: memory exhaustion (decompression bomb).
///
/// `zlib_decompress_strict` (`body.rs:1207-1230`) grows its output until the
/// stream ends, with no ceiling: neither the header's `size_uncompressed` nor
/// any absolute cap bounds it. Deflate reaches ~1000:1, so a 16 MiB image
/// carrying one compressed HeaderFile inflates to ~16 GiB. The decode runs for
/// every compressed HeaderFile on the default `ls` path
/// (`list.rs:120` -> `Entry::decode_verification` -> `decode_best_effort`),
/// in `verify`, in `extract -u`, and for compressed key stores inside
/// `CertifyingKeys::from_blob` — and once per directory entry, so entries
/// aliasing one bomb multiply the cost.
///
/// Here a 64 KiB stream declares `size_uncompressed = 0x1000` and inflates to
/// 80 MiB. Expected: inflation is capped (upstream ignores `size_uncompressed`), so the
/// decode fails and falls back to the compressed bytes instead of
/// materialising the whole stream.
#[test]
fn robust_body_zlib_bomb_is_bounded_by_header() {
    const DECLARED: u32 = 0x1000;
    const INFLATED: usize = 80 << 20;
    const CAP: usize = 64 << 20;

    let mut enc = ZlibEncoder::new(Vec::new(), Compression::best());
    let zeros = vec![0u8; 1 << 20];
    for _ in 0..INFLATED / zeros.len() {
        enc.write_all(&zeros).expect("compress");
    }
    let stream = enc.finish().expect("finish stream");
    // The decoder must pick the stream at offset 0, not a false magic at the
    // 0x100 fast path (`entry.rs:623`).
    assert!(
        !ZLIB_MAGICS
            .iter()
            .any(|m| stream.get(0x100..0x102) == Some(m.as_slice())),
        "fixture: stream carries a zlib magic at 0x100"
    );

    // Unsigned, unencrypted, compressed HeaderFile: header || stream.
    let mut file = vec![0u8; HEADER_FILE_LEN];
    file[0x10..0x14].copy_from_slice(b"$PS1");
    file[0x48..0x4C].copy_from_slice(&1u32.to_le_bytes()); // is_compressed
    file[0x50..0x54].copy_from_slice(&DECLARED.to_le_bytes()); // size_uncompressed
    file[0x54..0x58].copy_from_slice(&(stream.len() as u32).to_le_bytes()); // zlib_size
    file.extend_from_slice(&stream);

    // `$PSP` (mode 01) with one type-0x01 entry pointing at the file.
    let dir_at = 0x1000usize;
    let file_at = 0x2000usize;
    let mut image = vec![0u8; file_at + file.len()];
    image[dir_at..dir_at + 4].copy_from_slice(b"$PSP");
    image[dir_at + 8..dir_at + 12].copy_from_slice(&1u32.to_le_bytes());
    image[dir_at + 12..dir_at + 16].copy_from_slice(&0x2000_0000u32.to_le_bytes());
    image[dir_at + 0x10] = 0x01;
    image[dir_at + 0x14..dir_at + 0x18].copy_from_slice(&(file.len() as u32).to_le_bytes());
    image[dir_at + 0x18..dir_at + 0x1C].copy_from_slice(&(file_at as u32).to_le_bytes());
    image[file_at..].copy_from_slice(&file);

    let blob = SourceBytes::from_blob(image);
    let Directory::Psp(dir) = Directory::parse_at(&blob, FlashOffset(dir_at as u64)).unwrap()
    else {
        panic!("fixture: not a $PSP directory");
    };
    let entry = Entry::parse_psp(&blob, &dir, 0, RomSize::MIB_8, FlashOffset::ZERO).unwrap();
    let header = entry.class.header().expect("fixture: HeaderFile class");
    let window = entry.header_file_window(&blob).expect("HeaderFile window");

    // The `ls` path runs this decode for the entry; it must not panic either.
    let _ = entry.decode_verification(&blob, &CertifyingKeys::default(), Ikek::ZenPlus);

    let decoded = header
        .decode_best_effort(window.as_bytes(), Ikek::ZenPlus)
        .map(|(body, _)| body.len());
    if let Ok(len) = decoded {
        assert!(
            len <= CAP,
            "a {}-byte zlib stream declaring size_uncompressed {DECLARED:#x} was \
             inflated to {len} bytes (cap {CAP})",
            stream.len()
        );
    }
}
