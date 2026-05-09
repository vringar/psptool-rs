//! Regenerate the committed micro-fixture binaries under
//! `crates/psptool-fixtures/data/`.
//!
//! The committed `.bin` files are the source of truth at runtime — the
//! library exposes them via `include_bytes!`. This example exists so the
//! construction logic is reproducible and auditable.
//!
//! Run from the workspace root:
//!
//! ```text
//! cargo run --example build_fixtures -p psptool-fixtures
//! ```
//!
//! Each fixture matches the spec at `docs/firmware-layout.md`. Section
//! references in the comments below point at that document.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use flate2::Compression;
use flate2::write::ZlibEncoder;

fn main() -> std::io::Result<()> {
    let out_dir = data_dir();
    fs::create_dir_all(&out_dir)?;

    write(&out_dir, "fet.bin", &build_fet())?;
    write(&out_dir, "psp_directory.bin", &build_psp_directory())?;
    write(&out_dir, "bhd_directory.bin", &build_bhd_directory())?;
    write(&out_dir, "combo_psp.bin", &build_combo_psp())?;
    write(&out_dir, "header_signed.bin", &build_header_signed())?;
    write(&out_dir, "header_encrypted.bin", &build_header_encrypted())?;
    write(
        &out_dir,
        "header_compressed.bin",
        &build_header_compressed(),
    )?;
    write(&out_dir, "pubkey_v1.bin", &build_pubkey_v1())?;

    println!("wrote 8 fixtures to {}", out_dir.display());
    Ok(())
}

fn data_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR points at the crate root, regardless of where the
    // example is invoked from.
    Path::new(env!("CARGO_MANIFEST_DIR")).join("data")
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    let path = dir.join(name);
    fs::write(&path, bytes)?;
    println!("  {} ({} bytes)", name, bytes.len());
    Ok(())
}

// ---------------------------------------------------------------------------
// FET (§1.2)
// ---------------------------------------------------------------------------

fn build_fet() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[0xAA, 0x55, 0xAA, 0x55]); // magic
    out.extend_from_slice(&0x0000_0000u32.to_le_bytes()); // slot 0: reserved-zero
    out.extend_from_slice(&0xFFFF_FFFEu32.to_le_bytes()); // slot 1: skip-sentinel
    // Terminator: four 0xFFFFFFFF dwords (16 bytes).
    out.extend_from_slice(&[0xFF; 16]);
    out
}

// ---------------------------------------------------------------------------
// Fletcher-32 (§2.4)
// ---------------------------------------------------------------------------

/// Fletcher-32 over a directory body, exactly per `docs/firmware-layout.md`
/// §2.4 and `psptool/utils.py:fletcher32`.
///
/// Iterates 16-bit little-endian words; folds carry every 360 words and
/// twice at finalisation.
fn fletcher32(data: &[u8]) -> u32 {
    let mut c0: u32 = 0xFFFF;
    let mut c1: u32 = 0xFFFF;
    let mut iter = data.chunks_exact(2);
    for (i, chunk) in (&mut iter).enumerate() {
        let w = u16::from_le_bytes([chunk[0], chunk[1]]) as u32;
        c0 = c0.wrapping_add(w);
        c1 = c1.wrapping_add(c0);
        if i % 360 == 0 {
            c0 = (c0 & 0xFFFF) + (c0 >> 16);
            c1 = (c1 & 0xFFFF) + (c1 >> 16);
        }
    }
    // Trailing odd byte (none for our directories — they're 4-byte aligned).
    if !iter.remainder().is_empty() {
        let w = iter.remainder()[0] as u32;
        c0 = c0.wrapping_add(w);
        c1 = c1.wrapping_add(c0);
    }
    c0 = (c0 & 0xFFFF) + (c0 >> 16);
    c0 = (c0 & 0xFFFF) + (c0 >> 16);
    c1 = (c1 & 0xFFFF) + (c1 >> 16);
    c1 = (c1 & 0xFFFF) + (c1 >> 16);
    (c1 << 16) | c0
}

// ---------------------------------------------------------------------------
// $PSP directory (§2.1, §3.1)
// ---------------------------------------------------------------------------

fn build_psp_directory() -> Vec<u8> {
    // address_mode = 10 (offset from directory header) so the fixture is
    // self-contained — no ROM-relative arithmetic needed.
    // additional_info bit layout (§2.1): v1 (bit 31 = 0), bits [25:24] = mode.
    let additional_info: u32 = 0b10 << 24;

    // One entry: type 0x21 (WRAPPED_IKEK, NO_HDR), 16-byte body sitting just
    // after the entry record at directory-relative offset 0x20.
    let entry: [u8; 16] = {
        let mut e = [0u8; 16];
        e[0x00] = 0x21; // type
        e[0x01] = 0x00; // subprogram
        // flags @0x02..0x04 = 0
        e[0x04..0x08].copy_from_slice(&0x10u32.to_le_bytes()); // size
        e[0x08..0x0C].copy_from_slice(&0x20u32.to_le_bytes()); // offset (mode 10)
        // rsv0 = 0
        e
    };
    // 16-byte deterministic body — content does not matter for the parser
    // branch test; we just need to prove the offset/size resolve to bytes.
    let body: [u8; 16] = *b"WRAPPED-IKEK\x00\x00\x00\x00";

    // Build the header with a placeholder checksum, compute the checksum
    // over [0x08..end-of-directory], then patch it in.
    let mut out = Vec::with_capacity(0x10 + entry.len() + body.len());
    out.extend_from_slice(b"$PSP"); // magic
    out.extend_from_slice(&0u32.to_le_bytes()); // checksum placeholder
    out.extend_from_slice(&1u32.to_le_bytes()); // count
    out.extend_from_slice(&additional_info.to_le_bytes());
    out.extend_from_slice(&entry);

    let cksum = fletcher32(&out[0x08..]); // body-only, header[0x00..0x08] excluded
    out[0x04..0x08].copy_from_slice(&cksum.to_le_bytes());

    // Body comes after the directory; it is NOT covered by the checksum.
    out.extend_from_slice(&body);
    out
}

// ---------------------------------------------------------------------------
// $BHD directory (§2.1, §3.2)
// ---------------------------------------------------------------------------

fn build_bhd_directory() -> Vec<u8> {
    let additional_info: u32 = 0b10 << 24;
    // BIOS entry is 24 bytes; type 0x62 is a NO_HDR BIOS type.
    let entry: [u8; 24] = {
        let mut e = [0u8; 24];
        e[0x00] = 0x62; // type
        e[0x01] = 0x00; // region_type
        // flags @0x02..0x04 = 0
        e[0x04..0x08].copy_from_slice(&0x10u32.to_le_bytes()); // size
        e[0x08..0x0C].copy_from_slice(&0x28u32.to_le_bytes()); // offset = 0x10 hdr + 0x18 entry
        // rsv0 = 0
        // destination = 0xFFFFFFFFFFFFFFFF (unused sentinel, §3.2)
        e[0x10..0x18].copy_from_slice(&[0xFF; 8]);
        e
    };
    let body: [u8; 16] = *b"BHD-BODY\x00\x00\x00\x00\x00\x00\x00\x00";

    let mut out = Vec::with_capacity(0x10 + entry.len() + body.len());
    out.extend_from_slice(b"$BHD");
    out.extend_from_slice(&0u32.to_le_bytes()); // checksum placeholder
    out.extend_from_slice(&1u32.to_le_bytes()); // count
    out.extend_from_slice(&additional_info.to_le_bytes());
    out.extend_from_slice(&entry);

    let cksum = fletcher32(&out[0x08..]);
    out[0x04..0x08].copy_from_slice(&cksum.to_le_bytes());

    out.extend_from_slice(&body);
    out
}

// ---------------------------------------------------------------------------
// 2PSP combo directory (§2.3)
// ---------------------------------------------------------------------------

fn build_combo_psp() -> Vec<u8> {
    // Combo header layout: magic | cksum | count | lookup_mode | 16B reserved
    // followed by `count` 16-byte combo entries.
    let mut out = Vec::with_capacity(0x20 + 0x10);
    out.extend_from_slice(b"2PSP"); // magic
    out.extend_from_slice(&0u32.to_le_bytes()); // checksum placeholder
    out.extend_from_slice(&1u32.to_le_bytes()); // count = 1
    out.extend_from_slice(&0u32.to_le_bytes()); // lookup_mode = 0
    out.extend_from_slice(&[0u8; 16]); // 16-byte reserved (asserted zero)

    // Combo entry: flags | psp_generation | pointer | reserved
    out.extend_from_slice(&0u32.to_le_bytes()); // flags = 0
    // Zen 2 generation tag from §2.3. Stored as a little-endian dword
    // (0xBC0B0500 -> bytes 00 05 0B BC).
    out.extend_from_slice(&0xBC0B_0500u32.to_le_bytes()); // psp_generation
    // Pointer to a $PSP directory. Per §1.3 a raw pointer is x86-physical
    // when > 0xFF000000 in a 16 MiB ROM, else a flash offset. Use a flash
    // offset to keep the fixture self-describing.
    out.extend_from_slice(&0x0000_1000u32.to_le_bytes()); // pointer
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved

    let cksum = fletcher32(&out[0x08..]);
    out[0x04..0x08].copy_from_slice(&cksum.to_le_bytes());

    out
}

// ---------------------------------------------------------------------------
// HeaderFile: signed (§4)
// ---------------------------------------------------------------------------

const HEADER_LEN: usize = 0x100;
const SIG_RSA2048: usize = 0x100;
const BODY_LEN: usize = 0x10;

/// Build a HeaderFile header (0x100 bytes) with the given flag fields.
/// Fields not specified are zeroed; field offsets follow §4.
struct HeaderBuilder {
    is_encrypted: u32,
    is_signed: u32,
    signature_type: u32, // 0 = RSA-2048, 2 = RSA-4096
    is_compressed: u32,
    rom_size: u32,
    size_signed: u32,
    size_uncompressed: u32,
    zlib_size: u32,
    iv: [u8; 16],
    wrapped_key: [u8; 16],
}

impl HeaderBuilder {
    fn new() -> Self {
        Self {
            is_encrypted: 0,
            is_signed: 0,
            signature_type: 0,
            is_compressed: 0,
            rom_size: 0,
            size_signed: 0,
            size_uncompressed: 0,
            zlib_size: 0,
            iv: [0u8; 16],
            wrapped_key: [0u8; 16],
        }
    }

    fn build(self) -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        // 0x000..0x010: reserved (zero).
        // Magic at 0x010 = b'$PS1'.
        h[0x010..0x014].copy_from_slice(b"$PS1");
        h[0x014..0x018].copy_from_slice(&self.size_signed.to_le_bytes());
        h[0x018..0x01C].copy_from_slice(&self.is_encrypted.to_le_bytes());
        // 0x01C reserved.
        h[0x020..0x030].copy_from_slice(&self.iv);
        h[0x030..0x034].copy_from_slice(&self.is_signed.to_le_bytes());
        h[0x034..0x038].copy_from_slice(&self.signature_type.to_le_bytes());
        // signature_fingerprint @0x038..0x048 — deterministic byte pattern so
        // the fixture is reproducible (real images carry a 16-byte hash).
        for (i, b) in h[0x038..0x048].iter_mut().enumerate() {
            *b = 0xA0 + i as u8;
        }
        h[0x048..0x04C].copy_from_slice(&self.is_compressed.to_le_bytes());
        // 0x04C reserved.
        h[0x050..0x054].copy_from_slice(&self.size_uncompressed.to_le_bytes());
        h[0x054..0x058].copy_from_slice(&self.zlib_size.to_le_bytes());
        // bitfield @0x058 = 0 (no sha checksum), version @0x05C = 0 — both fine.
        // load_addr @0x068 = 0.
        h[0x06C..0x070].copy_from_slice(&self.rom_size.to_le_bytes());
        h[0x080..0x090].copy_from_slice(&self.wrapped_key);
        // sha_checksum @0x0D0..0x100 = zeros.
        h
    }
}

fn build_header_signed() -> Vec<u8> {
    let total = HEADER_LEN + BODY_LEN + SIG_RSA2048;
    // size_signed covers `header || body` per §4.1.
    let header = HeaderBuilder {
        is_signed: 1,
        signature_type: 0, // RSA-2048
        rom_size: total as u32,
        size_signed: (HEADER_LEN + BODY_LEN) as u32,
        ..HeaderBuilder::new()
    }
    .build();

    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&header);
    // Body: deterministic ASCII so a hex-dump shows the boundary clearly.
    out.extend_from_slice(b"SIGNED-FIXTURE\x00\x00");
    debug_assert_eq!(out.len(), HEADER_LEN + BODY_LEN);
    // Signature placeholder — we do not validate signatures in this fixture.
    out.extend(std::iter::repeat_n(0xBBu8, SIG_RSA2048));
    out
}

// ---------------------------------------------------------------------------
// HeaderFile: encrypted (§4 + §5)
// ---------------------------------------------------------------------------

fn build_header_encrypted() -> Vec<u8> {
    let total = HEADER_LEN + BODY_LEN + SIG_RSA2048;
    // Non-zero IV and wrapped_key per §5 ("must be non-zero — PSPTool
    // asserts"). We do not actually AES-encrypt the body — the fixture
    // tests the structural parse path; downstream tests can stub the IKEK
    // when they want to round-trip the encryption logic.
    let mut iv = [0u8; 16];
    for (i, b) in iv.iter_mut().enumerate() {
        *b = 0x10 + i as u8;
    }
    let mut wk = [0u8; 16];
    for (i, b) in wk.iter_mut().enumerate() {
        *b = 0xC0 + i as u8;
    }

    let header = HeaderBuilder {
        is_encrypted: 1,
        is_signed: 1,
        signature_type: 0,
        rom_size: total as u32,
        size_signed: (HEADER_LEN + BODY_LEN) as u32,
        iv,
        wrapped_key: wk,
        ..HeaderBuilder::new()
    }
    .build();

    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&header);
    // Body is "ciphertext" filler.
    out.extend(std::iter::repeat_n(0xDDu8, BODY_LEN));
    out.extend(std::iter::repeat_n(0xBBu8, SIG_RSA2048));
    out
}

// ---------------------------------------------------------------------------
// HeaderFile: compressed (§4 + §6)
// ---------------------------------------------------------------------------

fn build_header_compressed() -> Vec<u8> {
    // Real zlib stream over a deterministic plaintext — exercises the
    // §6 first-0x500-bytes magic search starting at body offset 0.
    const PLAINTEXT: &[u8] = b"hello, psptool-rs";
    let zlib_stream = zlib_compress(PLAINTEXT);
    let body_len = zlib_stream.len();
    let total = HEADER_LEN + body_len + SIG_RSA2048;

    let header = HeaderBuilder {
        is_compressed: 1,
        is_signed: 1,
        signature_type: 0,
        rom_size: total as u32,
        size_signed: (HEADER_LEN + body_len) as u32,
        size_uncompressed: PLAINTEXT.len() as u32,
        zlib_size: body_len as u32,
        ..HeaderBuilder::new()
    }
    .build();

    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&header);
    out.extend_from_slice(&zlib_stream);
    out.extend(std::iter::repeat_n(0xBBu8, SIG_RSA2048));
    out
}

fn zlib_compress(input: &[u8]) -> Vec<u8> {
    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
    e.write_all(input).expect("zlib write");
    e.finish().expect("zlib finish")
}

// ---------------------------------------------------------------------------
// PubkeyFile (§7.1)
// ---------------------------------------------------------------------------

fn build_pubkey_v1() -> Vec<u8> {
    const PUBEXP_BITS: u32 = 2048;
    const MODULUS_BITS: u32 = 2048;
    let pubexp_size = (PUBEXP_BITS / 8) as usize;
    let modulus_size = (MODULUS_BITS / 8) as usize;
    let total = 0x40 + pubexp_size + modulus_size;

    let mut out = vec![0u8; total];
    out[0x00..0x04].copy_from_slice(&1u32.to_le_bytes()); // version

    // key_id: deterministic 16-byte fingerprint.
    for (i, b) in out[0x04..0x14].iter_mut().enumerate() {
        *b = 0xE0 + i as u8;
    }
    // certifying_id: another deterministic 16-byte fingerprint.
    for (i, b) in out[0x14..0x24].iter_mut().enumerate() {
        *b = 0x70 + i as u8;
    }

    out[0x24..0x28].copy_from_slice(&0u32.to_le_bytes()); // key_usage = AMD_CODE_SIGN
    // reserved @0x28..0x2A = 0.
    // security_features @0x2A..0x2C = 0.
    // reserved @0x2C..0x38 = 0.
    out[0x38..0x3C].copy_from_slice(&PUBEXP_BITS.to_le_bytes());
    out[0x3C..0x40].copy_from_slice(&MODULUS_BITS.to_le_bytes());

    // pubexp: 0x10001 little-endian, rest zero (§7.1 says high bytes are zero).
    out[0x40..0x44].copy_from_slice(&0x0001_0001u32.to_le_bytes());
    // modulus: deterministic byte pattern so tests can match it byte-exact.
    let modulus_off = 0x40 + pubexp_size;
    for (i, b) in out[modulus_off..modulus_off + modulus_size]
        .iter_mut()
        .enumerate()
    {
        *b = (i & 0xFF) as u8;
    }
    // signature_size = total - 0x40 - pubexp_size - modulus_size = 0 — none.
    out
}
