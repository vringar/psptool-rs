//! `list` operations — `psp.ls()` / `psp.ls(verbose=True)` / `psp.ls_json()`
//! ports of the reference Python tool.
//!
//! Three functions take a [`RomListing`] (the inputs the parser already
//! produces — `SourceBytes`, `RomSize`, [`Fet`], the [`DirectoryRef`] list
//! returned by [`walk_directories`], and a ROM index) and return owned
//! output: tabular `String`s for the textual variants and a
//! [`serde_json::Value`] for the JSON variant. No I/O.
//!
//! Output shape mirrors the reference:
//! * `list_default` — one ROM-summary table, then per-directory:
//!   directory header table + entry table with the fixed column set.
//! * `list_verbose` — same as default plus the `flags / MD5 / size_signed /
//!   size_full / size_packed / load_addr` extension columns.
//!
//! [`RomListing::sparse`] selects between the richer default rendering of the
//! two verbose cells PSPTool narrows and the upstream-exact rendering
//! (`flags` = `''` per `psptool.py:179`; `MD5` = `md5()[:4].upper()` per
//! `psptool.py:180`). It defaults to `false` (richer); the CLI wires it behind
//! `--sparse` / `PSPTOOL_LS_SPARSE`. The default rendering is unchanged.
//! * `list_json(verbose)` — array of directory objects with
//!   `directory / address / magic / secondaryAddresses / entries[]`. Each
//!   entry mirrors PSPTool's `ls_files_dict` keys; `verbose=true` adds the
//!   extra `flags` and `load_addr` fields. Every HeaderFile-class entry
//!   carries `decodeVerified` / `decodeVerificationMethod` (`psptool.py:267-271`
//!   at PSPTool `241629b`) regardless of `verbose`.
//!
//! Signature and checksum outcomes in `File Info` / `info` come from one
//! [`Entry::decode_verification`] pass per entry against the image-wide
//! [`CertifyingKeys`] (upstream's single `CertificateTree`, built over every
//! ROM of the blob). The AGESA version is the one field the parser does not
//! expose yet; it is emitted as the placeholder `AGESA_UNKNOWN` (REQ-12, #75).
//!
//! ## REQ status (per `.design/psptool-ops/list.md`)
//!
//! | REQ | Status | Evidence |
//! |---|---|---|
//! | REQ-1 | SHIPPED | `render_text` `list.rs:177` composes ROM/header/entry tables per `psptool.py:68`/`:79`/`:103`; consumer `psptool-cli/src/cmds/list.rs:53`/`:55` |
//! | REQ-2 | SHIPPED | `list_json` `list.rs:148` emits directory objects per `psptool.py:208`; consumer `psptool-cli/src/cmds/list.rs:49` |
//! | REQ-3 | SHIPPED | `entry_to_json` `list.rs:424` inserts `index`/`address`/`size`/`sectionType` per `psptool.py:246`; consumer `psptool-cli/src/cmds/list.rs:49` |
//! | REQ-4 | SHIPPED | `readable_type` (`types.rs:196`) called `list.rs:316`/`:439` per `psptool.py:173`/`:250`; consumer `psptool-cli/src/cmds/list.rs:49` |
//! | REQ-5 | SHIPPED | `entries_for_directory` `list.rs:488` returns empty for combo per `psptool.py:95`; consumer `psptool-cli/src/cmds/list.rs:55` |
//! | REQ-6 | SHIPPED | self-oracle (differential-tolerated key). `magic_id_string` `list.rs:551` + `version_string` `list.rs:570` per `psptool.py:176`/`:177`; consumer `psptool-cli/src/cmds/list.rs:49` |
//! | REQ-7 | SHIPPED | `info_list` `list.rs:594` emits `compressed`, the signature outcome, `encrypted`, the checksum outcome, pubkey usage and `destination(..)` — no bare `signed`/`sha256`/`sha384` token — per `psptool.py:113-140`; HeaderFile rows agree with the reference `ls -v` on the corpus (`divergence_list_text_headerfile_cells.rs`, #120); `info` stays a differential-tolerated JSON key; consumer `psptool-cli/src/cmds/list.rs:55` |
//! | REQ-8 | SHIPPED | verbose branch `build_entry_row` `list.rs:336` + `entry_to_json` `list.rs:465` per `psptool.py:104`/`:183`; `MD5`/`md5` is `entry_md5` `list.rs:681`, upstream `md5()` — a HeaderFile hashes its `self.body` (`header_file.py:106`/`:312-315`, #119); `size_packed`/`sizes.packed` is `packed_size` `list.rs:530`, the normalised `rom_size` (`header_file.py:72-73`, #118); consumer `psptool-cli/src/cmds/list.rs:53` |
//! | #86/#87 sparse-mode (upstream-exact `flags`/`MD5`) | SHIPPED | richer default preserved; opt-in `RomListing::sparse` drives `build_entry_row`'s sparse branch (`flags`=`""`, `MD5`=`entry_md5(..)[..4]` upper-cased) per `psptool.py:179`/`:180`; consumer `psptool-cli/src/cmds/list.rs` sets it from `--sparse` / `PSPTOOL_LS_SPARSE` |
//! | REQ-9 | SHIPPED | `secondary_addresses` `list.rs:774` per `directory.py:156` printed `psptool.py:86`; consumer `psptool-cli/src/cmds/list.rs:49` |
//! | REQ-10 | SHIPPED | `directory_generation` `list.rs:738` renders the ids core `walk_directories` threads into `DirectoryRef::generations` (combo entry, L2 inheritance `directory.py:81-82`, accumulation + cascade `:61-62`/`:243-249`; #116/#117) as `generation_label` `list.rs:761` (`Zen N (PSP ID 0x..)`, `fet.py:117-123`; #57), one per line, per `psptool.py:84`; consumer `psptool-cli/src/cmds/list.rs:55` |
//! | REQ-11 | SHIPPED | a tertiary-reached directory's `generations` hold the `block[20:24]` id (`directory.py:89`/`94`, #70), rendered by `directory_generation` `list.rs:738` per `psptool.py:84`; consumer `psptool-cli/src/cmds/list.rs:55` |
//! | REQ-12 | NOT-STARTED | blocked on #75 (AGESA rendering); `render_rom_table` `list.rs:197` emits `AGESA_UNKNOWN` where `psptool.py:74` prints `rom.agesa_version` |
//! | REQ-13 | SHIPPED | self-oracle + corpus parity (differential-tolerated key). `info_list` `list.rs:594` renders `signature_tag` (`list.rs:641`: `verified`/`veri-failed`/`key_missing(XXXX)`) and `checksum_tag` (`list.rs:655`:`sha256_ok`/`_inconsistent`) from the entry's `Entry::decode_verification` (core `body.rs:899`) per `psptool.py:116-140`; consumer `psptool-cli/src/cmds/list.rs:55` (closes #76) |
//! | REQ-14 | SHIPPED | `entry_to_json` `list.rs:457` emits `decodeVerified`/`decodeVerificationMethod` for every HeaderFile-class entry per `psptool.py:267-271` (PSPTool `241629b`), from the `_verify_decode` port `verify_decode` (core `body.rs:937`, `header_file.py:198-243`) over the image-wide `CertifyingKeys::from_blob` (`body.rs:801`, `cert_tree.py:385-397`) built by `Verifier::new` `list.rs:112`; consumer `psptool-cli/src/cmds/list.rs:49` (closes #89) |

use md5::{Digest, Md5};
use serde_json::{Value, json};

use psptool_core::body::{CertifyingKeys, ChecksumCheck, DecodeVerification, SignatureCheck};
use psptool_core::entry::HEADER_FILE_LEN;
use psptool_core::{
    AddressMode, BiosDirectory, BiosEntry, Directory, DirectoryRef, Entry, EntryClass, EntryRecord,
    Fet, FlashOffset, HeaderEntry, Ikek, ParseError, PspDirectory, PspEntry, PspGenerationId,
    PubkeyEntry, ResolveContext, RomSize, SourceBytes, ZenGeneration,
};

use crate::table::{Align, Table};
use crate::types::readable_type;

/// All the inputs `list_*` operations need to render one ROM. Constructed by
/// the caller from `psptool-core` primitives.
pub struct RomListing<'a> {
    /// Index of this ROM in a multi-ROM blob — surfaces as the leading
    /// `ROM` column of the summary table. Single-ROM callers pass `0`.
    pub index: usize,
    pub blob: &'a SourceBytes,
    pub rom_size: RomSize,
    /// File offset of "ROM-flash-offset 0" inside `blob`. `FlashOffset::ZERO`
    /// for bare flash dumps; non-zero for capsule-wrapped images (§1.1).
    pub rom_origin: FlashOffset,
    pub fet: &'a Fet,
    pub directories: &'a [DirectoryRef],
    /// Render the upstream-exact SPARSE form of the two verbose cells PSPTool
    /// narrows: `flags` = `''` (`psptool.py:179`) and `MD5` = `md5()[:4].upper()`
    /// (`psptool.py:180`). `false` keeps the richer default (populated `flags`
    /// + full 32-char lowercase MD5) and is unchanged from prior behaviour.
    ///
    /// The CLI sets this from `--sparse` / `PSPTOOL_LS_SPARSE`.
    pub sparse: bool,
}

/// Parse outcome for one directory entry — either the parsed [`Entry`] or
/// the parse error so the renderer can emit a placeholder row instead of
/// silently dropping it (mirrors the reference tool's `PrintHelper` warning
/// path).
type EntryRow = Result<Entry, ParseError>;

/// Placeholder for the AGESA version the parser cannot yet populate (#75).
const AGESA_UNKNOWN: &str = "AGESA_UNKNOWN";

/// Upstream decrypts every entry with the Zen+ IKEK
/// (`get_unwrapped_ikek`, `header_file.py:294-307`).
const IKEK: Ikek = Ikek::ZenPlus;

/// Per-listing verification context: the image-wide certifying keys
/// (`CertificateTree.from_blob`, `cert_tree.py:385-406`, built once per
/// listing) and the image the entries were parsed from.
struct Verifier<'a> {
    blob: &'a SourceBytes,
    keys: CertifyingKeys,
}

impl<'a> Verifier<'a> {
    fn new(blob: &'a SourceBytes) -> Self {
        Self {
            blob,
            keys: CertifyingKeys::from_blob(blob, IKEK),
        }
    }

    /// Decode verification of one entry; `None` unless HeaderFile-class.
    fn verify(&self, e: &Entry) -> Option<DecodeVerification> {
        e.decode_verification(self.blob, &self.keys, IKEK)
    }
}

/// Render `psp.ls()` — basic columns only.
///
/// The `flags` / `MD5` extension cells honour [`RomListing::sparse`], but the
/// basic column set has neither, so this variant is unaffected by sparse mode.
pub fn list_default(rom: &RomListing<'_>) -> String {
    render_text(rom, false, rom.sparse)
}

/// Render `psp.ls(verbose=True)` — basic columns plus the verbose extension
/// (`flags / MD5 / size_signed / size_full / size_packed / load_addr`).
///
/// When [`RomListing::sparse`] is set, the `flags` cell is the upstream-exact
/// empty string and the `MD5` cell is `md5()[:4].upper()` (`psptool.py:179`/
/// `:180`); otherwise the richer default (populated `flags` + full 32-char
/// lowercase digest) is used.
pub fn list_verbose(rom: &RomListing<'_>) -> String {
    render_text(rom, true, rom.sparse)
}

/// Render `psp.ls_json(verbose)`. Returns a [`serde_json::Value`] that
/// callers may pretty-print or stringify; the schema mirrors the reference
/// Python tool (see module docs). `verbose=true` adds the `flags` and
/// `load_addr` fields per `docs/cli-surface.md` §1.3.
pub fn list_json(rom: &RomListing<'_>, verbose: bool) -> Value {
    let verifier = Verifier::new(rom.blob);
    let mut dirs_out = Vec::with_capacity(rom.directories.len());
    for (idx, dir_ref) in rom.directories.iter().enumerate() {
        let dir = &dir_ref.directory;
        let header = dir.header();
        let magic_str = magic_string(header.magic.as_bytes());
        let secondary = secondary_addresses(rom, dir);
        let parsed = entries_for_directory(rom, dir);
        let entries = parsed
            .iter()
            .enumerate()
            .map(|(i, row)| entry_row_to_json(i, row, dir.is_bios(), verbose, &verifier))
            .collect::<Vec<_>>();
        dirs_out.push(json!({
            "directory": idx,
            "address": dir.source().offset().get(),
            "magic": magic_str,
            "secondaryAddresses": secondary,
            "entries": entries,
        }));
    }
    Value::Array(dirs_out)
}

// ---------------------------------------------------------------------------
// Text renderer
// ---------------------------------------------------------------------------

fn render_text(rom: &RomListing<'_>, verbose: bool, sparse: bool) -> String {
    let verifier = Verifier::new(rom.blob);
    let mut out = String::new();
    out.push_str(&render_rom_table(rom));
    out.push('\n');
    for (idx, dir_ref) in rom.directories.iter().enumerate() {
        let parsed = entries_for_directory(rom, &dir_ref.directory);
        out.push_str(&render_directory_header_table(idx, dir_ref, rom));
        out.push_str(&render_entries_table(
            &dir_ref.directory,
            &parsed,
            verbose,
            sparse,
            &verifier,
        ));
        out.push_str("\n\n");
    }
    out
}

fn render_rom_table(rom: &RomListing<'_>) -> String {
    let mut t = Table::new(["ROM", "Addr", "Size", "FET", "AGESA"], Align::Center);
    t.add_row([
        rom.index.to_string(),
        format_hex_u64(rom.blob.offset().get()),
        format_hex_u64(rom.blob.len() as u64),
        format_hex_u64(rom.fet.source.offset().get()),
        AGESA_UNKNOWN.to_string(),
    ]);
    t.render()
}

fn render_directory_header_table(
    idx: usize,
    dir_ref: &DirectoryRef,
    rom: &RomListing<'_>,
) -> String {
    let mut t = Table::new(
        [
            "",
            "Directory",
            "Addr",
            "Generation",
            "Magic",
            "Secondary Directory",
        ],
        Align::Center,
    );
    let dir = &dir_ref.directory;
    let header = dir.header();
    let magic = magic_string(header.magic.as_bytes());
    let generation = directory_generation(dir_ref);
    let secondary = secondary_addresses(rom, dir)
        .iter()
        .map(|a| format_hex_u64(*a))
        .collect::<Vec<_>>()
        .join(", ");
    t.add_row([
        String::new(),
        idx.to_string(),
        format_hex_u64(dir.source().offset().get()),
        generation,
        magic,
        secondary,
    ]);
    t.render()
}

fn render_entries_table(
    dir: &Directory,
    parsed: &[EntryRow],
    verbose: bool,
    sparse: bool,
    verifier: &Verifier<'_>,
) -> String {
    let basic_fields: &[&str] = &[
        "",
        " ",
        "Entry",
        "Address",
        "Size",
        "Type",
        "Subprogram",
        "Instance",
        "Magic/ID",
        "File Version",
        "File Info",
    ];
    let verbose_fields: &[&str] = &[
        "flags",
        "MD5",
        "size_signed",
        "size_full",
        "size_packed",
        "load_addr",
    ];

    let headers: Vec<&str> = if verbose {
        basic_fields
            .iter()
            .chain(verbose_fields.iter())
            .copied()
            .collect()
    } else {
        basic_fields.to_vec()
    };

    let mut t = Table::new(headers, Align::Right);
    let is_bios = dir.is_bios();

    for (idx, row) in parsed.iter().enumerate() {
        match row {
            Ok(e) => t.add_row(build_entry_row(
                idx,
                e,
                is_bios,
                verbose,
                sparse,
                verifier.verify(e).as_ref(),
                verifier.blob,
            )),
            Err(err) => t.add_row(build_error_row(idx, err, verbose)),
        }
    }

    t.render()
}

fn build_entry_row(
    idx: usize,
    e: &Entry,
    is_bios: bool,
    verbose: bool,
    sparse: bool,
    verification: Option<&DecodeVerification>,
    blob: &SourceBytes,
) -> Vec<String> {
    let address = format_hex_u64(e.body.offset().get());
    let size = format_hex_u64(e.body.len() as u64);
    let type_name = readable_type(e.entry_type(), is_bios);
    let (subprogram, instance) = subprogram_and_instance(&e.record);
    let magic_id = magic_id_string(&e.class);
    let version = version_string(&e.class);
    let info = info_list(e, is_bios, verification).join(", ");

    let mut row = vec![
        String::new(),
        String::new(),
        idx.to_string(),
        address,
        size,
        type_name,
        format_hex_u64(subprogram as u64),
        format_hex_u64(instance as u64),
        magic_id,
        version,
        info,
    ];

    if verbose {
        // Upstream narrows two verbose cells in `ls_files` (`psptool.py`):
        // * `flags` is the literal `''` (`psptool.py:179`; the
        //   `hex(file.entry.flags)` form is commented out), and
        // * `MD5` is `file.md5()[:4].upper()` (`psptool.py:180`).
        // The richer default keeps the full `hex(flags)` + 32-char lowercase
        // digest of the same `md5()`; `sparse` reproduces the upstream-exact
        // cells.
        let flags = if sparse {
            String::new()
        } else {
            format_hex_u64(entry_flags(&e.record) as u64)
        };
        let md5 = entry_md5(e, blob);
        // The four leading characters are ASCII hex digits, so byte 4 is a
        // char boundary.
        let md5 = if sparse { md5[..4].to_uppercase() } else { md5 };
        let header = e.class.header();
        let (size_signed, size_full, size_packed, load_addr) = match header {
            Some(h) => (
                format_hex_u64(h.size_signed as u64),
                format_hex_u64(h.size_uncompressed as u64),
                format_hex_u64(packed_size(e, h)),
                format_hex_u64(h.load_addr as u64),
            ),
            None => (String::new(), String::new(), String::new(), String::new()),
        };
        row.extend([flags, md5, size_signed, size_full, size_packed, load_addr]);
    }

    row
}

fn build_error_row(idx: usize, err: &ParseError, verbose: bool) -> Vec<String> {
    let msg = format!("<parse error: {err}>");
    let mut row = vec![
        String::new(),
        String::new(),
        idx.to_string(),
        String::new(),
        String::new(),
        msg,
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        String::new(),
    ];
    if verbose {
        row.extend([
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        ]);
    }
    row
}

// ---------------------------------------------------------------------------
// JSON entry builder
// ---------------------------------------------------------------------------

fn entry_row_to_json(
    idx: usize,
    row: &EntryRow,
    is_bios: bool,
    verbose: bool,
    verifier: &Verifier<'_>,
) -> Value {
    match row {
        Ok(e) => entry_to_json(
            idx,
            e,
            is_bios,
            verbose,
            verifier.verify(e).as_ref(),
            verifier.blob,
        ),
        Err(err) => json!({
            "index": idx,
            "error": format!("{err}"),
        }),
    }
}

fn entry_to_json(
    idx: usize,
    e: &Entry,
    is_bios: bool,
    verbose: bool,
    verification: Option<&DecodeVerification>,
    blob: &SourceBytes,
) -> Value {
    let info = info_list(e, is_bios, verification);
    let mut obj = serde_json::Map::new();
    obj.insert("index".into(), json!(idx));
    obj.insert("address".into(), json!(e.body.offset().get()));
    obj.insert("size".into(), json!(e.body.len()));
    obj.insert(
        "sectionType".into(),
        json!(readable_type(e.entry_type(), is_bios)),
    );
    obj.insert("magic".into(), json!(magic_id_string(&e.class)));
    obj.insert("version".into(), json!(version_string(&e.class)));
    obj.insert("info".into(), json!(info));

    if let EntryRecord::Bios(b) = &e.record
        && readable_type(e.entry_type(), true) == "BIOS"
        && !b.destination_is_unused()
    {
        obj.insert(
            "destinationAddress".into(),
            json!(format!("{:x}", b.destination)),
        );
    }

    // `psptool.py:267-271` (PSPTool `241629b`): the authoritative decode-trust
    // bit of every HeaderFile-class entry, emitted regardless of `verbose`.
    if let Some(v) = verification {
        obj.insert("decodeVerified".into(), json!(v.decode_verified()));
        obj.insert(
            "decodeVerificationMethod".into(),
            json!(v.decode_verification_method().as_str()),
        );
    }

    if verbose {
        obj.insert("md5".into(), json!(entry_md5(e, blob)));
        obj.insert("flags".into(), json!(entry_flags(&e.record)));
        if let Some(h) = e.class.header() {
            obj.insert(
                "sizes".into(),
                json!({
                    "signed": h.size_signed,
                    "uncompressed": h.size_uncompressed,
                    "packed": packed_size(e, h),
                }),
            );
            obj.insert("load_addr".into(), json!(h.load_addr));
        }
    }

    Value::Object(obj)
}

// ---------------------------------------------------------------------------
// Per-entry rendering helpers
// ---------------------------------------------------------------------------

fn entries_for_directory(rom: &RomListing<'_>, dir: &Directory) -> Vec<EntryRow> {
    match dir {
        Directory::Psp(p) => parse_psp_entries(rom, p),
        Directory::Bios(b) => parse_bios_entries(rom, b),
        // Combo directories list pointers, not files. Their on-disk shape has
        // no "files" — `ls_files` for a combo is empty in PSPTool too.
        Directory::Combo(_) => Vec::new(),
    }
}

fn parse_psp_entries(rom: &RomListing<'_>, parent: &PspDirectory) -> Vec<EntryRow> {
    let mut out = Vec::with_capacity(parent.entries.len());
    for i in 0..parent.entries.len() {
        out.push(Entry::parse_psp(
            rom.blob,
            parent,
            i,
            rom.rom_size,
            rom.rom_origin,
        ));
    }
    out
}

fn parse_bios_entries(rom: &RomListing<'_>, parent: &BiosDirectory) -> Vec<EntryRow> {
    let mut out = Vec::with_capacity(parent.entries.len());
    for i in 0..parent.entries.len() {
        out.push(Entry::parse_bios(
            rom.blob,
            parent,
            i,
            rom.rom_size,
            rom.rom_origin,
        ));
    }
    out
}

/// `HeaderFile.rom_size` after `_parse` normalised it — the `size_packed` /
/// `sizes.packed` value (`psptool.py:187`, `:264`). A header `rom_size` of 0
/// becomes the buffer size (`header_file.py:72-73`): the directory-declared
/// entry, grown to the 0x100 header when shorter (`header_file.py:32-33`).
fn packed_size(e: &Entry, h: &HeaderEntry) -> u64 {
    match h.rom_size {
        0 => e.body.len().max(HEADER_FILE_LEN) as u64,
        rom_size => u64::from(rom_size),
    }
}

fn subprogram_and_instance(rec: &EntryRecord) -> (u8, u8) {
    match rec {
        EntryRecord::Psp(p) => (p.subprogram, p.instance()),
        EntryRecord::Bios(b) => (b.subprogram(), b.instance()),
    }
}

fn entry_flags(rec: &EntryRecord) -> u16 {
    match rec {
        EntryRecord::Psp(p) => p.flags,
        EntryRecord::Bios(b) => b.flags,
    }
}

fn magic_id_string(class: &EntryClass) -> String {
    if let Some(h) = class.header() {
        return ascii_or_hex_4(&h.magic);
    }
    if let Some(p) = class.pubkey() {
        // PSPTool's `get_readable_magic()` for `PubkeyFile` returns
        // `self.certifying_id.magic` — the leading 4 bytes of the certifying
        // ID rendered as ASCII (e.g. `"AMD"`) when printable.
        let leading: [u8; 4] = [
            p.certifying_id[0],
            p.certifying_id[1],
            p.certifying_id[2],
            p.certifying_id[3],
        ];
        return ascii_or_hex_4(&leading);
    }
    String::new()
}

fn version_string(class: &EntryClass) -> String {
    let h = match class.header() {
        Some(h) => h,
        None => return String::new(),
    };
    // §4 footnote: display order is the reverse of the on-disk byte order.
    let v = h.version;
    format!("{:02x}.{:02x}.{:02x}.{:02x}", v[3], v[2], v[1], v[0])
}

/// Info tokens for an entry. JSON uses the list form; text joins with ", "
/// (PSPTool's `', '.join(info)`, `psptool.py:178`).
///
/// Order mirrors `ls_files` (`psptool.py:113-140`):
/// `compressed, <signature outcome>, encrypted, <checksum outcome>`. Upstream
/// emits only outcome tags there — no bare `signed` / `sha256` / `sha384`
/// token. The BIOS-flag compressed bit is folded into the same `compressed`
/// slot (rather than emitted twice when both the entry flag and header bit
/// are set) so the text matches PSPTool byte-for-byte. The two outcome tags
/// come from `verification` (the entry's single
/// [`Entry::decode_verification`] pass): `verified(..)` / `veri-failed(..)` /
/// `key_missing(..)` (`psptool.py:117-123`) and `sha256_ok` /
/// `sha256_inconsistent`, else `sha384_ok` / `sha384_inconsistent`
/// (`psptool.py:131-140`).
fn info_list(
    e: &Entry,
    is_bios_directory: bool,
    verification: Option<&DecodeVerification>,
) -> Vec<String> {
    let mut info = Vec::new();
    let bios_flag_compressed = matches!(&e.record, EntryRecord::Bios(b) if b.is_compressed());
    let header = e.class.header();
    let header_compressed = header.map(|h| h.is_compressed).unwrap_or(false);

    if bios_flag_compressed || header_compressed {
        info.push("compressed".to_string());
    }
    if let Some(h) = header {
        // `psptool.py:116`: `if file.is_signed` — a KeyStoreFile always is
        // (`key_store_file.py:62-64`); `signature()` is `Some` exactly then.
        if let Some(check) = verification.and_then(DecodeVerification::signature) {
            info.push(signature_tag(check, &h.signature_fingerprint));
        }
        if h.is_encrypted {
            info.push("encrypted".to_string());
        }
        // `psptool.py:130-140`: `has_sha256_checksum` → `sha256_*`, `elif
        // has_sha384_checksum` → `sha384_*`; `checksum()` picks the same bit.
        match verification.and_then(DecodeVerification::checksum) {
            Some(ChecksumCheck::Sha256 { ok }) => info.push(checksum_tag("sha256", ok)),
            Some(ChecksumCheck::Sha384 { ok }) => info.push(checksum_tag("sha384", ok)),
            None => {}
        }
    }
    if let EntryClass::Pubkey(p) = &e.class {
        info.push(pubkey_usage(p));
    }
    let type_str = readable_type(e.entry_type(), is_bios_directory);
    if (type_str == "BIOS" || type_str == "APOB")
        && let EntryRecord::Bios(b) = &e.record
        && !b.destination_is_unused()
    {
        info.push(format!("destination({:x})", b.destination));
    }
    info
}

/// `psptool.py:117-125`: the certificate-tree outcome tagged with the
/// certifying key's readable id — `get_readable_signed_by()` /
/// `certifying_id.as_string()[:4]`, the first two id bytes as upper-case hex
/// (`KeyId.magic`, `crypto.py:369-374`).
fn signature_tag(check: SignatureCheck, certifying_id: &[u8; 16]) -> String {
    let id = format!("{:02X}{:02X}", certifying_id[0], certifying_id[1]);
    match check {
        SignatureCheck::Verified => format!("verified({id})"),
        SignatureCheck::Failed => format!("veri-failed({id})"),
        SignatureCheck::NoCertifyingKey => format!("key_missing({id})"),
        // Upstream's `ls` lets an unexpected verification exception propagate;
        // `invalid_sig(..)` is the tag its `except` arm reserves for a
        // signature that cannot be checked (`psptool.py:124-125`).
        SignatureCheck::Error => format!("invalid_sig({id})"),
    }
}

/// `psptool.py:131-140`: `<algo>_ok` / `<algo>_inconsistent`.
fn checksum_tag(algo: &str, ok: bool) -> String {
    if ok {
        format!("{algo}_ok")
    } else {
        format!("{algo}_inconsistent")
    }
}

fn pubkey_usage(p: &PubkeyEntry) -> String {
    match p.key_usage {
        0 => "AMD_CODE_SIGN".to_string(),
        other => format!("key_usage({:#x})", other),
    }
}

/// Full 32-character hex digest of upstream's `file.md5()`, which `ls` prints
/// as `md5()[:4].upper()` (`psptool.py:180`, `:254`).
///
/// `File.md5` hashes the file buffer (`file.py:380-383`). `HeaderFile.md5`
/// — inherited by `KeyStoreFile` — hashes its data region `self.body`
/// instead (`header_file.py:312-315`): `[0x100, rom_size - signature_len)` of
/// the HeaderFile buffer (`header_file.py:106`, `rom_size` normalised as in
/// [`packed_size`]), the signature reserved only when signed (`:83-90`; a
/// `KeyStoreFile` always is, `key_store_file.py:62-64`). A region the image
/// does not hold hashes no bytes, like upstream's `except` arm
/// (`header_file.py:316-317`).
fn entry_md5(e: &Entry, blob: &SourceBytes) -> String {
    let (h, key_store) = match &e.class {
        EntryClass::Header(h) => (h, false),
        EntryClass::KeyStore(h) => (h, true),
        _ => return md5_hex(e.body.as_bytes()),
    };
    let sig_len = if key_store || h.is_signed() {
        h.signature_len()
    } else {
        Some(0)
    };
    let end = sig_len.and_then(|sig| usize::try_from(packed_size(e, h)).ok()?.checked_sub(sig));
    let window = e.header_file_window(blob);
    let region = window
        .as_ref()
        .zip(end)
        .and_then(|(w, end)| w.as_bytes().get(HEADER_FILE_LEN..end));
    md5_hex(region.unwrap_or_default())
}

fn md5_hex(bytes: &[u8]) -> String {
    let digest = Md5::digest(bytes);
    let mut s = String::with_capacity(32);
    for b in digest.iter() {
        use core::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

fn ascii_or_hex_4(bytes: &[u8; 4]) -> String {
    if bytes.iter().all(|b| b.is_ascii_graphic()) {
        // Every byte is ASCII printable — use the literal tag (e.g. "$PS1").
        core::str::from_utf8(bytes).unwrap().to_string()
    } else {
        format!(
            "{:02x}{:02x}{:02x}{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3]
        )
    }
}

fn magic_string(bytes: &[u8; 4]) -> String {
    ascii_or_hex_4(bytes)
}

/// Generation column for a directory: upstream's `directory.zen_generation`
/// (`psptool.py:84`), one [`generation_label`] per line — upstream joins the
/// labels it accumulates with `'\n'` (`directory.py:246`) and PrettyTable
/// prints each on its own line.
///
/// * `$PSP`/`$BHD` directories: the ids the walk threaded through the
///   directory graph ([`DirectoryRef::generations`]: combo entry, tertiary
///   block, L2 parent). Empty when there are none — upstream prints `None`
///   there.
/// * Combo directories (not listed by upstream at all): the distinct ids of
///   their entries, i.e. what the directories they point at receive.
fn directory_generation(dir_ref: &DirectoryRef) -> String {
    let mut ids: Vec<PspGenerationId> = Vec::new();
    match &dir_ref.directory {
        Directory::Combo(c) => {
            for e in &c.entries {
                if !ids.contains(&e.psp_generation) {
                    ids.push(e.psp_generation);
                }
            }
        }
        Directory::Psp(_) | Directory::Bios(_) => ids.clone_from(&dir_ref.generations),
    }
    ids.into_iter()
        .map(generation_label)
        .collect::<Vec<_>>()
        .join("\n")
}

/// The label upstream threads into `zen_generation`:
/// `get_possible_zen_generation(id[1:4])` plus `f' (PSP ID {hex(id)})'`
/// (`fet.py:117-123`, `directory.py:89-95`), e.g. `Zen 3 (PSP ID
/// 0xbc0c0140)`; an id outside `ZEN_GENERATION_IDS` is `'unknown'`
/// (`directory.py:34-48`).
fn generation_label(id: PspGenerationId) -> String {
    let name = match id.zen_generation() {
        Some(ZenGeneration::Zen1) => "Zen 1",
        Some(ZenGeneration::Zen2) => "Zen 2",
        Some(ZenGeneration::Zen3) => "Zen 3",
        Some(ZenGeneration::Zen4) => "Zen 4",
        Some(ZenGeneration::Zen4Or5) => "Zen 4/5",
        None => "unknown",
    };
    format!("{name} (PSP ID {:#x})", id.get())
}

/// Resolve secondary-directory pointers for `dir` to flash offsets.
fn secondary_addresses(rom: &RomListing<'_>, dir: &Directory) -> Vec<u64> {
    let mut out = Vec::new();
    let dir_offset = dir.source().offset();
    let dir_mode = dir.header().address_mode();
    let ctx = ResolveContext {
        rom_size: rom.rom_size,
        directory_base: dir_offset,
        rom_origin: rom.rom_origin,
    };
    match dir {
        Directory::Psp(p) => collect_secondary_psp(&p.entries, dir_mode, ctx, &mut out),
        Directory::Bios(b) => collect_secondary_bios(&b.entries, dir_mode, ctx, &mut out),
        Directory::Combo(c) => {
            // Combo entries are §1.3-normalised PhysicalX86 pointers.
            let combo_ctx = ResolveContext {
                rom_size: rom.rom_size,
                directory_base: FlashOffset(0),
                rom_origin: rom.rom_origin,
            };
            for entry in &c.entries {
                if let Ok(off) = AddressMode::PhysicalX86.resolve(entry.pointer, combo_ctx) {
                    out.push(off.get());
                }
            }
        }
    }
    out
}

fn collect_secondary_psp(
    entries: &[PspEntry],
    dir_mode: AddressMode,
    ctx: ResolveContext,
    out: &mut Vec<u64>,
) {
    for e in entries {
        if e.entry_type.is_secondary_directory_pointer() {
            let addr = dir_mode.resolve_with_entry(e.entry_address_mode(), e.offset, ctx);
            out.push(addr.get());
        }
    }
}

fn collect_secondary_bios(
    entries: &[BiosEntry],
    dir_mode: AddressMode,
    ctx: ResolveContext,
    out: &mut Vec<u64>,
) {
    for e in entries {
        if e.entry_type.is_secondary_directory_pointer() {
            let addr = dir_mode.resolve_with_entry(e.entry_address_mode(), e.offset, ctx);
            out.push(addr.get());
        }
    }
}

fn format_hex_u64(v: u64) -> String {
    format!("{:#x}", v)
}

// ---------------------------------------------------------------------------
// Local helpers on Directory
// ---------------------------------------------------------------------------

trait DirectoryExt {
    fn is_bios(&self) -> bool;
}

impl DirectoryExt for Directory {
    fn is_bios(&self) -> bool {
        matches!(self, Directory::Bios(_))
    }
}
