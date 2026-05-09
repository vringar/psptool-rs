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
//! * `list_json(verbose)` — array of directory objects with
//!   `directory / address / magic / secondaryAddresses / entries[]`. Each
//!   entry mirrors PSPTool's `ls_files_dict` keys; `verbose=true` adds the
//!   extra `flags` and `load_addr` fields.
//!
//! Fields the reference Python tool can render but our parser does not
//! expose yet (AGESA version, signature-verification result, sha-checksum
//! result) are emitted as placeholder strings (e.g. `AGESA_UNKNOWN`). They
//! are explicit follow-ups, not stubs.

use md5::{Digest, Md5};
use serde_json::{Value, json};

use psptool_core::{
    AddressMode, BiosDirectory, BiosEntry, Directory, DirectoryProvenance, DirectoryRef, Entry,
    EntryClass, EntryRecord, Fet, FlashOffset, ParseError, PspDirectory, PspEntry, PubkeyEntry,
    ResolveContext, RomSize, SourceBytes, ZenGeneration,
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
    pub fet: &'a Fet,
    pub directories: &'a [DirectoryRef],
}

/// Parse outcome for one directory entry — either the parsed [`Entry`] or
/// the parse error so the renderer can emit a placeholder row instead of
/// silently dropping it (mirrors the reference tool's `PrintHelper` warning
/// path).
type EntryRow = Result<Entry, ParseError>;

/// Placeholder string for fields the parser cannot yet populate (AGESA
/// version, signature-verify, sha-checksum verify). The reference tool
/// emits human-readable tags in these slots; we mirror that contract.
const AGESA_UNKNOWN: &str = "AGESA_UNKNOWN";
const SIG_UNKNOWN: &str = "SIG_UNKNOWN";
const SHA_UNKNOWN: &str = "SHA_UNKNOWN";

/// Render `psp.ls()` — basic columns only.
pub fn list_default(rom: &RomListing<'_>) -> String {
    render_text(rom, false)
}

/// Render `psp.ls(verbose=True)` — basic columns plus the verbose extension
/// (`flags / MD5 / size_signed / size_full / size_packed / load_addr`).
pub fn list_verbose(rom: &RomListing<'_>) -> String {
    render_text(rom, true)
}

/// Render `psp.ls_json(verbose)`. Returns a [`serde_json::Value`] that
/// callers may pretty-print or stringify; the schema mirrors the reference
/// Python tool (see module docs). `verbose=true` adds the `flags` and
/// `load_addr` fields per `docs/cli-surface.md` §1.3.
pub fn list_json(rom: &RomListing<'_>, verbose: bool) -> Value {
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
            .map(|(i, row)| entry_row_to_json(i, row, dir.is_bios(), verbose))
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

fn render_text(rom: &RomListing<'_>, verbose: bool) -> String {
    let mut out = String::new();
    out.push_str(&render_rom_table(rom));
    out.push('\n');
    for (idx, dir_ref) in rom.directories.iter().enumerate() {
        let parsed = entries_for_directory(rom, &dir_ref.directory);
        out.push_str(&render_directory_header_table(idx, dir_ref, rom));
        out.push_str(&render_entries_table(&dir_ref.directory, &parsed, verbose));
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
    let generation = directory_generation(dir_ref, rom);
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

fn render_entries_table(dir: &Directory, parsed: &[EntryRow], verbose: bool) -> String {
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
            Ok(e) => t.add_row(build_entry_row(idx, e, is_bios, verbose)),
            Err(err) => t.add_row(build_error_row(idx, err, verbose)),
        }
    }

    t.render()
}

fn build_entry_row(idx: usize, e: &Entry, is_bios: bool, verbose: bool) -> Vec<String> {
    let address = format_hex_u64(e.body.offset().get());
    let size = format_hex_u64(e.body.len() as u64);
    let type_name = readable_type(e.entry_type(), is_bios);
    let (subprogram, instance) = subprogram_and_instance(&e.record);
    let magic_id = magic_id_string(&e.class);
    let version = version_string(&e.class);
    let info = info_string(e, is_bios);

    let mut row = vec![
        String::new(),
        String::new(),
        idx.to_string(),
        address,
        size,
        type_name,
        subprogram.to_string(),
        instance.to_string(),
        magic_id,
        version,
        info,
    ];

    if verbose {
        let flags = entry_flags(&e.record);
        let md5 = body_md5_hex(&e.body);
        let header = e.class.header();
        let (size_signed, size_full, size_packed, load_addr) = match header {
            Some(h) => (
                format_hex_u64(h.size_signed as u64),
                format_hex_u64(h.size_uncompressed as u64),
                format_hex_u64(h.rom_size as u64),
                format_hex_u64(h.load_addr as u64),
            ),
            None => (String::new(), String::new(), String::new(), String::new()),
        };
        row.extend([
            format_hex_u64(flags as u64),
            md5,
            size_signed,
            size_full,
            size_packed,
            load_addr,
        ]);
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

fn entry_row_to_json(idx: usize, row: &EntryRow, is_bios: bool, verbose: bool) -> Value {
    match row {
        Ok(e) => entry_to_json(idx, e, is_bios, verbose),
        Err(err) => json!({
            "index": idx,
            "error": format!("{err}"),
        }),
    }
}

fn entry_to_json(idx: usize, e: &Entry, is_bios: bool, verbose: bool) -> Value {
    let info = info_list(e, is_bios);
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

    if verbose {
        obj.insert("md5".into(), json!(body_md5_hex(&e.body)));
        obj.insert("flags".into(), json!(entry_flags(&e.record)));
        if let Some(h) = e.class.header() {
            obj.insert(
                "sizes".into(),
                json!({
                    "signed": h.size_signed,
                    "uncompressed": h.size_uncompressed,
                    "packed": h.rom_size,
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
        out.push(Entry::parse_psp(rom.blob, parent, i, rom.rom_size));
    }
    out
}

fn parse_bios_entries(rom: &RomListing<'_>, parent: &BiosDirectory) -> Vec<EntryRow> {
    let mut out = Vec::with_capacity(parent.entries.len());
    for i in 0..parent.entries.len() {
        out.push(Entry::parse_bios(rom.blob, parent, i, rom.rom_size));
    }
    out
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

/// Comma-separated info string for the textual output (matches PSPTool's
/// `', '.join(info)`).
fn info_string(e: &Entry, is_bios_directory: bool) -> String {
    info_list(e, is_bios_directory).join(", ")
}

/// Info tokens for an entry. JSON uses the list form; text joins with ", ".
///
/// Order mirrors the reference `HeaderFile.get_readable_attributes()`:
/// `compressed, signed, encrypted, sha256/sha384, [sig/sha verify status]`.
/// The BIOS-flag compressed bit is folded into the same `compressed` slot
/// (rather than emitted twice when both the entry flag and header bit are
/// set) so the text matches PSPTool byte-for-byte.
fn info_list(e: &Entry, is_bios_directory: bool) -> Vec<String> {
    let mut info = Vec::new();
    let bios_flag_compressed = matches!(&e.record, EntryRecord::Bios(b) if b.is_compressed());
    let header = e.class.header();
    let header_compressed = header.map(|h| h.is_compressed).unwrap_or(false);

    if bios_flag_compressed || header_compressed {
        info.push("compressed".to_string());
    }
    if let Some(h) = header {
        if h.is_signed() {
            info.push("signed".to_string());
            // Signature-verify result not yet computed.
            info.push(SIG_UNKNOWN.to_string());
        }
        if h.is_encrypted {
            info.push("encrypted".to_string());
        }
        if h.has_sha256_checksum() {
            info.push("sha256".to_string());
            info.push(SHA_UNKNOWN.to_string());
        }
        if h.has_sha384_checksum() {
            info.push("sha384".to_string());
            info.push(SHA_UNKNOWN.to_string());
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

fn pubkey_usage(p: &PubkeyEntry) -> String {
    match p.key_usage {
        0 => "AMD_CODE_SIGN".to_string(),
        other => format!("key_usage({:#x})", other),
    }
}

/// Full 32-character hex MD5 digest of the entry body, matching PSPTool's
/// `File.md5()` (`hashlib.md5(self.get_bytes()).hexdigest()`).
fn body_md5_hex(body: &SourceBytes) -> String {
    let mut hasher = Md5::new();
    hasher.update(body.as_bytes());
    let digest = hasher.finalize();
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

/// Generation column for a directory.
///
/// * Combo directories: list every distinct Zen generation across all combo
///   entries, comma-separated (e.g. `"Zen2, Zen3"`).
/// * `$PSP`/`$BHD` directories: when reached via a combo entry, inherit
///   that combo entry's generation. Otherwise empty (matches the reference
///   tool's `Directory.zen_generation`).
fn directory_generation(dir_ref: &DirectoryRef, rom: &RomListing<'_>) -> String {
    match &dir_ref.directory {
        Directory::Combo(c) => {
            let mut gens: Vec<&str> = Vec::new();
            for e in &c.entries {
                if let Some(g) = e.psp_generation.zen_generation() {
                    let label = zen_label(g);
                    if !gens.contains(&label) {
                        gens.push(label);
                    }
                }
            }
            gens.join(", ")
        }
        Directory::Psp(_) | Directory::Bios(_) => {
            let DirectoryProvenance::ComboEntry {
                combo_offset,
                index,
            } = &dir_ref.provenance
            else {
                return String::new();
            };
            for d in rom.directories {
                if let Directory::Combo(c) = &d.directory
                    && c.source.offset() == *combo_offset
                    && let Some(g) = c
                        .entries
                        .get(*index)
                        .and_then(|e| e.psp_generation.zen_generation())
                {
                    return zen_label(g).to_string();
                }
            }
            String::new()
        }
    }
}

const fn zen_label(g: ZenGeneration) -> &'static str {
    match g {
        ZenGeneration::Zen1 => "Zen1",
        ZenGeneration::Zen2 => "Zen2",
        ZenGeneration::Zen3 => "Zen3",
        ZenGeneration::Zen4 => "Zen4",
        ZenGeneration::Zen4Or5 => "Zen4Or5",
    }
}

/// Resolve secondary-directory pointers for `dir` to flash offsets.
fn secondary_addresses(rom: &RomListing<'_>, dir: &Directory) -> Vec<u64> {
    let mut out = Vec::new();
    let dir_offset = dir.source().offset();
    let dir_mode = dir.header().address_mode();
    let ctx = ResolveContext {
        rom_size: rom.rom_size,
        directory_base: dir_offset,
    };
    match dir {
        Directory::Psp(p) => collect_secondary_psp(&p.entries, dir_mode, ctx, &mut out),
        Directory::Bios(b) => collect_secondary_bios(&b.entries, dir_mode, ctx, &mut out),
        Directory::Combo(c) => {
            // Combo entries are §1.3-normalised PhysicalX86 pointers.
            let combo_ctx = ResolveContext {
                rom_size: rom.rom_size,
                directory_base: FlashOffset(0),
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
