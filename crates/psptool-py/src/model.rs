//! Upstream-ordered object graph: which ROMs, directories and files the
//! reference `PSPTool(rom_bytes)` constructor creates, in which order, and how
//! they share objects.
//!
//! Consumers store `(rom, directory, file)` indices and re-resolve them later
//! (`psp.blob.roms[r].directories[d].files[f]`, board #388), so the binding
//! must reproduce upstream's *construction order*, not merely its bytes. This
//! module is a translation of that order, built on the `psptool-core`
//! parsers:
//!
//! * ROMs — one per FET candidate that yields a layout (`blob.py:58-84`),
//!   sized `min(rom_size, 16 MiB)` outside page 0 (`blob.py:72-75`).
//! * Directories — per FET slot, combo directories expanded into their leaf
//!   directories (`fet.py:59-92`, `:94-127`); each leaf followed depth-first
//!   through its secondary and tertiary pointers (`directory.py:57-101`) and
//!   deduplicated through a cache keyed by the *requested* ROM-relative offset
//!   that is shared by every ROM of the blob (`psptool.directories_by_offset`,
//!   `psptool.py:47`).
//! * Files — per directory entry (`directory.py:149-153`), through a global
//!   `files_by_offset` cache keyed by the ROM-relative file offset
//!   (`file.py:39-56`): a cached file is *shared* (the same object appears in
//!   every directory that references its offset), BIOS `0x61` APOB entries
//!   bypass the cache, and a `File.ParseError` drops the entry from `files`.
//! * Classes and buffer sizes — `File.from_entry` (`file.py:259-269`),
//!   `File.__init__` (`file.py:285-319`), `HeaderFile._parse`
//!   (`header_file.py:31-106`), `PubkeyFile._parse` (`pubkey_file.py:53-91`),
//!   `KeyStoreFile._parse` (`key_store_file.py:28-48`),
//!   `MicrocodeFile.__init__` (`microcode_file.py:25-37`).
//!
//! `psptool-core`'s [`walk_directories`](psptool_core::walk_directories) is
//! not reused for ordering: it is LIFO-ordered and surfaces combo nodes, both
//! of which shift positional indices.
//!
//! Where upstream aborts the whole construction on malformed input (an
//! `AssertionError` from an out-of-bounds `NestedBuffer`, a `TypeError` from
//! merging a generation into `None`, an unknown directory magic) this model
//! drops the offending node instead (`DEVIATIONS.md`).

use std::collections::HashMap;

use psptool_core::directory::{BIOS_ENTRY_SIZE, DIRECTORY_HEADER_SIZE, PSP_ENTRY_SIZE};
use psptool_core::{
    Address, AddressMode, Directory, EntryRecord, EntryType, FlashOffset, HeaderEntry,
    PspGenerationId, ResolveContext, RomSize, SourceBytes, ZenGeneration, detect_rom_layout,
    scan_fet_candidates,
};

/// The 16 MiB window every ROM structure lives in (`blob.py:32`).
pub const PAGE_SIZE: u64 = 16 * 1024 * 1024;

/// `HeaderFile.HEADER_LEN` (`header_file.py:29`).
pub const HEADER_LEN: u64 = 0x100;

/// `PubkeyFile.HEADER_LEN` (`pubkey_file.py:29`).
pub const PUBKEY_HEADER_LEN: u64 = 0x40;

/// `KeyStoreFileHeader.HEADER_SIZE` (`key_store_file.py:69`).
const KEY_STORE_HEADER_LEN: u64 = 0x100;

const COMBO_MAGICS: [&[u8; 4]; 2] = [b"2PSP", b"2BHD"];
const PSP_MAGICS: [&[u8; 4]; 2] = [b"$PSP", b"$PL2"];
const BIOS_MAGICS: [&[u8; 4]; 2] = [b"$BHD", b"$BL2"];

/// Upstream class of a file object (`file.py:259-269`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileKind {
    /// `File` — PSP-directory entry without a recognised structure.
    Plain,
    /// `BiosFile` — BIOS-directory entry without a recognised structure.
    Bios,
    /// `HeaderFile` with its signature length (`header_file.py:83-90`).
    Header { signature_len: u64 },
    /// `KeyStoreFile` (a `HeaderFile` subclass, `key_store_file.py:23`).
    KeyStore { signature_len: u64 },
    /// `PubkeyFile` (`pubkey_file.py:27`).
    Pubkey,
    /// `MicrocodeFile`; `header` is the size of the optional wrapping
    /// `HeaderFile` (`microcode_file.py:29-37`), `None` when its parse failed.
    Microcode { header: Option<HeaderSizing> },
}

/// Buffer size and signature length of a parsed `HeaderFile`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderSizing {
    pub buffer_size: u64,
    pub signature_len: u64,
}

/// One ROM of the blob (`rom.py:7-22`).
#[derive(Clone, Debug)]
pub struct RomNode {
    /// `Rom.buffer_offset`: absolute offset of the ROM inside the blob.
    pub offset: u64,
    /// `Rom.buffer_size` (`addr_mask + 1`, `rom.py:14`).
    pub size: u64,
    /// `Fet.buffer_offset`: ROM-relative offset of the FET magic.
    pub fet_offset: u64,
    /// `Fet.buffer_size`: magic plus slots, without the terminator
    /// (`fet.py:44-57`).
    pub fet_size: u64,
    /// Distinct AGESA strings in first-seen order (`rom.py:24-52`).
    pub agesa: Vec<String>,
    /// `Rom.directories` / `Fet.directories` (the same list upstream).
    pub directories: Vec<usize>,
}

/// One directory (`directory.py:119-165`).
#[derive(Clone, Debug)]
pub struct DirNode {
    /// The ROM whose FET created the directory (`Directory.rom`).
    pub rom: usize,
    /// ROM-relative offset (`Directory.buffer_offset`, already masked).
    pub offset: u64,
    /// `BiosDirectory` rather than `Directory`.
    pub bios: bool,
    /// Number of entry records (`Directory.count`).
    pub count: u64,
    /// `Directory.zen_generation` (`directory.py:124`, merged by
    /// `update_zen_generation`, `directory.py:243-249`).
    pub zen_generation: Option<String>,
    /// Parsed entry records, in table order (`Directory.entries`).
    pub records: Vec<EntryRecord>,
    /// `Directory.files`.
    pub files: Vec<usize>,
    /// `secondary_directory_offsets` (`directory.py:156-163`).
    pub secondary: Vec<u64>,
    /// `tertiary_directory_offsets`.
    pub tertiary: Vec<u64>,
}

impl DirNode {
    /// `ENTRY_SIZE` of this directory family.
    pub const fn entry_size(&self) -> u64 {
        if self.bios {
            BIOS_ENTRY_SIZE as u64
        } else {
            PSP_ENTRY_SIZE as u64
        }
    }
}

/// One file object.
#[derive(Clone, Debug)]
pub struct FileNode {
    /// The ROM the creating directory belongs to (`File.parent_buffer`).
    pub rom: usize,
    /// The creating directory (`File.parent_directory`).
    pub dir: usize,
    /// Index of the creating entry in `dir`'s table (`File.entry`).
    pub entry: usize,
    /// ROM-relative `buffer_offset`.
    pub offset: u64,
    /// Final `buffer_size`.
    pub size: u64,
    pub kind: FileKind,
    /// `File.references`: every directory resolving to this file.
    pub references: Vec<usize>,
}

/// The whole graph plus the two caches upstream exposes on the `PSPTool`
/// object (`psptool.py:47-48`).
#[derive(Clone, Debug, Default)]
pub struct Model {
    pub roms: Vec<RomNode>,
    pub dirs: Vec<DirNode>,
    pub files: Vec<FileNode>,
    /// `directories_by_offset`, in insertion order.
    pub directories_by_offset: Vec<(u64, usize)>,
    /// `files_by_offset`, in insertion order.
    pub files_by_offset: Vec<(u64, usize)>,
}

/// Build the upstream object graph of `image` (`PSPTool.__init__`,
/// `psptool.py:43-51`).
pub fn build(image: &SourceBytes) -> Model {
    let mut b = Builder {
        image,
        model: Model::default(),
        dir_cache: HashMap::new(),
        file_cache: HashMap::new(),
    };
    for position in scan_fet_candidates(image) {
        if let Some(layout) = detect_rom_layout(image, position) {
            b.add_rom(position, layout);
        }
    }
    b.model
}

struct Builder<'a> {
    image: &'a SourceBytes,
    model: Model,
    dir_cache: HashMap<(usize, u64), usize>,
    file_cache: HashMap<(usize, u64), usize>,
}

/// The ROM a FET walk is running in.
#[derive(Clone, Copy)]
struct RomCtx {
    id: usize,
    origin: u64,
    size: u64,
}

impl RomCtx {
    const fn addr_mask(self) -> u64 {
        self.size - 1
    }
}

impl Builder<'_> {
    /// `blob.py:59-78` + `rom.py:8-22`.
    fn add_rom(&mut self, position: FlashOffset, layout: psptool_core::RomLayout) {
        let origin = layout.rom_origin.get();
        let full = layout.rom_size.bytes();
        // `blob.py:65,72-75`: page-0 ROMs keep the full size, others are
        // clamped to one 16 MiB window.
        let size = if position.get() / PAGE_SIZE == 0 {
            full
        } else {
            full.min(PAGE_SIZE)
        };
        let id = self.model.roms.len();
        let agesa = self
            .read(origin, size)
            .map(find_agesa_versions)
            .unwrap_or_default();
        self.model.roms.push(RomNode {
            offset: origin,
            size,
            fet_offset: position.get() - origin,
            fet_size: (layout.fet.source.len() as u64).saturating_sub(16),
            agesa,
            directories: Vec::new(),
        });
        let rom = RomCtx { id, origin, size };

        // `fet.py:59-92`.
        for slot in &layout.fet.slots {
            let raw = slot.slot.address().get();
            if Address(raw).is_fet_sentinel() {
                continue;
            }
            let rom_addr = mask_pointer(raw, rom);
            let Some(magic) = self.rom_read(rom, rom_addr, 4) else {
                // `fet.py:73-77`: an out-of-bounds pointer is skipped.
                continue;
            };
            let created = if COMBO_MAGICS.iter().any(|m| m[..] == magic[..]) {
                let mut created = Vec::new();
                for (offset, generation) in self.parse_combo(rom, rom_addr) {
                    created.extend(self.create_directories(rom, offset, Some(generation)));
                }
                created
            } else if &magic[..] == b"$PSP" || &magic[..] == b"$BHD" {
                self.create_directories(rom, rom_addr, None)
            } else {
                continue;
            };
            for dir in created {
                let list = &mut self.model.roms[id].directories;
                if !list.contains(&dir) {
                    list.push(dir);
                }
            }
        }
    }

    /// `Fet._parse_combo_dir` (`fet.py:94-127`): `(offset, zen_generation)`
    /// of every non-empty combo entry.
    fn parse_combo(&self, rom: RomCtx, dir_addr: u64) -> Vec<(u64, String)> {
        let Some(count) = self.rom_u32(rom, dir_addr + 8) else {
            return Vec::new();
        };
        let Some(combo) = self.rom_read(rom, dir_addr, 16 * (u64::from(count) + 2)) else {
            return Vec::new();
        };
        // `fet.py:101`: entries begin at 0x20; the reserved block is zero.
        if combo[0x10..0x20].iter().any(|&b| b != 0) {
            return Vec::new();
        }
        let mut out = Vec::new();
        for entry in combo[0x20..].chunks_exact(16) {
            let addr = le_u32(&entry[8..12]);
            if addr == 0 || addr == 0xFFFF_FFFF {
                continue;
            }
            let id = PspGenerationId(le_u32(&entry[4..8]));
            out.push((mask_pointer(addr, rom), generation_label(id)));
        }
        out
    }

    /// `Directory.create_directories_if_not_exist` (`directory.py:57-101`).
    fn create_directories(
        &mut self,
        rom: RomCtx,
        offset: u64,
        generation: Option<String>,
    ) -> Vec<usize> {
        // Explicit stack (pre-order, children pushed in reverse): an L2 chain can
        // be arbitrarily long.
        let mut created = Vec::new();
        let mut stack = vec![(offset, generation)];
        while let Some((offset, generation)) = stack.pop() {
            if let Some(&id) = self.dir_cache.get(&(rom.id, offset)) {
                self.update_zen_generation(rom.id, id, generation.as_deref());
                created.push(id);
                continue;
            }
            let Some(id) = self.parse_directory(rom, offset, generation.clone()) else {
                continue;
            };
            self.dir_cache.insert((rom.id, offset), id);
            self.model.directories_by_offset.push((offset, id));
            created.push(id);

            let mut children: Vec<(u64, Option<String>)> = self.model.dirs[id]
                .secondary
                .iter()
                .map(|&secondary| (secondary, generation.clone()))
                .collect();
            // `directory.py:86-99`: a tertiary entry points at a 32-byte block whose
            // `[16:20]` is the directory offset and `[20:24]` its PSP id.
            for tertiary in self.model.dirs[id].tertiary.clone() {
                let Some(block) = self.rom_read(rom, tertiary, 32) else {
                    continue;
                };
                let actual = u64::from(le_u32(&block[16..20]));
                let label = generation_label(PspGenerationId(le_u32(&block[20..24])));
                children.push((actual, Some(label)));
            }
            stack.extend(children.into_iter().rev());
        }
        created
    }

    /// `Directory.update_zen_generation` (`directory.py:243-249`). Upstream
    /// raises `TypeError` when the cached directory has no generation yet; we
    /// adopt the incoming one instead.
    fn update_zen_generation(&mut self, rom: usize, id: usize, generation: Option<&str>) {
        let Some(generation) = generation else {
            return;
        };
        let mut stack = vec![id];
        while let Some(id) = stack.pop() {
            let current = &mut self.model.dirs[id].zen_generation;
            match current {
                Some(existing) if existing.contains(generation) => continue,
                Some(existing) => {
                    existing.push('\n');
                    existing.push_str(generation);
                }
                None => *current = Some(generation.to_owned()),
            }
            let children: Vec<usize> = self.model.dirs[id]
                .secondary
                .iter()
                .filter_map(|secondary| self.dir_cache.get(&(rom, *secondary)).copied())
                .collect();
            stack.extend(children.into_iter().rev());
        }
    }

    /// `Directory.from_offset` + `Directory.__init__` (`directory.py:104-165`).
    fn parse_directory(
        &mut self,
        rom: RomCtx,
        requested: u64,
        generation: Option<String>,
    ) -> Option<usize> {
        let offset = requested & rom.addr_mask();
        let magic = self.rom_read(rom, offset, 4)?;
        let bios = if PSP_MAGICS.iter().any(|m| m[..] == magic[..]) {
            false
        } else if BIOS_MAGICS.iter().any(|m| m[..] == magic[..]) {
            true
        } else {
            // `directory.py:108-117`: empty slots are skipped; an unknown magic
            // aborts upstream and is skipped here.
            return None;
        };
        let window = self.rom_window(rom)?;
        let records: Vec<EntryRecord> =
            match Directory::parse_at(&window, FlashOffset(rom.origin + offset)).ok()? {
                Directory::Psp(d) => d.entries.into_iter().map(EntryRecord::Psp).collect(),
                Directory::Bios(d) => d.entries.into_iter().map(EntryRecord::Bios).collect(),
                Directory::Combo(_) => return None,
            };
        let id = self.model.dirs.len();
        let header = self.rom_read(rom, offset, DIRECTORY_HEADER_SIZE as u64)?;
        let additional_info = le_u32(&header[12..16]);
        self.model.dirs.push(DirNode {
            rom: rom.id,
            offset,
            bios,
            count: records.len() as u64,
            zen_generation: generation,
            records,
            files: Vec::new(),
            secondary: Vec::new(),
            tertiary: Vec::new(),
        });

        // `directory.py:150-153`: create/link files in table order.
        let entries = self.model.dirs[id].records.len();
        for index in 0..entries {
            if let Some(file) = self.create_file(rom, id, index, additional_info) {
                self.model.dirs[id].files.push(file);
            }
        }
        // `directory.py:159-163`.
        for index in 0..entries {
            let record = &self.model.dirs[id].records[index];
            let t = record.entry_type();
            let is_secondary = t.is_secondary_directory_pointer();
            let is_tertiary = t.is_tertiary_directory_pointer();
            if !(is_secondary || is_tertiary) {
                continue;
            }
            let Some(target) = file_offset(&self.model.dirs[id], index, additional_info, rom.size)
            else {
                continue;
            };
            let dir = &mut self.model.dirs[id];
            if is_secondary {
                dir.secondary.push(target);
            } else {
                dir.tertiary.push(target);
            }
        }
        Some(id)
    }

    /// `File.create_file_if_not_exists` (`file.py:39-56`).
    fn create_file(
        &mut self,
        rom: RomCtx,
        dir: usize,
        index: usize,
        additional_info: u32,
    ) -> Option<usize> {
        let node = &self.model.dirs[dir];
        let record = &node.records[index];
        let fo = file_offset(node, index, additional_info, rom.size)?;
        // `file.py:43-46`: APOBs carry no location; they bypass the cache.
        if node.bios && record.entry_type().get() == 0x61 {
            return self.parse_file(rom, dir, index, fo);
        }
        if let Some(&file) = self.file_cache.get(&(rom.id, fo)) {
            self.model.files[file].references.push(dir);
            return Some(file);
        }
        let file = self.parse_file(rom, dir, index, fo)?;
        self.file_cache.insert((rom.id, fo), file);
        self.model.files_by_offset.push((fo, file));
        Some(file)
    }

    /// `File.from_entry` + `File.__init__` + the subclass `_parse`
    /// (`file.py:249-329`). `None` is a `File.ParseError` (or an upstream
    /// abort, see the module docs).
    fn parse_file(&mut self, rom: RomCtx, dir: usize, index: usize, fo: u64) -> Option<usize> {
        let node = &self.model.dirs[dir];
        let record = &node.records[index];
        let t = record.entry_type();
        // `file.py:251`.
        if fo >= rom.size {
            return None;
        }
        let (offset, base_size) = self.base_buffer(rom, node, index, fo)?;
        let (kind, size) = if t.is_pubkey() {
            self.check_pubkey(rom, offset, base_size)?;
            (FileKind::Pubkey, base_size)
        } else if t.is_key_store() {
            let sizing = self.header_sizing(rom, offset, base_size, true)?;
            self.check_key_store(rom, offset, sizing)?;
            let kind = FileKind::KeyStore {
                signature_len: sizing.signature_len,
            };
            (kind, sizing.buffer_size)
        } else if !(t.has_no_header() || t.is_secondary_directory_pointer()) {
            let sizing = self.header_sizing(rom, offset, base_size, false)?;
            let kind = FileKind::Header {
                signature_len: sizing.signature_len,
            };
            (kind, sizing.buffer_size)
        } else if node.bios && t.get() == 0x66 {
            let header = self.header_sizing(rom, offset, base_size, false);
            (FileKind::Microcode { header }, base_size)
        } else if node.bios {
            (FileKind::Bios, base_size)
        } else {
            (FileKind::Plain, base_size)
        };
        let id = self.model.files.len();
        self.model.files.push(FileNode {
            rom: rom.id,
            dir,
            entry: index,
            offset,
            size,
            kind,
            references: vec![dir],
        });
        Some(id)
    }

    /// `File.__init__` buffer placement (`file.py:285-319`):
    /// `(rom-relative offset, size)`.
    fn base_buffer(
        &self,
        rom: RomCtx,
        node: &DirNode,
        index: usize,
        fo: u64,
    ) -> Option<(u64, u64)> {
        let record = &node.records[index];
        let t = record.entry_type();
        if t.is_soft_fuse_chain() {
            // `file.py:287-292`: the entry record itself.
            let start =
                node.offset + DIRECTORY_HEADER_SIZE as u64 + index as u64 * node.entry_size();
            return (start + node.entry_size() <= rom.size).then_some((start, node.entry_size()));
        }
        let size = u64::from(record.size());
        if fo + size <= rom.size {
            return Some((fo, size));
        }
        // `file.py:302-318`: an overrunning compressed BIOS entry is sized from
        // its embedded zlib stream; anything else is a ParseError.
        let compressed = matches!(record, EntryRecord::Bios(b) if b.is_compressed());
        if !compressed {
            return None;
        }
        let tail = self.rom_read(rom, fo, (rom.size - fo).min(0x500))?;
        let zlib_header = zlib_find_header(&tail)?;
        let zlib_size = u64::from(self.rom_u32(rom, fo + 0x14)?);
        let size = zlib_header + zlib_size;
        (fo + size <= rom.size).then_some((fo, size))
    }

    /// `HeaderFile._parse` / `_parse_hdr` sizing and its `ParseError`s
    /// (`header_file.py:31-106`). `key_store` selects `KeyStoreFile`, whose
    /// `is_signed` is unconditionally true (`key_store_file.py:62-64`), so the
    /// `signed` dword is neither validated nor consulted.
    fn header_sizing(
        &self,
        rom: RomCtx,
        offset: u64,
        size: u64,
        key_store: bool,
    ) -> Option<HeaderSizing> {
        // `header_file.py:32-33`.
        let buffer_size = size.max(HEADER_LEN);
        let header = self.rom_read(rom, offset, HEADER_LEN)?;
        let window = SourceBytes::from_blob(header);
        let h = HeaderEntry::parse(&window).ok()?;
        // `header_file.py:69-70`.
        if h.has_sha256_checksum() && h.has_sha384_checksum() {
            return None;
        }
        // `header_file.py:72-75,104-105`: `rom_size` (or the buffer) wins.
        let rom_size = match u64::from(h.rom_size) {
            0 => buffer_size,
            n => n,
        };
        // `header_file.py:131-135`: an undocumented `signed` value is a
        // ParseError raised from `_parse`.
        if !key_store && !h.signed_value_is_documented() {
            return None;
        }
        let signature_len = if key_store || h.is_signed() {
            h.signature_len()? as u64
        } else {
            0
        };
        // `header_file.py:98-102`: an encrypted header needs a non-zero IV and
        // wrapped key.
        if h.is_encrypted && (h.iv == [0; 16] || h.wrapped_key == [0; 16]) {
            return None;
        }
        Some(HeaderSizing {
            buffer_size: rom_size,
            signature_len,
        })
    }

    /// `PubkeyFile._parse` assertions (`pubkey_file.py:53-91`).
    fn check_pubkey(&self, rom: RomCtx, offset: u64, size: u64) -> Option<()> {
        if size < PUBKEY_HEADER_LEN {
            return None;
        }
        let h = self.rom_read(rom, offset, PUBKEY_HEADER_LEN)?;
        let version = le_u32(&h[0..4]);
        let pubexp_bits = u64::from(le_u32(&h[0x38..0x3C]));
        let modulus_bits = u64::from(le_u32(&h[0x3C..0x40]));
        if !matches!(version, 1 | 2)
            || pubexp_bits != modulus_bits
            || !matches!(pubexp_bits, 2048 | 4096)
        {
            return None;
        }
        let material = 2 * (pubexp_bits / 8);
        if PUBKEY_HEADER_LEN + material > size {
            return None;
        }
        let pubexp = self.rom_read(rom, offset + PUBKEY_HEADER_LEN, pubexp_bits / 8)?;
        if pubexp[..4] != 0x10001u32.to_le_bytes() || pubexp[4..].iter().any(|&b| b != 0) {
            return None;
        }
        let signature = size - PUBKEY_HEADER_LEN - material;
        matches!(signature, 0 | 0x100 | 0x200).then_some(())
    }

    /// `KeyStoreFileHeader.__init__` assertions (`key_store_file.py:71-89`).
    fn check_key_store(&self, rom: RomCtx, offset: u64, sizing: HeaderSizing) -> Option<()> {
        let h = self.rom_read(rom, offset, KEY_STORE_HEADER_LEN)?;
        let magic = &h[0x10..0x14];
        if magic != b"$PS1" && magic != [0; 4] {
            return None;
        }
        let body_size = u64::from(le_u32(&h[0x14..0x18]));
        let packed_size = u64::from(le_u32(&h[0x6C..0x70]));
        let signature_size = if packed_size != 0 {
            packed_size.checked_sub(KEY_STORE_HEADER_LEN + body_size)?
        } else {
            sizing
                .buffer_size
                .checked_sub(body_size + KEY_STORE_HEADER_LEN)?
        };
        let keystore_type = le_u32(&h[0x7C..0x80]);
        let constants_ok = le_u32(&h[0x30..0x34]) == 1 && le_u32(&h[0x34..0x38]) == 2;
        (matches!(signature_size, 0x100 | 0x200)
            && constants_ok
            && matches!(keystore_type, 0 | 0x50 | 0x51))
        .then_some(())
    }

    fn read(&self, abs: u64, len: u64) -> Option<Vec<u8>> {
        self.image
            .subslice_at(abs..abs.checked_add(len)?)
            .map(|s| s.as_bytes().to_vec())
    }

    /// Read inside the ROM window (upstream's `NestedBuffer` bounds).
    fn rom_read(&self, rom: RomCtx, offset: u64, len: u64) -> Option<Vec<u8>> {
        if offset.checked_add(len)? > rom.size {
            return None;
        }
        self.read(rom.origin + offset, len)
    }

    fn rom_u32(&self, rom: RomCtx, offset: u64) -> Option<u32> {
        self.rom_read(rom, offset, 4).map(|b| le_u32(&b))
    }

    /// The ROM as a [`SourceBytes`] window with absolute offsets, so the core
    /// parsers bound every read by the ROM like upstream's `NestedBuffer`.
    fn rom_window(&self, rom: RomCtx) -> Option<SourceBytes> {
        self.image
            .subslice_at(rom.origin..rom.origin.checked_add(rom.size)?)
    }
}

/// FET / combo pointer masking (`fet.py:68-71`, `:108-114`).
const fn mask_pointer(raw: u32, rom: RomCtx) -> u64 {
    let raw = raw as u64;
    if raw > 0xFF00_0000 && rom.size > PAGE_SIZE {
        raw & 0x00FF_FFFF
    } else {
        raw & rom.addr_mask()
    }
}

/// `DirectoryEntry.file_offset()` (`entry.py:38-70`): the ROM-relative offset
/// entry `index` of `dir` points at, for a ROM of `rom_size` bytes.
pub fn file_offset(
    dir: &DirNode,
    index: usize,
    additional_info: u32,
    rom_size: u64,
) -> Option<u64> {
    let record = dir.records.get(index)?;
    let entry_rsv0 = match record {
        EntryRecord::Psp(p) => p.rsv0,
        EntryRecord::Bios(b) => b.rsv0,
    };
    resolve_file_offset(
        record.entry_type(),
        additional_info,
        entry_rsv0,
        record.offset().get(),
        dir.offset,
        index as u64 * dir.entry_size(),
        rom_size,
    )
}

/// `DirectoryEntry.file_offset()` (`entry.py:38-70`) over raw field values,
/// shared by the model and the live `DirectoryEntry.file_offset()` method.
/// Delegates the address-mode arithmetic to `psptool-core`
/// ([`AddressMode::resolve_with_entry`]) with the ROM at origin 0, so the
/// result is ROM-relative.
pub fn resolve_file_offset(
    entry_type: EntryType,
    additional_info: u32,
    entry_rsv0: u32,
    entry_offset_field: u32,
    dir_offset: u64,
    entry_offset_in_body: u64,
    rom_size: u64,
) -> Option<u64> {
    // `entry.py:40-42`: the soft-fuse chain lives inside the table.
    if entry_type.is_soft_fuse_chain() {
        return Some(dir_offset + DIRECTORY_HEADER_SIZE as u64 + entry_offset_in_body);
    }
    let ctx = ResolveContext {
        rom_size: RomSize::new(rom_size)?,
        directory_base: FlashOffset(dir_offset),
        rom_origin: FlashOffset::ZERO,
    };
    let dir_mode = AddressMode::from_additional_info(additional_info);
    let entry_mode = AddressMode::from_entry_rsv0(entry_rsv0);
    Some(
        dir_mode
            .resolve_with_entry(entry_mode, Address(entry_offset_field), ctx)
            .get(),
    )
}

/// `Directory.get_possible_zen_generation` + the `' (PSP ID 0x..)'` suffix
/// (`directory.py:34-48`, `:89-95`; `fet.py:117-123`).
pub fn generation_label(id: PspGenerationId) -> String {
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

/// `utils.zlib_find_header` (`utils.py:209-234`): offset of the first zlib
/// magic in `s[:0x500]`, checking `0x100` first for each magic.
pub fn zlib_find_header(s: &[u8]) -> Option<u64> {
    let window = &s[..s.len().min(psptool_core::body::ZLIB_SEARCH_WINDOW)];
    for magic in psptool_core::body::ZLIB_MAGICS {
        if window.get(0x100..0x102) == Some(magic.as_slice()) {
            return Some(0x100);
        }
        if let Some(pos) = window.windows(2).position(|w| w == magic) {
            return Some(pos as u64);
        }
    }
    None
}

/// `Rom._find_agesa_version` matches (`rom.py:24-52`): every match of
/// `AGESA!..\x00.*?\x00` (no `re.DOTALL`: `.` excludes `\n`), deduplicated in
/// first-seen order, rendered `NUL -> ' '`, stripped, ASCII-decoded.
pub fn find_agesa_versions(rom: Vec<u8>) -> Vec<String> {
    const PREFIX: &[u8] = b"AGESA!";
    let mut found: Vec<Vec<u8>> = Vec::new();
    let mut i = 0;
    while i + PREFIX.len() + 3 <= rom.len() {
        if &rom[i..i + PREFIX.len()] != PREFIX {
            i += 1;
            continue;
        }
        let p = i + PREFIX.len();
        let matched = if rom[p] != b'\n' && rom[p + 1] != b'\n' && rom[p + 2] == 0 {
            // `.*?\x00`: the first NUL after `p + 3` with no `\n` before it.
            rom[p + 3..]
                .iter()
                .position(|&b| b == 0 || b == b'\n')
                .filter(|&n| rom[p + 3 + n] == 0)
                .map(|n| p + 3 + n + 1)
        } else {
            None
        };
        match matched {
            Some(end) => {
                let m = rom[i..end].to_vec();
                if !found.contains(&m) {
                    found.push(m);
                }
                i = end;
            }
            None => i += 1,
        }
    }
    found
        .into_iter()
        .map(|m| {
            let text: Vec<u8> = m.iter().map(|&b| if b == 0 { b' ' } else { b }).collect();
            String::from_utf8_lossy(strip_python_whitespace(&text)).into_owned()
        })
        .collect()
}

/// `bytes.strip()` with no argument: strips `b' \t\n\r\x0b\x0c'` (unlike
/// [`slice::trim_ascii`], which keeps `\x0b`).
fn strip_python_whitespace(b: &[u8]) -> &[u8] {
    let ws = |c: &u8| matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C);
    let start = b.iter().position(|c| !ws(c)).unwrap_or(b.len());
    let end = b.iter().rposition(|c| !ws(c)).map_or(start, |e| e + 1);
    &b[start..end]
}

fn le_u32(b: &[u8]) -> u32 {
    let mut word = [0u8; 4];
    word.copy_from_slice(&b[..4]);
    u32::from_le_bytes(word)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_label_matches_upstream_format() {
        // `fet.py:117-123`: name from bytes [5:8], id from [4:8] via `hex()`.
        assert_eq!(
            generation_label(PspGenerationId(0xBC0B_0500)),
            "Zen 2 (PSP ID 0xbc0b0500)"
        );
        assert_eq!(
            generation_label(PspGenerationId(0xBC0D_0300)),
            "Zen 4/5 (PSP ID 0xbc0d0300)"
        );
        assert_eq!(
            generation_label(PspGenerationId(0x1234_5678)),
            "unknown (PSP ID 0x12345678)"
        );
    }

    #[test]
    fn agesa_regex_semantics() {
        let mut rom = vec![0xFFu8; 64];
        rom[4..4 + 26].copy_from_slice(b"AGESA!V9\0Combo-AM4 1.0.0.2");
        rom[30] = 0;
        // A duplicate is reported once.
        rom.extend_from_slice(b"AGESA!V9\0Combo-AM4 1.0.0.2\0");
        // A `\n` inside `.*?` defeats the match.
        rom.extend_from_slice(b"AGESA!V9\0bad\nname\0");
        assert_eq!(find_agesa_versions(rom), vec!["AGESA!V9 Combo-AM4 1.0.0.2"]);
    }

    #[test]
    fn zlib_header_prefers_0x100() {
        let mut s = vec![0u8; 0x200];
        s[0x10..0x12].copy_from_slice(&[0x78, 0x9C]);
        s[0x100..0x102].copy_from_slice(&[0x78, 0xDA]);
        assert_eq!(zlib_find_header(&s), Some(0x100));
        s[0x100..0x102].copy_from_slice(&[0, 0]);
        assert_eq!(zlib_find_header(&s), Some(0x10));
        assert_eq!(zlib_find_header(&[0u8; 0x600]), None);
    }

    #[test]
    fn soft_fuse_offset_is_inside_the_table() {
        // `entry.py:40-42`.
        let off = resolve_file_offset(EntryType(0x0B), 0, 0, 0xDEAD, 0x1000, 0x20, 16 << 20);
        assert_eq!(off, Some(0x1000 + 0x10 + 0x20));
    }

    #[test]
    fn mode0_upper_window_override() {
        // `entry.py:50-60`: > 0xFF000000 in a 32 MiB ROM masks to 24 bits.
        let mode0_v1 = 1u32 << 31; // v1 header, bits[25:24] = 00
        let off = resolve_file_offset(EntryType(1), mode0_v1, 0, 0xFF12_3456, 0, 0, 32 << 20);
        assert_eq!(off, Some(0x12_3456));
        let off = resolve_file_offset(EntryType(1), mode0_v1, 0, 0x0112_3456, 0, 0, 32 << 20);
        assert_eq!(off, Some(0x0112_3456));
    }
}
