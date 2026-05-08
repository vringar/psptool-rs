# Reference PSPTool surface survey

Source: [PSPReverse/PSPTool](https://github.com/PSPReverse/PSPTool) (master, surveyed 2026-05-08).
Files audited: `psptool/__main__.py`, `psptool/psptool.py`, `psptool/blob.py`, `psptool/rom.py`,
`psptool/fet.py`, `psptool/directory.py`, `psptool/entry.py`, `psptool/file.py`,
`psptool/header_file.py`, `psptool/pubkey_file.py`, `psptool/microcode_file.py`,
`psptool/cert_tree.py`, `psptool/utils.py`, `psptool/__init__.py`, and
`tests/integration/test_rom_files.py`.

This is a design note. Implementation is out of scope (see issue #3). It captures what the Rust
port must reproduce in semantics and (for the CLI) byte-exact output.

---

## 1. Command-line surface

The CLI is wired in `psptool/__main__.py` using `argparse` (via `ObligingArgumentParser`,
which is `argparse.ArgumentParser` with auto-help on parse error). Help strings for every flag
except the four action flags are explicitly suppressed (`help=SUPPRESS`); flag documentation
lives only in the action-flag epilogs.

### 1.1 Action mode (mutually exclusive, optional, defaults to `-E`)

When no action flag is given but a `file` positional is present, the tool falls through to the
`-E` (entries) listing branch. With no `file`, it prints help and exits 0.

| Short | Long             | Behavior                                                                                                              |
|-------|------------------|-----------------------------------------------------------------------------------------------------------------------|
| `-V`  | `--version`      | Print `psptool.__version__` (read from `importlib.metadata.version("psptool")`) to stdout and exit 0.                 |
| `-E`  | `--entries`      | Default. Parse and list PSP firmware. See output-format modifiers below.                                              |
| `-X`  | `--extract-file` | Extract one file (with `-d` + `-e`, or `-T` regex) or every file (no selector) to `outfile`/`outdir`.                 |
| `-R`  | `--replace-file` | Splice `--subfile` into `(rom-index, directory-index, file-index)`, optionally re-sign, write whole ROM to `outfile`. |

The action group is `add_mutually_exclusive_group(required=False)`. Unrecognized combinations
fall through to the `-E` default branch.

### 1.2 Selectors (apply to `-X` and `-R`)

| Short | Long                | Type | Default        | Meaning                                                                                                |
|-------|---------------------|------|----------------|--------------------------------------------------------------------------------------------------------|
| `-r`  | `--rom-index`       | int  | `0`            | ROM index inside the blob (some BIOS images contain multiple ROMs, e.g. Naples + Rome).                |
| `-d`  | `--directory-index` | int  | (none)         | Directory index inside the chosen ROM. Required for single-file `-R`. Optional for `-X`.               |
| `-e`  | `--file-index`      | int  | (none)         | File index inside the chosen directory. Required for `-R`. Required + valid for single-file `-X`.      |
| `-T`  | `--type-regex`      | str  | (none)         | Alternative to `-d -e` for `-X`: case-insensitive regex matched against `file.get_readable_type()`.    |

`-T` semantics (from `find_files_by_type_regex` in `__main__.py`):
- 0 matches → `print_error_and_exit`.
- 1 match → extract that file.
- N matches, identical bytes → emit warning, extract the first.
- N matches, differing bytes → `print_error_and_exit` ("Not extracting any.").

### 1.3 Output / transform modifiers

| Short | Long                | Type | Default | Used by  | Meaning                                                                                                                  |
|-------|---------------------|------|---------|----------|--------------------------------------------------------------------------------------------------------------------------|
| `-o`  | `--outfile`         | str  | (none)  | `-X`/`-R`| Output file (single-file `-X`) or output dir (multi-file `-X`). Default for stdout (single) or `./{file}_extracted/`.    |
| `-u`  | `--decompress`      | flag | false   | `-X`     | Emit `HeaderFile.get_signed_bytes()` (header + decrypted+decompressed body, truncated to `size_signed`). Errors if file is not compressed in single-file mode. |
| `-c`  | `--decrypt`         | flag | false   | `-X`     | Single: emit `to_decrypted_file_bytes()` (clears encrypted-bit + IV in header, body decrypted). Multi: emit `get_decrypted_body()`. Errors if file not encrypted in single-file mode. |
| `-k`  | `--pem-key`         | flag | false   | `-X`     | For `PubkeyFile`, emit `get_pem_encoded()`. In multi-file mode silently ignored for non-pubkey files.                    |
| `-n`  | `--no-duplicates`   | flag | false   | `-E`/`-X`| `-E`: call `psp.ls_files()` (flat unique-files list). `-X`: iterate `psp.blob.unique_files()` and write to `./{file}_unique_extracted/`. |
| `-j`  | `--json`            | flag | false   | `-E`     | Emit `psp.ls_json(verbose=...)` instead of pretty tables.                                                                |
| `-t`  | `--key-tree`        | flag | false   | `-E`     | Print `psp.cert_tree.print_key_tree()`.                                                                                  |
| `-m`  | `--metrics`         | flag | false   | `-E`     | Emit `psp.print_metrics()` (filename, error/warning/info counts, rom/directory/unique-file counts).                      |
| `-v`  | `--verbose`         | flag | false   | global   | Adds `flags`, `MD5`, `size_signed`, `size_full`, `size_packed`, `load_addr` columns to `ls`; adds extra info to `ls_json`. Also threads through to `PrintHelper` for warnings/info to stderr. |

### 1.4 Re-signing options (apply to `-R`)

| Short | Long             | Type | Meaning                                                                              |
|-------|------------------|------|--------------------------------------------------------------------------------------|
| `-s`  | `--subfile`      | str  | Path to new file contents. If omitted, `-R` becomes a "plain re-sign" of the entry. |
| `-p`  | `--privkeystub`  | str  | Stub for re-signing keys (e.g. `keys/id`); `PrivateKeyDict.read_from_files` consumer. |
| `-a`  | `--privkeypass`  | str  | Password for the re-signing keys.                                                    |

Re-sign flow when `-R` is selected and `-d -e -o` are all set:
1. Resolve `file = psp.blob.roms[rom_index].directories[d].files[e]`.
2. If `-s subfile` given: read it, `file.move_buffer(file.get_address(), len(sub))`, `file.set_bytes(0, len(sub), sub)`.
3. If `-p` given: load `PrivateKeyDict`.
4. If `file.signed_entity`: `file.signed_entity.resign_and_replace(privkeys, recursive=True)`.
   Else: warn "Did not resign anything since target file is not signed".
5. `psp.to_file(args.outfile)`.
6. If `privkeys` were used: `privkeys.save_to_files(stub, password)`.

### 1.5 Positional

| Name   | Required | Meaning                                       |
|--------|----------|-----------------------------------------------|
| `file` | yes for any action other than `-V`/no-args | Path to a UEFI ROM image (raw flash dump). Read fully into a `bytearray`. |

### 1.6 Output-format matrix

| Mode | Pretty table              | JSON               | Tree                | Metrics            | File bytes (stdout / file) |
|------|---------------------------|--------------------|---------------------|--------------------|----------------------------|
| `-E` (no flag)        | ✓ `psp.ls()`   |                    |                     |                    |                            |
| `-E -n`               | ✓ `psp.ls_files()` |                    |                     |                    |                            |
| `-E -j`               |                    | ✓ `psp.ls_json()` |                     |                    |                            |
| `-E -t`               |                    |                    | ✓ key tree          |                    |                            |
| `-E -m`               |                    |                    |                     | ✓                  |                            |
| `-X` single (stdout)  |                    |                    |                     |                    | ✓ stdout (binary)          |
| `-X` single (`-o`)    |                    |                    |                     |                    | ✓ `outfile`                |
| `-X` multi            |                    |                    |                     |                    | ✓ `outdir/d{NN}_e{NN}_{TYPE}[…]` |
| `-X -n` multi         |                    |                    |                     |                    | ✓ `outdir/{TYPE}[_{ver}]`  |
| `-R`                  |                    |                    |                     |                    | ✓ entire ROM written to `outfile` |

### 1.7 Multi-file extraction filename rules

For `-X` without `-e` (multi-file mode), per `__main__.py`:

- Default outdir: `./{psp.filename}_extracted` (or `./{psp.filename}_unique_extracted` for `-n`).
- Per-file path: `outdir/d{dir_index:02d}_e{file_index:02d}_{readable_type}`.
- Append `_SUB_{hex}_INS_{hex}` if `entry.subprogram != 0` or `entry.instance != 0`.
- Append `_{readable_version}` if the file is a `HeaderFile`.
- For `-n` mode the path is `outdir/{readable_type}[_{readable_version}]` (no dir/entry prefix).

---

## 2. Python API surface

What `from psptool import PSPTool` exposes, and what the integration tests in
`tests/integration/test_rom_files.py` actually exercise.

### 2.1 Object graph

```
PSPTool
├── filename: str | None
├── ph: PrintHelper                     (warning/info/error tracking)
├── blob: Blob                          (the raw bytearray, owns everything)
│   ├── buffer_size: int
│   ├── roms: list[Rom]
│   │   ├── addr_mask: int              (rom_size - 1)
│   │   ├── agesa_version: str
│   │   ├── fet: Fet
│   │   └── directories: list[Directory]
│   │       ├── magic: bytes            ($PSP/$PL2/$BHD/$BL2/...)
│   │       ├── zen_generation: str
│   │       ├── address_mode: int       (0..3)
│   │       ├── secondary_directory_offsets: list[int]
│   │       ├── tertiary_directory_offsets: list[int]
│   │       ├── entries: list[DirectoryEntry | BiosDirectoryEntry]
│   │       └── files:   list[File | HeaderFile | PubkeyFile | KeyStoreFile | MicrocodeFile | BiosFile]
│   ├── range_dict: RangeDict           (address → file/dir/fet)
│   └── unique_files() -> set[File]
├── cert_tree: CertificateTree          (built from blob; holds SignedEntity/PublicKeyEntity nodes)
├── directories_by_offset: dict[int, Directory]
└── files_by_offset:       dict[int, File]
```

All buffer-bearing nodes (`Blob`, `Rom`, `Fet`, `Directory`, `DirectoryEntry`, `File` and
subclasses) inherit from `NestedBuffer`, which provides:

- `buffer_size: int`, `buffer_offset: int`, `parent_buffer`
- `__len__`, `__getitem__`/`__setitem__` (bytes-like, supports slicing)
- `get_address() -> int` (recursive offset into the root buffer)
- `get_buffer()` (returns the parent — confusing but that's the API)
- `get_bytes(offset=0, size=None) -> bytes`
- `set_bytes(address, size, value)` (length-checked)
- `get_chunks(size, offset=0)`

### 2.2 `class PSPTool`

| Member                              | Kind     | Notes                                                                                        |
|-------------------------------------|----------|----------------------------------------------------------------------------------------------|
| `PSPTool.from_file(filename, verbose=False)` | classmethod | Reads the file as `bytearray`, constructs a `PSPTool`. Returns the instance.            |
| `PSPTool(rom_bytes, verbose=False, filename=None)` | ctor   | Builds `Blob` and `CertificateTree`.                                                  |
| `to_file(filename)`                 | method   | Writes `self.blob.get_buffer()` to disk.                                                     |
| `to_stdout()`                       | method   | Writes the same bytes to `sys.stdout.buffer`.                                                |
| `ls(verbose=False)`                 | method   | Prints per-ROM and per-directory `PrettyTable`s, then per-directory file table via `ls_dir`. |
| `ls_dir(rom, directory_index, verbose=False)` | method   | Prints one directory's file table.                                                  |
| `ls_files(files=None, verbose=False)` | method   | Prints a flat file table; `files=None` defaults to `sorted(self.blob.unique_files())`. Verbose adds `flags/MD5/size_signed/size_full/size_packed/load_addr`. |
| `ls_json(verbose=False)`            | method   | Prints a single `json.dumps(data)` line: list of `{directory, address, magic, secondaryAddresses, entries: [...]}`. Note JSON shape uses the legacy term "entries" for what are now `files`. |
| `ls_dir_dict(rom, directory_index, verbose=False)` | method | Helper for `ls_json`; returns `list[dict]`.                                       |
| `ls_files_dict(files=None)`         | method   | Per-file dict shape: `{index, address, size, sectionType, magic, version, info, md5, [destinationAddress], [sizes]}`. |
| `print_metrics()`                   | method   | Prints filename plus error/warning/info counts and rom/directory/unique-file counts.         |
| `filename`                          | attr     | The path passed to `from_file`, or `None`.                                                   |
| `blob`                              | attr     | `Blob` instance.                                                                             |
| `cert_tree`                         | attr     | `CertificateTree` instance.                                                                  |
| `directories_by_offset`, `files_by_offset` | attr | Dedup caches, populated during parse.                                                  |

### 2.3 `class Blob` (`psptool/blob.py`)

| Member                                  | Notes                                                                                       |
|-----------------------------------------|---------------------------------------------------------------------------------------------|
| `roms: list[Rom]`                       | Found by scanning for `\xff\xff\xff\xff\xAA\x55\xAA\x55` and `\x00…\xAA\x55\xAA\x55`.       |
| `range_dict: RangeDict`                 | Address → `File`/`Directory`/`Fet` lookup over the entire buffer.                           |
| `unique_files() -> set[File]`           | Flatten `[d.files for r in roms for d in r.directories]` and dedup by `File.__hash__`.      |
| `get_files_by_type(type_) -> list[File]`| Filter `unique_files()` by `file.type == type_`.                                            |
| `find_inline_pubkey_entries(ids)`       | Locate inline `PubkeyFile`s embedded in other files via fingerprint scan.                   |
| `_FIRMWARE_ENTRY_MAGIC = b'\xAA\x55\xAA\x55'`, `_MAX_PAGE_SIZE = 16 MiB`                                                       |

### 2.4 `class Rom`

| Member                                  | Notes                                                                                        |
|-----------------------------------------|----------------------------------------------------------------------------------------------|
| `addr_mask: int`                        | `rom_size - 1`. Used to mask x86 physical addresses into flash offsets.                      |
| `agesa_version: str`                    | First match of `b"AGESA!..\x00.*?\x00"`, `'AGESA_UNKNOWN'` if none.                          |
| `agesa_version_second: str` (optional)  | Set on dual-ROM images.                                                                      |
| `fet: Fet`                              | The Firmware Entry Table for this ROM.                                                       |
| `directories: list[Directory]`          | Aliased to `fet.directories`.                                                                |
| `unique_entries: set`, `pubkeys: dict`  | Populated during parse.                                                                      |

### 2.5 `class Directory` and `BiosDirectory`

| Member                                              | Notes                                                                                          |
|-----------------------------------------------------|------------------------------------------------------------------------------------------------|
| `DIRECTORY_MAGICS = [b'$PSP', b'$PL2']` (`Directory`), `[b'$BHD', b'$BL2']` (`BiosDirectory`) | Magic discrimination lives in `from_offset`.                  |
| `HEADER_SIZE = 0x10`                                | Per-directory header.                                                                          |
| `ENTRY_CLASS`, `ENTRY_SIZE`, `FILE_CLASS`           | Class-level type wiring (overridden in `BiosDirectory`).                                       |
| `count`                                             | Property; setter updates header bytes and recomputes checksum.                                 |
| `magic: bytes`, `zen_generation: str`               | Set during parse.                                                                              |
| `address_mode: int (0..3)`                          | Decoded from `additional_info`. 0=x86 phys, 1=flash from BIOS, 2=from dir header, 3=from slot. |
| `secondary_directory_offsets`, `tertiary_directory_offsets: list[int]` | Discovered via entry-type bitmap.                                       |
| `entries: list[DirectoryEntry]`                     | Raw entry table (one per slot).                                                                |
| `files: list[File]`                                 | Parsed file objects (`None` entries filtered). Some entries dedup against existing files.      |
| `update_entry_fields(file, type_, size, offset)`    | Write back to the binary directory body and recompute checksum (used by replace-file flow).    |
| `verify_checksum()` / `update_checksum()`           | Fletcher-32 over `self[8:]`.                                                                   |

`ZEN_GENERATION_IDS` map — `Zen 1`/`Zen 2`/`Zen 3`/`Zen 4`/`Zen 4/5` keyed by 3-byte ID
prefixes (e.g. `\x00\x09\xBC`, `\x05\x0B\xBC`, …).

### 2.6 `class DirectoryEntry` and `BiosDirectoryEntry`

| Member                                | Type | Notes                                                                                  |
|---------------------------------------|------|----------------------------------------------------------------------------------------|
| `ENTRY_SIZE`                          | int  | `0x10` for PSP, `0x18` for BIOS.                                                       |
| `type` (1 B at +0)                    | int  |                                                                                        |
| `subprogram` (PSP: 1 B at +1; BIOS: bits 8..10 of `flags`) | int |                                                                |
| `flags` (2 B at +2)                   | int  |                                                                                        |
| `instance` (PSP: bits 3..6 of `flags`; BIOS: bits 4..7) | int |                                                                  |
| `size` (4 B at +4)                    | int  |                                                                                        |
| `offset` (4 B at +8)                  | int  |                                                                                        |
| `rsv0` (4 B at +12)                   | int  | Top two bits = entry-level `address_mode`.                                             |
| `address_mode` (bits 30..31 of `rsv0`)| int  | Per-entry override when the directory address mode is 2 or 3.                          |
| `region_type` (BIOS only, 1 B at +1)  | int  |                                                                                        |
| `destination` (BIOS only, 8 B at +16) | int  |                                                                                        |
| `file_offset()`                       | method | Resolves an entry's flash offset, applying address-mode and rom-size overrides. Special-cases soft-fuse-chain (type `0x0B`). |

All getters/setters serialize back into the underlying directory body bytes — so writes through
the API mutate the parsed ROM in place.

### 2.7 `class File` (and class hierarchy)

```
NestedBuffer
└── File
    ├── BiosFile               # type 0x62 in a BIOS directory; carries .destination
    ├── HeaderFile             # 0x100-byte AMD signed/encrypted/compressed header
    │   └── KeyStoreFile       # types 0x50, 0x51
    ├── MicrocodeFile          # type 0x66 in a BIOS directory
    └── PubkeyFile             # types in PUBKEY_ENTRY_TYPES (0x0, 0x9, 0xa, 0x5, 0xd, 0x43, 0x4e, 0x53, 0x81, 0x97, 0xad)
        └── InlinePubkeyFile   # pubkey discovered inside another file's body
```

Dispatch: `File.create_file_if_not_exists(directory, entry)` → `File.from_entry(...)` chooses
the subclass by `entry.type`, falling back to `File` for types in `NO_HDR_ENTRY_TYPES` or
`SECONDARY_DIRECTORY_ENTRY_TYPES`. APOB (`type 0x61` in BIOS) is intentionally never deduped
(absent location/size) and one is created per directory.

#### Common `File` API (used by CLI and tests)

| Member                            | Notes                                                                                          |
|-----------------------------------|------------------------------------------------------------------------------------------------|
| `entry: DirectoryEntry`           | Owning entry.                                                                                  |
| `type: int`                       | Mirror of `entry.type`.                                                                        |
| `compressed: bool`                | `False` for plain `File`, computed from header for `HeaderFile`, from BIOS flags for `BiosFile`. |
| `encrypted: bool`                 | Default `False`; set in `HeaderFile._parse`.                                                    |
| `is_legacy: bool`                 | Default `False`.                                                                                |
| `size_uncompressed: int`          | Set on `HeaderFile`; otherwise `0`.                                                             |
| `is_signed: bool`                 | Property; default `False`, overridden on `HeaderFile`.                                          |
| `signed_entity` (HeaderFile/PubkeyFile) | Set by `CertificateTree`. None for plain `File`.                                          |
| `references: list[Directory]`     | Every directory that points at this file (multi-directory files share one `File`).             |
| `parent_directory: Directory`     |                                                                                                |
| `get_bytes(offset=0, size=None)`  | Inherited from `NestedBuffer`. **This is what `entry.get_bytes()` resolves to in the integration tests.** |
| `get_address() -> int`            | Recursive offset; overridden on `BiosFile` so APOB returns 0.                                  |
| `get_readable_type() -> str`      | "`{NAME}~0x{type:x}`" or `"BIOS"`/`"APOB"`/`"0x{type:x}"`. The string the CLI's `-T` regex matches against. |
| `get_readable_destination_address() -> str` | Hex of `entry.destination` (BIOS files only).                                        |
| `get_readable_version() -> str`   | `''` on the base class.                                                                        |
| `get_readable_magic() -> str`     | `''` on the base class.                                                                        |
| `get_readable_signed_by() -> str` | `''` on the base class.                                                                        |
| `shannon_entropy() -> float`      |                                                                                                |
| `md5() -> str`                    | Hex digest of `get_bytes()`.                                                                   |
| `move_buffer(new_address, size)`  | Slide the file in the ROM and update every `references` directory's entry.                     |
| `__eq__`/`__hash__`/`__lt__`      | Equality on `(type, address, size)`. `__lt__` by address (so `sorted(unique_files())` works).  |

#### `class HeaderFile` (the workhorse)

`HEADER_LEN = 0x100`. Header layout (little-endian, byte offsets into the 0x100 header):

| Offset   | Field                                 |
|----------|---------------------------------------|
| `0x00`   | nonce / 0                             |
| `0x10`   | `magic` (4 B)                         |
| `0x14`   | `size_signed` (u32)                   |
| `0x18`   | `encrypted` (u32, 0/1)                |
| `0x20`   | `iv` (16 B, when `encrypted`)         |
| `0x30`   | `_signed` (u32: 0, 1, or 0xFFFF0000)  |
| `0x34`   | `signature_type` (u32: 0=2048, 2=4096)|
| `0x38`   | `signature_fingerprint` (16 B, hex)   |
| `0x48`   | `compressed` (u32, 0/1)               |
| `0x4c`   | `unknown_field_2` (u32)               |
| `0x50`   | `size_uncompressed` (u32)             |
| `0x54`   | `zlib_size` (u32)                     |
| `0x58`   | `bitfield` (u32 big-endian: bit0=sha256, bit1=sha384) |
| `0x5c..0x64` | `version` (4 B, byte-reversed for printing) |
| `0x68`   | `load_addr` (u32)                     |
| `0x6c`   | `rom_size` (u32)                      |
| `0x7c`   | `unknown_field_3` (u32)               |
| `0x80`   | `wrapped_key` (16 B, when `encrypted`)|
| `0xd0`   | `_sha256_checksum` (32 B) / `_sha384_checksum` (48 B) — overlapping at the same offset |

| Member                                    | Notes                                                                                       |
|-------------------------------------------|---------------------------------------------------------------------------------------------|
| `header: NestedBuffer` (0x100 B)          |                                                                                             |
| `body: NestedBuffer`                      | `len(self) - 0x100 - signature_len` starting at `0x100`.                                    |
| `signature: NestedBuffer` (0x100 / 0x200 B)| At `rom_size - signature_len`. `signature_len = 0` if not signed.                          |
| `magic`, `size_signed`, `encrypted`, `compressed`, `signature_type`, `signature_fingerprint`, `zlib_size`, `bitfield`, `version`, `load_addr`, `rom_size`, `size_uncompressed`, `unknown_field_2`, `unknown_field_3` | parsed scalars |
| `iv`, `key`                               | Set when `encrypted`.                                                                       |
| `has_sha256_checksum`, `has_sha384_checksum` | Bitfield bits.                                                                           |
| `inline_keys: set[PubkeyFile]`            | Populated by `Blob._find_inline_pubkeys`.                                                   |
| `is_signed -> bool`                       | Property: `_signed != 0`. Raises `ParseError` for unexpected values.                        |
| `verify_sha256()` / `verify_sha384()`     | Compares hash over `get_decrypted_decompressed_body()`.                                     |
| `update_sha256()`                         | Re-hashes after a body change.                                                              |
| `get_signed_bytes() -> bytes`             | `header + decrypted_decompressed_body`, truncated to `0x100 + size_signed`. **Used by CLI `-X -u`.** |
| `get_decrypted_body() -> bytes`           | Body bytes, AES-CBC-decrypted with the unwrapped IKEK if `encrypted`. Multi-file `-X -c` writes this. |
| `get_decrypted_decompressed_body() -> bytes` | Decrypts then zlib-decompresses (truncated to `zlib_size`). **Exercised by `test_extract_advanced`.** |
| `to_decrypted_file_bytes() -> bytes`      | Same file with header's `encrypted` flag and IV cleared, body decrypted, signature preserved. **Used by single-file `-X -c`.** |
| `get_unwrapped_ikek() -> bytes`           | Currently hardcoded to `UNWRAPPED_IKEK_ZEN_PLUS` (TODO in upstream).                        |
| `get_readable_version() -> str`           | `'.'.join(hex(b)[2:].upper() for b in self.version)`.                                       |
| `get_readable_magic() -> str`             | ASCII-printable form of `self.magic` (special-case `b'\x05\x00\x00\x00'` → `"0x05"`).       |
| `get_readable_signed_by() -> str`         | `signed_entity.certifying_id.magic`.                                                        |
| `get_checksummed_bytes() -> bytes`        | Alias for `get_decrypted_decompressed_body()`.                                              |

Note: there is **no** method literally named `get_decompressed_body` or `get_decrypted` on
`HeaderFile`. The closest mappings are `get_decrypted_decompressed_body()` (decrypt → maybe
decompress) and `get_decrypted_body()` (decrypt only). Issue #3's prose used the legacy names;
the implementation should match what the CLI and the integration tests actually call.

#### `class PubkeyFile`

| Member                                | Notes                                                                                  |
|---------------------------------------|----------------------------------------------------------------------------------------|
| `KNOWN_VERSIONS = {1, 2}`             |                                                                                        |
| `version`, `key_usage`, `security_features`, `key_id`, `certifying_id` | parsed scalars / 16-byte IDs              |
| `pubexp_bits`, `modulus_bits ∈ {2048, 4096}` | Always equal in-spec.                                                            |
| `crypto_material`, `_pubexp`, `_modulus`, `signature` | `NestedBuffer`s.                                                            |
| `get_modulus_bytes() -> bytes`        |                                                                                        |
| `get_der_encoded() -> bytes`          | RSA SPKI for 2048 / 4096; only `e=65537` supported, else `NotImplementedError`.        |
| `get_pem_encoded() -> bytes`          | DER → base64 → PEM-wrapped. **Used by CLI `-X -k`.**                                   |
| `get_readable_key_usage() -> str`, `get_readable_security_features() -> str` | Used by `ls_files()`.                              |

### 2.8 `class CertificateTree` (`psptool/cert_tree.py`)

Built once via `CertificateTree.from_blob(blob, psptool)` and stored on `PSPTool.cert_tree`.

| Member                                       | Notes                                                                            |
|----------------------------------------------|----------------------------------------------------------------------------------|
| `add_signed_entity` / `add_pubkey_entity` / `add_header_file` / `add_pubkey_file` / `add_key_store_file` | Builders.       |
| `unique_pubkeys(key_id)`                     |                                                                                  |
| `print_key_tree()`                           | **CLI `-E -t`.**                                                                 |
| Inner `class SignedEntity`: `is_verified()`, `is_verified_by(pubkey)`, `verify_with_tree()`, `verify_with_pubkey(pubkey)`, `resign_only(privkey)`, `resign_and_replace(privkeys=None, recursive=False)`, `get_address()`, `get_length()`, `get_range()` | **`resign_and_replace` is the CLI `-R` re-sign hook.** |
| Inner `class PublicKeyEntity`: `get_magic()`, `is_root()`, `get_certifying_keys()`, `get_certified_keys()`, `get_public_key() -> PublicKey`, `replace_crypto_material(bytes)`, `replace_only(pubkey)`, `replace_and_resign(privkeys=None, recursive=False)` |   |

### 2.9 What `tests/integration/test_rom_files.py` actually exercises

The reference test suite exercises only this surface (everything else is implementation
detail or covered by unit tests against synthetic blobs):

- `psptool.PSPTool.from_file(filename)` succeeds and yields `len(pt.blob.roms) > 0`.
- `pt.to_file('/dev/null')` round-trips without crashing.
- `pt.ls()`, `pt.ls(verbose=True)`, `pt.ls_files()`, `pt.ls_json()` all complete (output is
  redirected to `StringIO` and discarded; errors are by exception only).
- For every `entry in directory.entries`: `entry.get_bytes()` must return exactly
  `entry.buffer_size` bytes. Note the iteration uses `directory.entries` (raw
  `DirectoryEntry` objects, not the parsed files), and `get_bytes` is the inherited
  `NestedBuffer` method.
- For every `entry in directory.files` that is a `HeaderFile`: `entry.get_decrypted_decompressed_body()`
  completes with **no warnings written to stderr**. (The test asserts `stderr_buf.getvalue() == ""`.)

Out-of-scope upstream (and therefore out-of-scope for the v1 port unless explicitly added
to the Rust suite):

- Extraction tests: "extract entry and make sure it has the correct size" is a TODO in
  `test_rom_files.py`.
- Re-sign correctness: "only resign the ROM and check that it is parsed with the same output"
  is also a TODO.

### 2.10 Implications for the Rust port (informational, not a design decision)

- `directory.entries` and `directory.files` are **two different lists**. The first is the raw
  entry table (one slot per directory entry); the second is the parsed-and-deduped file list
  (entries that share a `file_offset` collapse onto one shared `File` with `references`).
  The Rust port needs both views, or an equivalent way to expose the raw entry table for
  byte-exact roundtripping.
- `File`/`HeaderFile`/etc. inherit from `NestedBuffer`, which means **every read goes through
  the original `bytearray`**. This is the mechanism that backs the project's "byte-exact
  roundtrip" goal: the parsed objects don't own their bytes, they alias them, and writes via
  `set_bytes`/property setters mutate the underlying buffer. The Rust port's "diff-and-patch"
  serialization rule (per `CLAUDE.md`) is the natural Rust analogue.
- `unique_files()` uses Python's `set` with `__eq__` / `__hash__` defined as
  `(type, address, buffer_size)`. The Rust port needs the same dedup key.
- The CLI's `-T` regex is matched against `get_readable_type()`, **not** against the entry
  type number. The full strings (`"FW_PSP_SMUSCS_OR_TPMLITE~0x5f"`, `"BIOS"`, `"APOB"`,
  `"0x208"`, …) are part of the user-visible surface and need to be reproduced verbatim if
  CLI compatibility is the goal.
- `to_decrypted_file_bytes()` (single-file `-X -c`) and `get_decrypted_body()` (multi-file
  `-X -c`) produce **different** outputs for the same file. This asymmetry is in the upstream
  CLI and should be preserved verbatim if the port aims for byte-exact CLI parity.
