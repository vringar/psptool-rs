# AMD PSP Firmware On-Disk Layout

This document is the parser specification for `psptool-rs`. It describes the
physical (on-flash) layout of an AMD PSP firmware image, the field-level
contents of every container the parser must traverse, and the address-mode
arithmetic required to walk between them. Every field is sourced from the
reference Python implementation
[`PSPReverse/PSPTool`](https://github.com/PSPReverse/PSPTool) and validated
against `vendor/test-corpus/test_files/AORUS_B450AE.F40` (a Zen 2 16 MiB image
with a Combo PSP directory) unless noted.

> **Goal of `psptool-rs`.** Parse the layout below and re-serialize an
> unmutated image **byte-for-byte identical** to the input. Roundtrip is
> verified by `psptool-fixtures` (issue #16) and integration tests (#17).
> Anything in the binary that this document does not describe must still
> survive a parse/serialize cycle — diff-and-patch, not reconstruct.

---

## 1. Top-level structure (the BIOS image envelope)

A PSP firmware **image** is whatever bytes you load from disk. That blob may be:

- a raw 8/16/32 MiB SPI flash dump (e.g. `Acer_R01-A4.CAP`, `AORUS_B450AE.F40`),
- a vendor capsule (`*.CAP`), or
- a UEFI payload that embeds one or more flash dumps end-to-end.

The PSP layer does not parse the envelope. It scans the input for one or more
**Firmware Entry Tables (FETs)** and treats each FET as the root of an
independent **ROM**.

```
+-------------------------------------------------------------+   offset 0
|              vendor / UEFI envelope (opaque)                |
|                                                             |
|     ...                                                     |
|                                                             |
|   FF FF FF FF | AA 55 AA 55 <-- FET magic, byte-aligned     |   <-- FET 0
|   <FET dword pointers, terminated by 16 bytes of 0xFF>      |
|                                                             |
|   ...                                                       |
|                                                             |
|   (optional) second 0xFFFFFFFF | AA 55 AA 55 <-- FET 1      |
|                                                             |
+-------------------------------------------------------------+   end of file
```

### 1.1 FET location heuristics

PSPTool tries every candidate FET and accepts the first that yields a parseable
`$PSP` / `$BHD` directory. ROM size is the largest of `{32, 16, 8} MiB` that
fits inside the input.

| FET flash offset | Seen on                      |
| ---------------- | ---------------------------- |
| `0x020000`       | Zen 1 (PSPTrace boot)        |
| `0x0fa0000`      | many Zen+/Zen 2 16 MiB ROMs  |
| `0x0f20000`      |                              |
| `0x0e20000`      |                              |
| `0x0c20000`      |                              |
| `0x0820000`      |                              |
| `0x0120000`      |                              |

**FET discovery rule (PSPTool/blob.py).**

1. Find every `\xff\xff\xff\xff\xaa\x55\xaa\x55` and `\x00\x00\x00\x00\xaa\x55\xaa\x55` in the input. The 4-byte word *before* `AA55AA55` MUST be `0x00000000` or `0xFFFFFFFF` — this disambiguates FET magic from random noise.
2. The FET flash offset is the byte after that 4-byte pad.
3. For each candidate FET, try every entry in the table above as the
   "FET-relative-to-ROM-start" offset. The implied ROM start is
   `fet_location − fet_offset`, which must be ≥ 0 and the resulting ROM must
   fit in the input.
4. ROMs are 16 MiB **windows**: structures within a ROM never span a 16 MiB
   page boundary except for an explicit single-ROM workaround (`page == 0`).

### 1.2 The Firmware Entry Table (FET)

The FET is a flat array of 4-byte little-endian dwords starting at the byte
after the 4-byte magic, terminated by **16 consecutive `0xFF` bytes** (i.e.
four `0xFFFFFFFF` dwords).

```
offset  size  field
------  ----  -----
0x00     4    magic = 0xAA55AA55
0x04    +N    array of dword pointers (each is a directory ROM offset, see §1.3)
end:    16    terminator = 0xFFFFFFFF * 4
```

Validated on `AORUS_B450AE.F40` at flash offset `0x20000`:

```
+0x00: 55 AA 55 AA       <-- magic
+0x04: 00 00 00 00       <-- (slot reserved)
+0x08: 00 00 00 00
+0x0c: 00 00 00 00
+0x10: 00 00 00 00
+0x14: 00 70 0A 00       <-- 0x000A7000 -> Combo $PSP
+0x18: 00 80 15 FF       <-- 0xFF158000 -> $BHD #1
+0x1c: 00 80 25 FF       <-- 0xFF258000 -> $BHD #2
+0x20: 00 80 38 00       <-- 0x00388000 -> $BHD #3
+0x24: FE FF FF FF       <-- skipped (sentinel; PSPTool also skips 0xFFFFFFFE)
+0x28: FF FF FF FF       <-- terminator dword
+0x2c: FF FF FF FF
+0x30: 00 F0 85 FF       <-- 0xFF85F000 -> _PT_ (EFS-ish, ignored by PSP layer)
...
```

The slots before the terminator have **positional meaning** (e.g. the BIOS
team places `$PSP` at index 1, `$BHD` at index 2). `psptool-rs` should preserve
slot ordering and skip-but-record dwords equal to `0x00000000`,
`0xFFFFFFFF`, or `0xFFFFFFFE`. Only dwords whose dereferenced location starts
with a known directory magic (`$PSP`, `$BHD`, `2PSP`, `2BHD`) are followed.

### 1.3 ROM-physical address normalisation

FET slots — and many other pointers — store **x86 physical addresses** (the
SPI ROM is mapped at `0xFF000000–0xFFFFFFFF` for 16 MiB parts, `0xFF800000+`
for 8 MiB parts) interleaved with **flash offsets** (zero-based). The
following rule normalises any pointer to a flash offset:

```
addr_mask = rom_size - 1                       # 0x00FFFFFF for 16 MiB
if raw > 0xFF000000 and rom_size > 16 MiB:
    flash_off = raw & 0x00FFFFFF               # force 16 MiB window for >16 MiB ROMs
else:
    flash_off = raw & addr_mask
```

This rule is applied verbatim in `fet.py:_parse_entry_table` and
`entry.py:file_offset` (mode 0).

---

## 2. Directories

There are four directory magics, in two structural families:

| Magic   | Family    | Role                                                |
| ------- | --------- | --------------------------------------------------- |
| `$PSP`  | PSP       | Primary PSP directory                               |
| `$PL2`  | PSP       | Secondary ("level 2") PSP directory                 |
| `$BHD`  | BIOS      | Primary BIOS directory                              |
| `$BL2`  | BIOS      | Secondary BIOS directory                            |
| `2PSP`  | Combo PSP | Combo header that maps zen-generation → `$PSP`/`$PL2` |
| `2BHD`  | Combo BIOS | Combo header that maps zen-generation → `$BHD`/`$BL2` |

PSP and BIOS directories have an **identical 16-byte header** but **different
entry sizes** (16 B vs 24 B). Combo directories have a different layout (§2.3).

### 2.1 PSP / BIOS directory header (16 bytes)

```
offset  size  field            notes
------  ----  ---------------  -----
0x00     4    magic            $PSP / $PL2 / $BHD / $BL2
0x04     4    fletcher32       Fletcher-32 over bytes [0x08 .. end-of-directory]
0x08     4    count            number of entries that follow the header
0x0c     4    additional_info  packed: address-mode bits + lookup mode etc.
```

`additional_info` bit layout (`directory.py:address_mode`):

```
bit 31:    version flag (1 = "v1", 0 = "v2")
if version == 1:
    bits [25:24] = address_mode  (00 .. 11)
else:
    bits [30:29] = address_mode  (00 .. 11)
```

The remaining bits are unused by PSPTool but **must be preserved** for
roundtripping (e.g. `additional_info = 0x0000_0500` and `0x0000_0420` are
common).

### 2.2 Address-mode lookup table

`address_mode` is a 2-bit value applied at *directory* scope (and overridden
at *entry* scope only when the directory mode is 2 or 3):

| Value | Meaning                                                     |
| ----- | ----------------------------------------------------------- |
| `00`  | Pointer is an **x86 physical address** in `[0xFF00_0000, 0xFFFF_FFFF]`. Normalize via §1.3. *Some images store flash offsets here too — both work after masking.* |
| `01`  | Pointer is a **flash offset** from start of the BIOS image. Most common on modern systems. |
| `10`  | Pointer is an **offset from the directory header** (use `directory_base + offset`). |
| `11`  | Pointer is an **offset from the partition / slot** (treated identically to mode 10 in PSPTool today; see TODO in `entry.py:67`). |

When *directory* mode is `10`/`11`, PSPTool reads the **entry-level**
`address_mode` (bits `[31:30]` of the entry's `rsv0` field) and uses that mode
for the calculation. When directory mode is `00`/`01`, the entry-level field
is ignored.

### 2.3 Combo directory layout (`2PSP` / `2BHD`)

A combo directory selects one of several PSP/BIOS directories at runtime,
keyed by the active **PSP generation ID** (a 4-byte tag the PSP exposes via a
hardware register).

```
offset  size  field
------  ----  -----
0x00     4    magic = 2PSP / 2BHD
0x04     4    fletcher32 (over [0x08 .. end-of-directory], same scheme as §2.1)
0x08     4    count        (number of combo entries that follow)
0x0c     4    lookup_mode  (0 or 1 — meaning unmodelled by PSPTool)
0x10    16    reserved (asserted to be all zeroes by PSPTool)

# count entries follow, each 16 bytes:
+0x00    4    entry_flags     (always 0 in observed corpus)
+0x04    4    psp_generation  (e.g. 0xBC0B0500 = "Zen 2"; full table below)
+0x08    4    pointer         (raw — apply §1.3 normalisation)
+0x0c    4    reserved
```

PSP generation IDs (`directory.py:Directory.ZEN_GENERATION_IDS`, only the
high 3 bytes are matched; the low byte is a sub-revision):

| Generation | IDs (high 3 bytes, big-endian display)       |
| ---------- | -------------------------------------------- |
| Zen 1      | `BC 09 00`, `BC 0A 00`                       |
| Zen 2      | `BC 0B 05`, `BC 0A 01`                       |
| Zen 3      | `BC 0C 01`, `BC 0C 00`                       |
| Zen 4      | `BC 0D 04`, `BC 0D 0B`                       |
| Zen 4/5    | `BC 0D 03`                                   |

Validated on `AORUS_B450AE.F40` at flash offset `0xA7000`:

```
header @ 0xA7000:
  magic   = 2PSP
  cksum   = 0x7DEBF393
  count   = 4
  lookup_mode = 0
entries:
  [0] flags=0x00000000 psp_id=0xBC0B0500 ptr=0x00288000  -> $PSP (Zen 2)
  [1] flags=0x00000000 psp_id=0xBC0A0000 ptr=0xFF178000  -> $PSP (Zen 1, "Raven")
  [2] flags=0x00000000 psp_id=0xBC0A0100 ptr=0xFF178000  -> $PSP (Zen 2, "Pinnacle revision")
  [3] flags=0x00000000 psp_id=0xBC090000 ptr=0xFF0A8000  -> $PSP (Zen 1)
```

### 2.4 Fletcher-32 checksum

Both PSP and BIOS directory headers (and the FET in some images) use the same
Fletcher-32 variant as PSPTool's `utils.fletcher32`:

```
c0 = c1 = 0xFFFF
for each 16-bit little-endian word w in [0x08 .. end-of-directory]:
    c0 += w
    c1 += c0
    if word_index % 360 == 0:
        c0 = (c0 & 0xFFFF) + (c0 >> 16)
        c1 = (c1 & 0xFFFF) + (c1 >> 16)
# finalise twice
c0 = (c0 & 0xFFFF) + (c0 >> 16); twice
c1 = (c1 & 0xFFFF) + (c1 >> 16); twice
checksum = (c1 << 16) | c0          # written little-endian into header[0x04..0x08]
```

The directory body (`count * entry_size` bytes) immediately follows the
header. Total directory length is `0x10 + count * entry_size`. The body is
always covered by the checksum.

---

## 3. Directory entries

### 3.1 PSP directory entry (16 bytes)

```
offset  size  field         notes
------  ----  ------------  -----
0x00     1    type          §3.3 (file kind selector)
0x01     1    subprogram    use to disambiguate multiple files of the same type
0x02     2    flags         instance = (flags >> 3) & 0xF; rest reserved
0x04     4    size          file size in bytes (0xFFFFFFFF means "no size", see §3.4)
0x08     4    offset        per directory address_mode (see §2.2)
0x0c     4    rsv0          bits [31:30] = entry-level address_mode (only honored when directory mode = 10/11)
```

### 3.2 BIOS directory entry (24 bytes)

```
offset  size  field         notes
------  ----  ------------  -----
0x00     1    type          §3.3
0x01     1    region_type
0x02     2    flags         compressed = (flags >> 3) & 1
                            instance   = (flags >> 4) & 0xF
                            subprogram = (flags >> 8) & 0x7
                            bit 0      = "reset image"
                            bit 1      = "copy image"
                            bit 2      = "read only"
0x04     4    size          file size in bytes
0x08     4    offset        per directory address_mode
0x0c     4    rsv0          bits [31:30] = entry-level address_mode
0x10     8    destination   64-bit memory address where the BIOS loader copies the body; 0xFFFFFFFFFFFFFFFF = unused
```

### 3.3 Sub-directory pointers (entry types that are NOT files)

Some entry `type` values point to *another directory* instead of a file
body. These are recursively expanded into the parsed directory list:

| Type         | Meaning                                                |
| ------------ | ------------------------------------------------------ |
| `0x40`       | PSP_FW_L2_PTR — points to `$PL2`                       |
| `0x49`       | BIOS_L2AB_PTR (used for combo's secondary BIOS dir)    |
| `0x70`       | BIOS_L2_PTR — points to `$BL2`                         |
| `0x48`, `0x4a` | "tertiary" pointers (Zen 4) — see below              |

`SECONDARY_DIRECTORY_ENTRY_TYPES = {0x40, 0x49, 0x70}` from `file.py:34`.
`TERTIARY_DIRECTORY_ENTRY_TYPES = {0x48, 0x4a}`.

**Tertiary pointers (Zen 4)** introduce one additional level of indirection.
For an entry with `type` in `{0x48, 0x4a}`:

```
read 32 bytes at directory.entry.file_offset()  # call this "directory_body"
real_directory_offset = u32_le(directory_body[16:20])
zen_generation_id     =       directory_body[21:24]   # 3 bytes, see §2.3
```

Then recurse on `real_directory_offset`. PSPTool prints a hex of
`directory_body[20:24]` as the "PSP ID" alongside the resolved generation.

### 3.4 Special entry types

- **`type == 0x0B` "soft fuse chain"**: `size == 0xFFFFFFFF`,
  `offset` is data (low dword) and `rsv0` is data (high dword) — the entry
  body itself encodes the fuse mask, no separate file. PSPTool's
  `entry.file_offset()` returns the address of the entry-in-directory so the
  file machinery has somewhere to point.
- **APOB (`0x61` in BIOS dir)**: per `BiosFile.get_address`, address is
  always `0` (APOB is allocated by firmware at runtime; the entry's offset
  is irrelevant). De-duplication keys must therefore include
  `(type, address, size)` even when address is 0.
- **L2 / L2A / L2B pointers (`0x40, 0x48, 0x49, 0x4A, 0x70`)**: as §3.3.

### 3.5 Known PSP directory entry type table

The full type → name mapping is in
`/tmp/psptool-ref/psptool/file.py:DIRECTORY_ENTRY_TYPES` (PSP) and
`BIOS_DIRECTORY_ENTRY_TYPES` (BIOS-only types `0x60..0x7C`). These are
identifiers for human consumption — `psptool-rs` should keep the same names
for table output but **must not** make parsing depend on type recognition
(unknown types are still valid entries).

Notable subsets:

| Set                        | Types                                                                                          |
| -------------------------- | ---------------------------------------------------------------------------------------------- |
| `PUBKEY_ENTRY_TYPES`       | `0x00, 0x05, 0x09, 0x0A, 0x0D, 0x43, 0x4E, 0x53, 0x81, 0x97, 0xAD`                            |
| `KEY_STORE_TYPES`          | `0x50, 0x51`                                                                                   |
| `NO_HDR_ENTRY_TYPES`       | `0x04, 0x06, 0x07, 0x0B, 0x1A, 0x21, 0x22, 0x38, 0x40, 0x46, 0x48, 0x49, 0x4A, 0x54, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x66, 0x67, 0x68, 0x69, 0x6D, 0x70, 0x7C, 0x82, 0x84, 0x8D, 0x98` |
| `NO_SIZE_ENTRY_TYPES`      | `0x0B`                                                                                         |
| `SECONDARY_DIR_ENTRY_TYPES`| `0x40, 0x49, 0x70`                                                                             |
| `TERTIARY_DIR_ENTRY_TYPES` | `0x48, 0x4A`                                                                                   |

Entries whose `type` is not in `NO_HDR_ENTRY_TYPES ∪ SECONDARY_DIR_ENTRY_TYPES`
(and not a pubkey or keystore type) are parsed as **HeaderFile** (§4).

---

## 4. Signed-entry header (`HeaderFile`, 0x100 bytes)

The PSP "blob header" sits at the start of every signed firmware entry. Length
is fixed at `0x100`. After the header comes the (optionally
encrypted/compressed) body, followed by the signature.

```
offset  size  field                  notes
------  ----  ---------------------  -----
0x000   16    reserved / unknown_0
0x010    4    magic                  e.g. b'$PS1' (0x24505331), b'\x05\0\0\0', or vendor-specific
0x014    4    size_signed            length of the bytes covered by the signature (excludes signature itself, but includes the header)
0x018    4    is_encrypted           1 = body encrypted with AES-128-CBC (§5)
0x01c    4    unknown_1c
0x020   16    iv                     AES IV (when is_encrypted == 1)
0x030    4    is_signed              0 = unsigned; 1 = signed; 0xFFFF0000 = signed (legacy); other → ParseError
0x034    4    signature_type         0 = RSA-2048 / 0x100-byte sig; 2 = RSA-4096 / 0x200-byte sig
0x038   16    signature_fingerprint  16-byte hash of the certifying key (matches a PubkeyFile.key_id elsewhere)
0x048    4    is_compressed          1 = body is zlib-compressed (§6)
0x04c    4    unknown_4c
0x050    4    size_uncompressed      uncompressed body size (when is_compressed == 1)
0x054    4    zlib_size              size of the zlib stream within the body (when is_compressed == 1)
0x058    4    bitfield (BIG-ENDIAN!) bits: [0] has_sha256, [1] has_sha384 — at most one may be set
0x05c    4    version                read backwards as 4 bytes (header[0x63:0x5F:-1]) for "X.Y.Z.W" display
0x060    8    unknown_60
0x068    4    load_addr              memory address the PSP places this image at
0x06c    4    rom_size               total in-flash size of the entry (header + body + signature). 0 means "use entry size".
0x070   16    unknown_70
0x080   16    wrapped_key            AES-128 key wrapped under IKEK (when is_encrypted == 1)
0x090   64    unknown_90
0x0d0   32    sha_checksum           sha256 (lo 32 B) or sha384 (full 48 B) of `get_decrypted_decompressed_body()`
                                     occupies bytes 0x0D0..0x100 (sha384 spans the whole 48-byte slot)
```

> **Note on the bitfield at 0x58.** PSPTool decodes it big-endian
> (`struct.unpack('>I', ...)`) and only checks bits 0 and 1 of the
> *byte-reversed* result, so the meaningful bits sit in the **last** byte of
> the field as written on disk.

> **Note on the version field.** The four bytes at `[0x60, 0x61, 0x62, 0x63]`
> are *displayed* in reverse order. The on-disk byte order must be preserved
> verbatim.

### 4.1 Signed bytes

The bytes covered by the RSA signature are
`header || decrypted_decompressed_body[..size_signed]`. That is, AES decryption
and zlib decompression are reversed *before* the signature check. PSPTool
implements this in `header_file.HeaderFile.get_signed_bytes`.

### 4.2 Signature placement

The signature occupies the *last* `signature_len` bytes of the entry body, where
`signature_len ∈ {0x100, 0x200}` per `signature_type`. The body region
(between header and signature) has length:

```
body_len = rom_size - 0x100 - signature_len
```

`rom_size` from the header is authoritative; if it is `0` it falls back to the
parent entry's `size`.

---

## 5. AES-encrypted bodies

When `header.is_encrypted == 1`:

- IV is `header[0x20..0x30]` (must be non-zero — PSPTool asserts).
- Wrapped entry key is `header[0x80..0x90]` (must be non-zero).
- The "IKEK" (initial key encryption key) is hard-wired per Zen generation. PSPTool ships two:

  | Generation | IKEK SHA1 hash on disk    | Unwrapped IKEK (16 bytes)                       |
  | ---------- | ------------------------- | ----------------------------------------------- |
  | Zen        | `47 23 A8 52 03 38 BD 2E AC 5F AE 9C 2C B5 92 5B` | `49 1E 40 1A 40 1E C1 B2 28 46 00 F0 99 FD E8 68` |
  | Zen+ (default) | `E2 84 DA E0 6E 58 01 04 FA 6E 8E 6B 58 68 8A 0C` | `4C 77 63 65 32 FE 4C 6F D6 B9 D6 D7 B5 1E DE 59` |

  PSPTool currently always uses the Zen+ IKEK (`HeaderFile.get_unwrapped_ikek`
  contains a TODO to detect the right one).

- **Decryption procedure** (`utils.decrypt`):
  1. `unwrapped_entry_key = AES-128-ECB-decrypt(wrapped_key, ikek)`
  2. `plaintext_body = AES-128-CBC-decrypt(body, iv, unwrapped_entry_key)`

- The entry on disk holds the **encrypted** body. To produce a decrypted
  *equivalent entry* (for re-export) PSPTool zeroes `header[0x18..0x1C]`
  (is_encrypted) and `header[0x20..0x30]` (IV), then writes
  `header || plaintext_body || signature`
  — see `HeaderFile.to_decrypted_file_bytes`.

- The wrapped IKEK itself is shipped in-band as **entry type `0x21`
  (`WRAPPED_IKEK`)** in the PSP directory. Tools that re-derive IKEK use
  `md5(WRAPPED_IKEK_entry_bytes)` to identify which generation it belongs to.

---

## 6. zlib-compressed bodies

When `header.is_compressed == 1`:

- The body bytes start with a zlib stream — **but the stream may not begin at
  body offset 0**. PSPTool searches the first 0x500 bytes for any of these
  zlib magics, in order:

  | Magic   | Description                            |
  | ------- | -------------------------------------- |
  | `78 DA` | Zlib compressed, best compression      |
  | `78 9C` | Zlib compressed, default compression   |
  | `78 5E` | Zlib compressed                        |
  | `78 01` | Zlib header, no compression            |

  If a magic is present at exactly offset `0x100` it is accepted immediately
  (common case — the leading 0x100 bytes are a second header / glue region).

- The compressed stream length is `zlib_size` (header offset 0x54). After
  decompression, expect `size_uncompressed` (header offset 0x50) bytes.

- BIOS-directory entries set "compressed" via `BiosDirectoryEntry.flags`
  bit 3 (`(flags >> 3) & 1`), not via the PSP header bitfield.

- **Microcode** entries (BIOS dir type `0x66`) may *optionally* be wrapped in
  a PSP HeaderFile (then compressed) or stored raw. Parsers must handle both.

---

## 7. Public-key files and key store

### 7.1 PubkeyFile (entry types `PUBKEY_ENTRY_TYPES`)

A PubkeyFile is a self-contained signed pubkey blob (SEV spec, Appendix B.1):

```
offset  size            field             notes
------  --------------  ---------------   -----
0x00     4              version           1 or 2 (others raise UnknownPubkeyFileVersion)
0x04    16              key_id            fingerprint of the contained key (the "magic" displayed in `ls`)
0x14    16              certifying_id     fingerprint of the key that signed THIS pubkey
0x24     4              key_usage         0=AMD_CODE_SIGN, 1=BIOS_CODE_SIGN, 2=BOTH, 8=PSB
0x28     2              reserved
0x2A     2              security_features bits: [0]=disable_bios_key_anti_rollback, [1]=disable_amd_bios_key_use, [2]=disable_secure_debug_unlock
0x2C    12              reserved
0x38     4              pubexp_bits       bit-length of public exponent (always 2048 or 4096; pubexp itself = 0x10001)
0x3C     4              modulus_bits      same value as pubexp_bits (asserted equal)
0x40     pubexp_size    pubexp            little-endian; high bytes are zero
0x40+sz  modulus_size   modulus           little-endian
END     {0, 0x100, 0x200} signature       PRESENT iff `signature_size != 0`; stored REVERSED (see below)
```

Where `pubexp_size = pubexp_bits / 8`, `modulus_size = modulus_bits / 8`, and
`signature_size = total_buffer - 0x40 - pubexp_size - modulus_size`.

The signature, when present, is stored **byte-reversed** vs. the on-the-wire
RSA-PSS signature (PSPTool's `ReversedSignature` adapter). The padding scheme
is RSA-PSS with `MGF1(SHAxxx)`, salt length = digest length, hash
SHA-256 (2048-bit keys) or SHA-384 (4096-bit keys).

Pubkey files appear both as proper directory entries AND as **inline pubkeys**
embedded inside other files. Inline-pubkey scanning (`blob._find_inline_pubkeys`)
keys off the certifying-id fingerprint and known version dwords {1, 2}.

### 7.2 KeyStoreFile (`$PS1` magic, entry types `0x50, 0x51`)

A KeyStoreFile is a HeaderFile whose body is a self-describing
table-of-pubkeys:

```
KeyStoreFileHeader (0x100 bytes, sits at the start of the file):
  +0x10  4   magic                = b'$PS1' or 4 zero bytes
  +0x14  4   body_size            = size of the embedded $KDB key store
  +0x30  4   unknown_const_1      = 0x00000001 (asserted)
  +0x34  4   unknown_const_2      = 0x00000002 (asserted)
  +0x38 16   certifying_id        signs THIS key store
  +0x6c  4   packed_size          total size including header + body + signature
  +0x7c  4   keystore_type        in {0x50, 0x51} or 0

KeyStore body ($KDB):
  +0x00  4   size                 = body_size
  +0x04  4   unknown_flag         (always 1)
  +0x08  4   magic                = b'$KDB'
  +0x0C 0x44 zero
  +0x50 ...  KeyStoreKey records, packed back-to-back

KeyStoreKey (variable size, header 0x50 + crypto material):
  +0x00  4   size                 = total record size
  +0x04  4   unknown_flag         (always 1)
  +0x08  4   unknown_id           (< 0x100)
  +0x0C  4   rsa_exponent         = 0x10001
  +0x10 16   key_id               same fingerprint scheme as PubkeyFile.key_id
  +0x20  4   key_size_bits        2048 or 4096
  +0x24 0x2C zero / one-byte flag at +0x4F (0, 1, or 2)
  +0x50  N   crypto material      modulus bytes (and pubexp if size warrants — same convention as PubkeyFile)
```

Signature trails the body: `signature_size = packed_size - 0x100 - body_size`,
must be 0x100 or 0x200.

---

## 8. Roundtrip and mutation invariants

`psptool-rs` follows a **diff-and-patch** model: every parsed object retains
its source byte range; serialisation walks the original blob and only
overwrites bytes that the user explicitly mutated. Concrete consequences:

- Unknown reserved fields, padding, slot ordering, and "skipped" FET dwords
  must be byte-identical on output.
- Directory checksums are recomputed only when at least one entry within the
  directory was modified.
- HeaderFile checksums (sha256/sha384) are recomputed only when the body is
  modified; the bitfield decides which one.
- Signatures are recomputed only on `replace-file` / `sign` paths; otherwise
  the existing signature bytes are preserved verbatim.
- AES-encrypted bodies are kept **encrypted on disk**; decryption is a view
  layer (`get_decrypted_body`). The same for zlib (`get_decompressed_body`).
- When an entry body is replaced, `entry.size` is updated *and*
  `entry.offset` is rewritten **preserving the original address-mode bits**
  (`directory.update_entry_fields` mirrors `entry.file_offset` in reverse).
- Directories are de-duplicated by `(type, address, size)` so that the same
  physical entry referenced from multiple directories is parsed once
  (`File.create_file_if_not_exists`).

---

## 9. AGESA version sniff

`Rom._find_agesa_version` regex-scans the ROM for `AGESA!\x00.{2}\x00` strings
(see AMD doc 44065 Arch2008). Some images contain two distinct strings (e.g.
Naples + Rome dual-ROM), in which case PSPTool labels the ROM as `dual_rom`
and exposes both as `agesa_version` and `agesa_version_second`. This is used
only for human-readable output; the parser does not key any structural
decision off it.

---

## 10. Reference material

### 10.1 Source files in `PSPReverse/PSPTool` mapped to this document

| Section | PSPTool file               |
| ------- | -------------------------- |
| §1.1, §1.2 | `psptool/blob.py`, `psptool/fet.py` |
| §1.3, §2.2 | `psptool/entry.py`, `psptool/fet.py` |
| §2.1, §2.3, §2.4 | `psptool/directory.py`, `psptool/utils.py:fletcher32` |
| §3.x        | `psptool/entry.py`, `psptool/file.py` |
| §4          | `psptool/header_file.py` |
| §5          | `psptool/utils.py` (`decrypt_ecb`, `decrypt_cbd`, `decrypt`), `psptool/file.py` (IKEK constants) |
| §6          | `psptool/utils.py` (`zlib_find_header`, `zlib_decompress`) |
| §7.1        | `psptool/pubkey_file.py`, `psptool/crypto.py` (PSS, ReversedSignature) |
| §7.2        | `psptool/key_store_file.py` |
| §8          | `psptool/directory.py`, `psptool/file.py:create_file_if_not_exists`, `psptool/header_file.py:to_decrypted_file_bytes` |
| §9          | `psptool/rom.py` |

### 10.2 Corpus binaries used for cross-validation

All under `vendor/test-corpus/test_files/`:

| File                       | Variant features                                           |
| -------------------------- | ---------------------------------------------------------- |
| `AORUS_B450AE.F40`         | 16 MiB, **Combo PSP** (`2PSP` at 0xA7000), 3× `$BHD` shards, `_PT_` blocks at 0x85F000/0x87F000 |
| `Acer_R01-A4.CAP`          | 16 MiB, Zen 1, no combo (single-FET path)                  |
| `ASUS_PRIME-B450M-A-ASUS-1201.CAP` | 16 MiB + 0x800 capsule wrapper                       |
| `bootloader_overview.py`   | Enumerator that exercises every ROM in the corpus          |

`vendor/test-corpus/test_psptool.py` is the upstream-supplied smoke test —
running it against every file in `test_files/` exercises the full parse path
this document describes.
