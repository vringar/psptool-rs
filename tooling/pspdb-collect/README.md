# PSP-DB collection harness

Scripts to collect **Zen 4/5 AM5** firmware ROMs for differential testing. The
committed Zen 1–3 corpus never exercises the tertiary L2 directory path; these
images do (see issue #51).

## What it does

Drives [nuernbergk/PSP-DB](https://github.com/nuernbergk/PSP-DB) to resolve an
ASRock consumer motherboard's newest BIOS, download it, extract the `.ROM`, and
validate it with reference PSPTool. ASRock is used because ASUS's `product.asmx`
support API was retired and PSP-DB's ASUS strategy no longer resolves links.

## Environment

PSP-DB needs Python 3.11 + Pony ORM + Selenium. The nixpkgs `python311` package
set fails to evaluate on the current channel, so the env is **pip-centric**: nix
provides only the interpreter and C build headers, pip installs the Python deps.

```bash
git clone https://github.com/nuernbergk/PSP-DB /tmp/PSP-DB
cp pspdb-shell.nix setup-env.sh asrock_fetch.py /tmp/PSP-DB/
cd /tmp/PSP-DB && bash setup-env.sh          # builds .venv, installs pspdb
```

Selenium runs in a container (rootless podman in the sandbox):

```bash
podman --remote --url unix:///tmp/podman/podman.sock run -d --name pspdb_selenium \
  --share-net -p 4444:4444 docker.io/selenium/standalone-chrome:latest
```

Populate the board list once (ASRock consumer discovery), then fetch a board:

```bash
cd /tmp/PSP-DB && .venv/bin/python asrock_fetch.py "X870E Taichi"
```

Images land in `/tmp/psp-extra/corpus/`. Copy the validated ones into the
repo-local, gitignored `.local-corpus/test_files/` to keep them across restarts.

## Differential-test against them

```bash
PSPTOOL_TEST_CORPUS="$PWD/.local-corpus" \
  nix-shell default.nix -A shell --run \
  'cargo test -p psptool-cli --test differential -- --nocapture'
```

## Captured so far (2026-07-11)

| Image | PSP gen id | Dirs (ref) | Note |
|-------|-----------|-----------:|------|
| ASRock_B650_PG_Lightning_1.14.AS06[Beta].bin | 0xbc0d0300 | 4 | Zen 4/5, known gen |
| ASRock_X870E_Taichi_4.43.bin | 0xbc0e0b / 0xbc0e10 | 8 | 2026 BIOS, gen newer than PSPTool 3.6 knows |
| ASRock_B850_Steel_Legend_WiFi_4.43.bin | 0xbc0e0b / 0xbc0e10 | 8 | 2026 BIOS, same |

All three currently **fail** the differential (issue #51: tertiary 0x48/0x4A L2
pointers not followed) and **pass** roundtrip (unparsed bytes emitted verbatim).
