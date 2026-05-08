# psptool-rs

Rust reimplementation of [PSPTool](https://github.com/PSPReverse/PSPTool). Goals: flag-compatible CLI, clean lib API for downstream Rust consumers, and **byte-exact roundtripping** when nothing was mutated. See `.crosslink/rules/project.md` for the full design rules.

## Quick start

```bash
nix-shell -A shell                     # default.nix entry; or just `nix-shell` (uses shell.nix)
git submodule update --init vendor/test-corpus   # optional, ~315 MB private corpus
```

## Worker launching

Always pass `--skip-permissions` when spawning kickoff workers — the host provides outer-process sandboxing, and interactive permission prompts would block autonomous progress. Use `scripts/kickoff` to apply the flag automatically:

```bash
scripts/kickoff "implement directory parser" --verify local
```

Equivalent to `crosslink kickoff run --skip-permissions "..."`.

## Where to look first

- Issue graph in crosslink: `crosslink issue tree` shows the v1 plan.
- Roundtrip rule: every `Entry`/`Directory` carries source bytes; serialization is diff-and-patch. See `project.md`.
- Reference Python tool: `vendor/test-corpus/test_psptool.py` shows the surface area we must match (`from_file`, `ls`, `ls_json`, directory iteration, `get_bytes`, `get_decompressed_body`, `get_decrypted`).
