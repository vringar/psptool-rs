//! `clap`-derive surface for the `psptool` binary.
//!
//! Drop-in flag compatibility with the upstream Python tool
//! (`docs/cli-surface.md` §1) is a hard requirement:
//!
//! * Every action flag (`-V`, `-E`, `-X`, `-R`) is accepted at the top level,
//!   either as a flag or via the corresponding subcommand. When a positional
//!   `file` is supplied with no action and no subcommand, the tool falls
//!   through to `list` (the upstream `-E` default).
//! * Every selector (`-r`/`-d`/`-e`/`-T`), output modifier
//!   (`-o`/`-u`/`-c`/`-k`/`-n`/`-j`/`-t`/`-m`/`-v`) and re-sign option
//!   (`-s`/`-p`/`-a`) keeps its short letter, long name, argument shape and
//!   default semantics from upstream.
//!
//! Beyond the upstream flags this CLI exposes Rust-native subcommands
//! (`list`, `extract`, `replace`, `sign`, `verify`, `search-keys`) that bind
//! 1:1 to `psptool-ops`. Defaults are chosen so that pre-existing scripts
//! (which invoke through the legacy flags) keep working unchanged.

use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand};

/// Top-level CLI.
#[derive(Debug, Parser)]
#[command(
    name = "psptool",
    version,
    about = "Inspect and modify AMD PSP firmware images.",
    long_about = None,
    disable_version_flag = true,
)]
pub struct Cli {
    /// Print version (mirrors upstream `-V` / `--version`).
    #[arg(short = 'V', long = "version", action = ArgAction::SetTrue, global = false)]
    pub version: bool,

    // ----- Upstream action flags (mutually exclusive). ---------------------
    /// List entries — the upstream `-E` action (default when a `file` is
    /// supplied with no subcommand and no other action flag).
    #[arg(short = 'E', long = "entries", action = ArgAction::SetTrue, conflicts_with_all = ["extract_file", "replace_file"])]
    pub entries: bool,

    /// Extract one or more entries — upstream `-X`.
    #[arg(short = 'X', long = "extract-file", action = ArgAction::SetTrue, conflicts_with_all = ["entries", "replace_file"])]
    pub extract_file: bool,

    /// Replace an entry's body — upstream `-R`.
    #[arg(short = 'R', long = "replace-file", action = ArgAction::SetTrue, conflicts_with_all = ["entries", "extract_file"])]
    pub replace_file: bool,

    // ----- Upstream shared flags (only for the no-subcommand "legacy" --
    //       invocation; subcommand structs declare their own copies so each
    //       subcommand's --help shows only the flags that apply to it). ----
    /// Selector — ROM index inside a multi-ROM blob.
    #[arg(short = 'r', long = "rom-index", default_value_t = 0)]
    pub rom_index: usize,

    /// Selector — directory index inside the chosen ROM.
    #[arg(short = 'd', long = "directory-index")]
    pub directory_index: Option<usize>,

    /// Selector — entry index inside the chosen directory.
    #[arg(short = 'e', long = "file-index")]
    pub file_index: Option<usize>,

    /// Selector — type-name regex (alternative to `-d -e` for `-X`).
    #[arg(short = 'T', long = "type-regex")]
    pub type_regex: Option<String>,

    /// Output file (single-file `-X`/`-R`) or output directory (multi-file
    /// `-X`).
    #[arg(short = 'o', long = "outfile")]
    pub outfile: Option<PathBuf>,

    /// Decompress when extracting (`-X -u`). Errors when the entry is not
    /// compressed in single-file mode.
    #[arg(short = 'u', long = "decompress", action = ArgAction::SetTrue)]
    pub decompress: bool,

    /// Decrypt when extracting (`-X -c`). Errors when the entry is not
    /// encrypted in single-file mode.
    #[arg(short = 'c', long = "decrypt", action = ArgAction::SetTrue)]
    pub decrypt: bool,

    /// Emit the PEM-encoded pubkey (`-X -k`). Silently ignored for
    /// non-pubkey entries in multi-file mode.
    #[arg(short = 'k', long = "pem-key", action = ArgAction::SetTrue)]
    pub pem_key: bool,

    /// Iterate unique entries only (`-E -n` / `-X -n`).
    #[arg(short = 'n', long = "no-duplicates", action = ArgAction::SetTrue)]
    pub no_duplicates: bool,

    /// JSON output (`-E -j`).
    #[arg(short = 'j', long = "json", action = ArgAction::SetTrue)]
    pub json: bool,

    /// Print the certificate-tree key tree (`-E -t`).
    #[arg(short = 't', long = "key-tree", action = ArgAction::SetTrue)]
    pub key_tree: bool,

    /// Print parsing metrics (`-E -m`).
    #[arg(short = 'm', long = "metrics", action = ArgAction::SetTrue)]
    pub metrics: bool,

    /// Verbose output. Adds the `flags / MD5 / size_signed / size_full /
    /// size_packed / load_addr` columns to `list`.
    #[arg(short = 'v', long = "verbose", action = ArgAction::SetTrue)]
    pub verbose: bool,

    /// Re-sign: replacement file contents (`-R -s`).
    #[arg(short = 's', long = "subfile")]
    pub subfile: Option<PathBuf>,

    /// Re-sign: private-key path (`-R -p`). When the upstream flag accepted
    /// a stub, this Rust port accepts a single PEM file.
    #[arg(short = 'p', long = "privkey", visible_alias = "privkeystub")]
    pub privkey: Option<PathBuf>,

    /// Re-sign: passphrase for the private key (`-R -a`).
    #[arg(short = 'a', long = "privkeypass")]
    pub privkey_pass: Option<String>,

    /// Positional firmware image. Required for any action other than
    /// `--version` / no-args (which prints help).
    #[arg(value_name = "FILE", index = 1)]
    pub file: Option<PathBuf>,

    /// Subcommand. Mutually exclusive with the upstream action flags above.
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Subcommands. Each binds 1:1 to a `psptool-ops` entry-point.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// List directories and entries.
    #[command(visible_alias = "ls")]
    List(ListArgs),
    /// Extract one or more entry bodies.
    Extract(ExtractArgs),
    /// Replace an entry body (and optionally re-sign).
    Replace(ReplaceArgs),
    /// Re-sign a signed entry with a caller-supplied private key.
    Sign(SignArgs),
    /// Walk every directory and report chain-of-trust verification status.
    Verify(VerifyArgs),
    /// Discover RSA pubkeys (structured + heuristic).
    #[command(name = "search-keys")]
    SearchKeys(SearchKeysArgs),
}

/// `list` arguments — upstream `-E` action.
#[derive(Debug, Args)]
pub struct ListArgs {
    /// ROM index.
    #[arg(short = 'r', long = "rom-index", default_value_t = 0)]
    pub rom_index: usize,

    /// JSON output.
    #[arg(short = 'j', long = "json", action = ArgAction::SetTrue)]
    pub json: bool,

    /// Iterate unique entries only.
    #[arg(short = 'n', long = "no-duplicates", action = ArgAction::SetTrue)]
    pub no_duplicates: bool,

    /// Print the cert-tree key tree.
    #[arg(short = 't', long = "key-tree", action = ArgAction::SetTrue)]
    pub key_tree: bool,

    /// Print parsing metrics.
    #[arg(short = 'm', long = "metrics", action = ArgAction::SetTrue)]
    pub metrics: bool,

    /// Verbose columns.
    #[arg(short = 'v', long = "verbose", action = ArgAction::SetTrue)]
    pub verbose: bool,

    /// Firmware image.
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
}

/// `extract` arguments — upstream `-X` action.
#[derive(Debug, Args)]
pub struct ExtractArgs {
    #[arg(short = 'r', long = "rom-index", default_value_t = 0)]
    pub rom_index: usize,

    #[arg(short = 'd', long = "directory-index")]
    pub directory_index: Option<usize>,

    #[arg(short = 'e', long = "file-index")]
    pub file_index: Option<usize>,

    #[arg(short = 'T', long = "type-regex")]
    pub type_regex: Option<String>,

    #[arg(short = 'o', long = "outfile")]
    pub outfile: Option<PathBuf>,

    #[arg(short = 'u', long = "decompress", action = ArgAction::SetTrue)]
    pub decompress: bool,

    #[arg(short = 'c', long = "decrypt", action = ArgAction::SetTrue)]
    pub decrypt: bool,

    #[arg(short = 'k', long = "pem-key", action = ArgAction::SetTrue)]
    pub pem_key: bool,

    #[arg(short = 'n', long = "no-duplicates", action = ArgAction::SetTrue)]
    pub no_duplicates: bool,

    #[arg(value_name = "FILE")]
    pub file: PathBuf,
}

/// `replace` arguments — upstream `-R` action.
#[derive(Debug, Args)]
pub struct ReplaceArgs {
    #[arg(short = 'r', long = "rom-index", default_value_t = 0)]
    pub rom_index: usize,

    /// Required.
    #[arg(short = 'd', long = "directory-index")]
    pub directory_index: usize,

    /// Required.
    #[arg(short = 'e', long = "file-index")]
    pub file_index: usize,

    /// Required.
    #[arg(short = 'o', long = "outfile")]
    pub outfile: PathBuf,

    /// Replacement file contents. When omitted, this becomes a "plain
    /// re-sign" of the entry (requires `-p`).
    #[arg(short = 's', long = "subfile")]
    pub subfile: Option<PathBuf>,

    /// Private key (PEM) for re-signing.
    #[arg(short = 'p', long = "privkey", visible_alias = "privkeystub")]
    pub privkey: Option<PathBuf>,

    /// Passphrase (currently ignored — `rsa::pkcs8::DecodePrivateKey` reads
    /// PEM directly; encrypted-PEM support is a follow-up).
    #[arg(short = 'a', long = "privkeypass")]
    pub privkey_pass: Option<String>,

    #[arg(value_name = "FILE")]
    pub file: PathBuf,
}

/// `sign` arguments — Rust-native (no upstream short letter).
#[derive(Debug, Args)]
pub struct SignArgs {
    #[arg(short = 'r', long = "rom-index", default_value_t = 0)]
    pub rom_index: usize,

    #[arg(short = 'd', long = "directory-index")]
    pub directory_index: usize,

    #[arg(short = 'e', long = "file-index")]
    pub file_index: usize,

    /// Output ROM (the input is not modified in-place).
    #[arg(short = 'o', long = "outfile")]
    pub outfile: PathBuf,

    /// Private key (PEM).
    #[arg(short = 'p', long = "privkey")]
    pub privkey: PathBuf,

    /// Passphrase (currently ignored).
    #[arg(short = 'a', long = "privkeypass")]
    pub privkey_pass: Option<String>,

    #[arg(value_name = "FILE")]
    pub file: PathBuf,
}

/// `verify` arguments — Rust-native.
#[derive(Debug, Args)]
pub struct VerifyArgs {
    #[arg(short = 'r', long = "rom-index", default_value_t = 0)]
    pub rom_index: usize,

    #[arg(short = 'j', long = "json", action = ArgAction::SetTrue)]
    pub json: bool,

    #[arg(short = 'v', long = "verbose", action = ArgAction::SetTrue)]
    pub verbose: bool,

    #[arg(value_name = "FILE")]
    pub file: PathBuf,
}

/// `search-keys` arguments — Rust-native.
#[derive(Debug, Args)]
pub struct SearchKeysArgs {
    #[arg(short = 'r', long = "rom-index", default_value_t = 0)]
    pub rom_index: usize,

    #[arg(short = 'j', long = "json", action = ArgAction::SetTrue)]
    pub json: bool,

    #[arg(value_name = "FILE")]
    pub file: PathBuf,
}
