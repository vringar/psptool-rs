//! Corpus RSS regression for #98 (board #533).
//!
//! `tests/memory_probe.py` runs the psp-etl ingest loop over every corpus ROM
//! — `PSPTool.from_file`, decode every `HeaderFile` body, drop the object,
//! no `gc.collect()` — under the interpreter the extension was built for, and
//! the RSS growth from the first ROM to the peak must stay bounded. Before the
//! fix no parse was ever reclaimed (~40 MiB retained per 16 MiB ROM, past
//! 2 GiB over the corpus); with the cycle collector alone, scheduled by object
//! counts, Python 3.13 still held ~1 GiB of dead parses.
//!
//! Gating mirrors `corpus_parity.rs`: the `corpus` feature and
//! `PSPTOOL_TEST_CORPUS` (the test self-skips without ROMs); the probe reads
//! Linux `/proc`.

#[cfg_attr(
    not(all(feature = "corpus", target_os = "linux")),
    allow(dead_code, reason = "the helpers only drive the corpus probe")
)]
mod common;

#[cfg(all(feature = "corpus", target_os = "linux"))]
use std::path::PathBuf;

/// Allowed RSS growth over the run. `memory.rs` lets up to 128 MiB of dropped
/// images and decoded bodies await the collector, a ROM in flight costs a few
/// image-sized copies, and the allocator keeps freed arenas mapped; the whole
/// corpus is ~430 MiB of ROMs.
#[cfg(all(feature = "corpus", target_os = "linux"))]
const MAX_GROWTH: u64 = 512 << 20;

#[cfg(all(feature = "corpus", target_os = "linux"))]
#[test]
fn corpus_parse_loop_rss_is_bounded() {
    let roms = psptool_fixtures::corpus_rom_paths();
    if roms.is_empty() {
        eprintln!("PSPTOOL_TEST_CORPUS unset or without ROMs: skipping the corpus RSS probe");
        return;
    }
    let stage = match common::stage("psptool-py-memory-stage") {
        Ok(s) => s,
        Err(e) => panic!("staging the package: {e}"),
    };
    let args: Vec<&std::ffi::OsStr> = roms.iter().map(|p| p.as_os_str()).collect();
    let script = common::scripts().join("memory_probe.py");
    // The interpreter the extension was built for, as in `python_api.rs`.
    let python = std::env::var_os("PYO3_PYTHON")
        .filter(|v| !v.is_empty())
        .map_or_else(|| PathBuf::from("python3"), PathBuf::from);
    let output = common::python(&python, Some(&stage), &script, &args);
    let stdout = match output.and_then(|o| common::stdout_of(o, "memory probe")) {
        Ok(s) => s,
        Err(e) => panic!("{e}"),
    };
    let report: serde_json::Value = match serde_json::from_str(stdout.trim()) {
        Ok(v) => v,
        Err(e) => panic!("probe output {stdout:?}: {e}"),
    };
    assert_eq!(report["roms"].as_u64(), Some(roms.len() as u64));
    let (Some(first), Some(peak)) = (report["first"].as_u64(), report["peak"].as_u64()) else {
        panic!("probe output without RSS samples: {report}");
    };
    let growth = peak.saturating_sub(first);
    eprintln!(
        "{} ROMs: RSS {} MiB after the first, peak {} MiB (+{} MiB)",
        roms.len(),
        first >> 20,
        peak >> 20,
        growth >> 20
    );
    assert!(
        growth < MAX_GROWTH,
        "RSS grew {} MiB over {} ROMs (bound {} MiB): dropped parses are retained",
        growth >> 20,
        roms.len(),
        MAX_GROWTH >> 20
    );
}
