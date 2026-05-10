//! `search-keys` subcommand — binds to
//! `psptool_ops::search_keys_with_directories`.

use std::io::Write;

use anyhow::Result;
use psptool_ops::{KeyHit, KeyHitLocation, search_keys_with_directories};
use serde_json::{Value, json};

use crate::cli::SearchKeysArgs;
use crate::load::open_rom;

pub fn run(args: &SearchKeysArgs, out: &mut dyn Write) -> Result<()> {
    let opened = open_rom(&args.file, args.rom_index)?;
    let hits = search_keys_with_directories(
        &opened.blob,
        &opened.directories,
        opened.rom_size,
        opened.rom_origin,
    );
    if args.json {
        let value = json_hits(&hits);
        let s = serde_json::to_string(&value)?;
        writeln!(out, "{s}")?;
    } else {
        for hit in &hits {
            let loc = match hit.location {
                KeyHitLocation::Structured(r) => {
                    format!("structured(d{}.e{})", r.directory_index, r.entry_index)
                }
                KeyHitLocation::Heuristic => "heuristic".to_string(),
            };
            writeln!(
                out,
                "{:#010x}  {}  modulus={}  {}",
                hit.offset.get(),
                hex16(&hit.key_id),
                hit.modulus_size,
                loc,
            )?;
        }
    }
    Ok(())
}

fn json_hits(hits: &[KeyHit]) -> Value {
    let arr: Vec<Value> = hits
        .iter()
        .map(|h| {
            let location = match h.location {
                KeyHitLocation::Structured(r) => json!({
                    "kind": "structured",
                    "directory": r.directory_index,
                    "entry": r.entry_index,
                }),
                KeyHitLocation::Heuristic => json!({"kind": "heuristic"}),
            };
            json!({
                "offset": h.offset.get(),
                "key_id": hex16(&h.key_id),
                "modulus_size": h.modulus_size,
                "location": location,
            })
        })
        .collect();
    Value::Array(arr)
}

fn hex16(bytes: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in bytes {
        use core::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}
