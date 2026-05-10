//! `verify` subcommand — binds to `psptool_ops::verify_with_directories`.

use std::io::Write;

use anyhow::Result;
use psptool_ops::{EntryVerification, verify_with_directories};
use serde_json::{Value, json};

use crate::cli::VerifyArgs;
use crate::load::open_rom;

pub fn run(args: &VerifyArgs, out: &mut dyn Write) -> Result<()> {
    let opened = open_rom(&args.file, args.rom_index)?;
    let report = verify_with_directories(
        &opened.blob,
        &opened.directories,
        opened.rom_size,
        opened.rom_origin,
        None,
    );
    if args.json {
        let value = json_report(&report);
        let s = serde_json::to_string(&value)?;
        writeln!(out, "{s}")?;
    } else {
        write_text(&report, args.verbose, out)?;
    }
    Ok(())
}

fn write_text(report: &[EntryVerification], verbose: bool, out: &mut dyn Write) -> Result<()> {
    for row in report {
        if verbose {
            writeln!(
                out,
                "dir={:>3} entry={:>3} type={:#04x} body={:#010x} status={}",
                row.directory_index,
                row.entry_index,
                row.entry_type.get(),
                row.body_offset.get(),
                row.status,
            )?;
        } else {
            writeln!(
                out,
                "{:>3}.{:<3} {:#04x} {}",
                row.directory_index,
                row.entry_index,
                row.entry_type.get(),
                row.status,
            )?;
        }
    }
    Ok(())
}

fn json_report(report: &[EntryVerification]) -> Value {
    let entries: Vec<Value> = report
        .iter()
        .map(|r| {
            let mut obj = serde_json::Map::new();
            obj.insert("directory".into(), json!(r.directory_index));
            obj.insert("entry".into(), json!(r.entry_index));
            obj.insert("type".into(), json!(format!("{:#04x}", r.entry_type.get())));
            obj.insert("body".into(), json!(r.body_offset.get()));
            obj.insert("status".into(), json!(format!("{}", r.status)));
            if let Some(k) = r.key_id {
                obj.insert("key_id".into(), json!(hex16(&k)));
            }
            Value::Object(obj)
        })
        .collect();
    Value::Array(entries)
}

fn hex16(bytes: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in bytes {
        use core::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}
