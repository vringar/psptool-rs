//! `PSPTool.ls` / `ls_files` / `ls_json` / `ls_files_dict`
//! (`psptool.py:66-275`) over the bindings' object graph.
//!
//! The values are read through the Python-visible methods of the file
//! objects (so the output reflects the live image and any subclass
//! override), then rendered the way upstream renders them: tables in
//! `prettytable`'s default style (`print(t)`), JSON via the stdlib `json`
//! module (`json.dumps(data)`).

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use crate::buffer::py_hex;
use crate::errors::{NoCertifyingKey, SignatureInvalid};
use crate::file::{HeaderFile, MicrocodeFile, PubkeyFile};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Align {
    Center,
    Right,
}

/// `prettytable`'s default style: `+---+` rules, one space of padding,
/// headers and cells justified per column, multi-line cells split on `\n`
/// and top-aligned.
fn render(headers: &[&str], rows: &[Vec<String>], align: Align) -> String {
    let lines = |s: &str| -> Vec<String> { s.split('\n').map(str::to_owned).collect() };
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (w, cell) in widths.iter_mut().zip(row) {
            for line in lines(cell) {
                *w = (*w).max(line.chars().count());
            }
        }
    }
    let rule: String = std::iter::once("+".to_owned())
        .chain(widths.iter().map(|w| format!("{}+", "-".repeat(w + 2))))
        .collect();
    let render_row = |cells: &[String]| -> String {
        let split: Vec<Vec<String>> = cells.iter().map(|c| lines(c)).collect();
        let height = split.iter().map(Vec::len).max().unwrap_or(1);
        let mut out = Vec::with_capacity(height);
        for i in 0..height {
            let mut line = "|".to_owned();
            for (cell, &w) in split.iter().zip(&widths) {
                let text = cell.get(i).map_or("", String::as_str);
                line.push(' ');
                line.push_str(&justify(text, w, align));
                line.push_str(" |");
            }
            out.push(line);
        }
        out.join("\n")
    };
    let header: Vec<String> = headers.iter().map(|h| (*h).to_owned()).collect();
    let mut out = vec![rule.clone(), render_row(&header), rule.clone()];
    for row in rows {
        out.push(render_row(row));
    }
    out.push(rule);
    out.join("\n")
}

/// `PrettyTable._justify`: centring puts the odd space on the right of
/// odd-length text and on the left of even-length text.
fn justify(text: &str, width: usize, align: Align) -> String {
    let len = text.chars().count();
    let excess = width.saturating_sub(len);
    match align {
        Align::Right => format!("{}{text}", " ".repeat(excess)),
        Align::Center if excess % 2 == 1 && len % 2 == 1 => {
            format!(
                "{}{text}{}",
                " ".repeat(excess / 2),
                " ".repeat(excess / 2 + 1)
            )
        }
        Align::Center if excess % 2 == 1 => {
            format!(
                "{}{text}{}",
                " ".repeat(excess / 2 + 1),
                " ".repeat(excess / 2)
            )
        }
        Align::Center => format!("{}{text}{}", " ".repeat(excess / 2), " ".repeat(excess / 2)),
    }
}

fn print(py: Python<'_>, text: String) -> PyResult<()> {
    py.import("builtins")?.call_method1("print", (text,))?;
    Ok(())
}

fn hex_of(obj: &Bound<'_, PyAny>) -> PyResult<String> {
    Ok(py_hex(obj.extract()?))
}

fn call_str(obj: &Bound<'_, PyAny>, method: &str) -> PyResult<String> {
    Ok(obj.call_method0(method)?.str()?.to_string())
}

/// `directory.magic.decode('utf-8', 'backslashreplace')`.
fn magic_text(directory: &Bound<'_, PyAny>) -> PyResult<String> {
    directory
        .getattr("magic")?
        .call_method1("decode", ("utf-8", "backslashreplace"))?
        .extract()
}

/// `md5()[:4].upper()`.
fn short_md5(file: &Bound<'_, PyAny>) -> PyResult<String> {
    let md5: String = file.call_method0("md5")?.extract()?;
    Ok(md5.chars().take(4).collect::<String>().to_uppercase())
}

/// `sorted(self.blob.unique_files())`.
fn sorted_unique_files<'py>(psptool: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyAny>> {
    let files = psptool.getattr("blob")?.call_method0("unique_files")?;
    psptool
        .py()
        .import("builtins")?
        .call_method1("sorted", (files,))
}

/// `PSPTool.ls` (`psptool.py:66-92`).
pub fn ls(psptool: &Bound<'_, PyAny>, verbose: bool) -> PyResult<()> {
    let py = psptool.py();
    for (rom_index, rom) in psptool
        .getattr("blob")?
        .getattr("roms")?
        .try_iter()?
        .enumerate()
    {
        let rom = rom?;
        let row = vec![
            rom_index.to_string(),
            hex_of(&rom.call_method0("get_address")?)?,
            hex_of(&rom.getattr("buffer_size")?)?,
            hex_of(&rom.getattr("fet")?.call_method0("get_address")?)?,
            rom.getattr("agesa_version")?.str()?.to_string(),
        ];
        print(
            py,
            render(
                &["ROM", "Addr", "Size", "FET", "AGESA"],
                &[row],
                Align::Center,
            ),
        )?;
        for (index, directory) in rom.getattr("directories")?.try_iter()?.enumerate() {
            let directory = directory?;
            let secondary = directory
                .getattr("secondary_directory_offsets")?
                .try_iter()?
                .map(|o| hex_of(&o?))
                .collect::<PyResult<Vec<_>>>()?
                .join(", ");
            let row = vec![
                String::new(),
                index.to_string(),
                hex_of(&directory.call_method0("get_address")?)?,
                directory.getattr("zen_generation")?.str()?.to_string(),
                magic_text(&directory)?,
                secondary,
            ];
            let headers = [
                "",
                "Directory",
                "Addr",
                "Generation",
                "Magic",
                "Secondary Directory",
            ];
            print(py, render(&headers, &[row], Align::Center))?;
            ls_files(psptool, Some(&directory.getattr("files")?), verbose)?;
            print(py, "\n".to_owned())?;
        }
    }
    Ok(())
}

/// `File Info` tokens of `ls_files` (`psptool.py:112-165`).
fn file_info(file: &Bound<'_, PyAny>) -> PyResult<Vec<String>> {
    let py = file.py();
    let mut info = Vec::new();
    if file.getattr("compressed")?.is_truthy()? {
        info.push("compressed".to_owned());
    }
    if file.getattr("is_signed")?.is_truthy()? {
        let entity = file.getattr("signed_entity")?;
        match entity.call_method0("is_verified") {
            Ok(v) if v.is_truthy()? => info.push(format!(
                "verified({})",
                call_str(file, "get_readable_signed_by")?
            )),
            Ok(_) => info.push(format!(
                "veri-failed({})",
                call_str(file, "get_readable_signed_by")?
            )),
            Err(e) if e.is_instance_of::<NoCertifyingKey>(py) => {
                let id: String = entity
                    .getattr("certifying_id")?
                    .call_method0("as_string")?
                    .extract()?;
                info.push(format!(
                    "key_missing({})",
                    id.chars().take(4).collect::<String>()
                ));
            }
            Err(e) if e.is_instance_of::<SignatureInvalid>(py) => {
                info.push(format!(
                    "invalid_sig({})",
                    call_str(file, "get_readable_signed_by")?
                ));
            }
            Err(e) => return Err(e),
        }
    }
    if file.getattr("is_legacy")?.is_truthy()? {
        info.push("legacy_header".to_owned());
    }
    if file.getattr("encrypted")?.is_truthy()? {
        info.push("encrypted".to_owned());
    }
    if file.is_instance_of::<HeaderFile>() {
        if file.getattr("has_sha256_checksum")?.is_truthy()? {
            let ok = file.call_method0("verify_sha256")?.is_truthy()?;
            info.push(
                if ok {
                    "sha256_ok"
                } else {
                    "sha256_inconsistent"
                }
                .to_owned(),
            );
        } else if file.getattr("has_sha384_checksum")?.is_truthy()? {
            let ok = file.call_method0("verify_sha384")?.is_truthy()?;
            info.push(
                if ok {
                    "sha384_ok"
                } else {
                    "sha384_inconsistent"
                }
                .to_owned(),
            );
        }
        let inline = file.getattr("inline_keys")?;
        if inline.is_truthy()? {
            let names = inline
                .try_iter()?
                .map(|k| call_str(&k?, "get_readable_magic"))
                .collect::<PyResult<Vec<_>>>()?;
            info.push(format!("inline_keys({})", names.join(", ")));
        }
    }
    if file.is_exact_instance_of::<PubkeyFile>() {
        info.push(call_str(file, "get_readable_key_usage")?);
        let features = call_str(file, "get_readable_security_features")?;
        if !features.is_empty() {
            info.push(features);
        }
    }
    let readable = call_str(file, "get_readable_type")?;
    if readable == "BIOS" {
        info.push(format!(
            "destination({})",
            call_str(file, "get_readable_destination_address")?
        ));
        let flags: i64 = file.getattr("entry")?.getattr("flags")?.extract()?;
        for (bit, label) in [
            (0x1, "reset image"),
            (0x2, "copy image"),
            (0x4, "read only"),
        ] {
            if flags & bit != 0 {
                info.push(label.to_owned());
            }
        }
    }
    if readable == "APOB" {
        info.push(format!(
            "destination({})",
            call_str(file, "get_readable_destination_address")?
        ));
    }
    if file.is_exact_instance_of::<MicrocodeFile>() {
        info.push(format!(
            "patch_level({})",
            hex_of(&file.getattr("patch_level")?)?
        ));
        info.push(format!("date({})", call_str(file, "get_readable_date")?));
    }
    if file.getattr("type")?.extract::<i64>()? == 0xB {
        let entry = file.getattr("entry")?;
        let offset: i64 = entry.getattr("offset")?.extract()?;
        let rsv0: i64 = entry.getattr("rsv0")?.extract()?;
        info.push(format!("soft_fuse({})", py_hex(offset + (rsv0 << 32))));
    }
    Ok(info)
}

/// `PSPTool.ls_files` (`psptool.py:98-200`).
pub fn ls_files(
    psptool: &Bound<'_, PyAny>,
    files: Option<&Bound<'_, PyAny>>,
    verbose: bool,
) -> PyResult<()> {
    let py = psptool.py();
    let files = match files {
        Some(f) if !f.is_none() => f.clone(),
        _ => sorted_unique_files(psptool)?,
    };
    let basic = [
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
    let extended = [
        "flags",
        "MD5",
        "size_signed",
        "size_full",
        "size_packed",
        "load_addr",
    ];
    let mut rows = Vec::new();
    for (index, file) in files.try_iter()?.enumerate() {
        let file = file?;
        let entry = file.getattr("entry")?;
        let mut row = vec![
            String::new(),
            String::new(),
            index.to_string(),
            hex_of(&file.call_method0("get_address")?)?,
            hex_of(&file.getattr("buffer_size")?)?,
            call_str(&file, "get_readable_type")?,
            hex_of(&entry.getattr("subprogram")?)?,
            hex_of(&entry.getattr("instance")?)?,
            call_str(&file, "get_readable_magic")?,
            call_str(&file, "get_readable_version")?,
            file_info(&file)?.join(", "),
        ];
        if verbose {
            row.push(String::new());
            row.push(short_md5(&file)?);
            if file.is_exact_instance_of::<HeaderFile>() {
                for name in ["size_signed", "size_uncompressed", "rom_size", "load_addr"] {
                    row.push(hex_of(&file.getattr(name)?)?);
                }
            } else {
                row.extend(std::iter::repeat_n(String::new(), 4));
            }
        }
        rows.push(row);
    }
    let mut headers: Vec<&str> = basic.to_vec();
    if verbose {
        headers.extend(extended);
    }
    print(py, render(&headers, &rows, Align::Right))
}

/// `PSPTool.ls_json` (`psptool.py:202-218`).
pub fn ls_json(psptool: &Bound<'_, PyAny>, verbose: bool) -> PyResult<()> {
    let _ = verbose;
    let py = psptool.py();
    let data = PyList::empty(py);
    for rom in psptool.getattr("blob")?.getattr("roms")?.try_iter()? {
        for (index, directory) in rom?.getattr("directories")?.try_iter()?.enumerate() {
            let directory = directory?;
            let d = PyDict::new(py);
            d.set_item("directory", index)?;
            d.set_item("address", directory.call_method0("get_address")?)?;
            d.set_item("magic", magic_text(&directory)?)?;
            d.set_item(
                "secondaryAddresses",
                directory.getattr("secondary_directory_offsets")?,
            )?;
            d.set_item(
                "entries",
                ls_files_dict(psptool, Some(&directory.getattr("files")?))?,
            )?;
            data.append(d)?;
        }
    }
    let text: String = py
        .import("json")?
        .call_method1("dumps", (data,))?
        .extract()?;
    print(py, text)
}

/// `PSPTool.ls_files_dict` (`psptool.py:224-275`).
pub fn ls_files_dict<'py>(
    psptool: &Bound<'py, PyAny>,
    files: Option<&Bound<'py, PyAny>>,
) -> PyResult<Bound<'py, PyList>> {
    let py = psptool.py();
    let files = match files {
        Some(f) if !f.is_none() => f.clone(),
        _ => sorted_unique_files(psptool)?,
    };
    let out = PyList::empty(py);
    for (index, file) in files.try_iter()?.enumerate() {
        let file = file?;
        let mut info = Vec::new();
        if file.getattr("compressed")?.is_truthy()? {
            info.push("compressed".to_owned());
        }
        if file.getattr("is_signed")?.is_truthy()? {
            info.push(format!(
                "signed({})",
                call_str(&file, "get_readable_signed_by")?
            ));
            match file.getattr("signed_entity")?.call_method0("is_verified") {
                Ok(v) if v.is_truthy()? => info.push("verified".to_owned()),
                Ok(_) => {}
                Err(e) if e.is_instance_of::<NoCertifyingKey>(py) => info.push("no_key".to_owned()),
                Err(e) => return Err(e),
            }
        }
        if file.getattr("is_legacy")?.is_truthy()? {
            info.push("legacy header".to_owned());
        }
        if file.getattr("encrypted")?.is_truthy()? {
            info.push("encrypted".to_owned());
        }
        let values = PyDict::new(py);
        values.set_item("index", index)?;
        values.set_item("address", file.call_method0("get_address")?)?;
        values.set_item("size", file.getattr("buffer_size")?)?;
        let readable = call_str(&file, "get_readable_type")?;
        values.set_item("sectionType", &readable)?;
        values.set_item("magic", file.call_method0("get_readable_magic")?)?;
        values.set_item("version", file.call_method0("get_readable_version")?)?;
        values.set_item("info", info)?;
        values.set_item("md5", short_md5(&file)?)?;
        if readable == "BIOS" {
            values.set_item(
                "destinationAddress",
                file.call_method0("get_readable_destination_address")?,
            )?;
        }
        if file.is_instance_of::<HeaderFile>() {
            let sizes = PyDict::new(py);
            sizes.set_item("signed", file.getattr("size_signed")?)?;
            sizes.set_item("uncompressed", file.getattr("size_uncompressed")?)?;
            sizes.set_item("packed", file.getattr("rom_size")?)?;
            values.set_item("sizes", sizes)?;
            let (verified, method): (bool, String) =
                file.call_method0("decode_verification")?.extract()?;
            values.set_item("decodeVerified", verified)?;
            values.set_item("decodeVerificationMethod", method)?;
        }
        out.append(values)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_like_prettytable() {
        // Captured from prettytable 3.17 (the reference env's version).
        let t = render(
            &["ROM", "Addr", "AGESA"],
            &[vec!["0".into(), "0x0".into(), "AGESA!V9 X".into()]],
            Align::Center,
        );
        assert_eq!(
            t,
            "+-----+------+------------+\n\
             | ROM | Addr |   AGESA    |\n\
             +-----+------+------------+\n\
             |  0  | 0x0  | AGESA!V9 X |\n\
             +-----+------+------------+"
        );
        let t = render(&["", " ", "Entry"], &[], Align::Right);
        assert_eq!(
            t,
            "+--+---+-------+\n|  |   | Entry |\n+--+---+-------+\n+--+---+-------+"
        );
    }

    #[test]
    fn multi_line_cells_are_top_aligned() {
        let t = render(&["G"], &[vec!["a\nbcd".into()]], Align::Center);
        assert_eq!(t, "+-----+\n|  G  |\n+-----+\n|  a  |\n| bcd |\n+-----+");
    }
}
