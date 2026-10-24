//! Robustness pin for `replace_*_entry_body` (`replace.rs`) on a crafted,
//! untrusted image. Synthetic bytes only.

use psptool_core::{BlobEditor, Directory, FlashOffset, RomSize, SourceBytes};
use psptool_ops::replace_psp_entry_body;

/// Severity: low (silent half-applied edit for library callers).
///
/// `apply` (`replace.rs:213-238`) records the directory record's `size` patch
/// and the recomputed header checksum *before* the body patch, and its comment
/// claims "either both succeed or neither commits". That holds for bounds, not
/// for overlap: an entry whose body aliases its own directory (here the body
/// starts at the directory header) makes the body patch collide with the
/// checksum patch just recorded, so `apply` returns `PatchError::Overlap` with
/// two patches left in the editor. A caller that skips the failed replace and
/// serializes anyway writes a ROM whose record and checksum describe a body
/// that was never written.
///
/// Expected: a failed replace leaves the editor unchanged.
#[test]
fn robust_replace_failed_replace_leaves_editor_clean() {
    let dir_at = 0x1000usize;
    let mut buf = vec![0u8; 0x2000];
    buf[dir_at..dir_at + 4].copy_from_slice(b"$PSP");
    buf[dir_at + 8..dir_at + 12].copy_from_slice(&1u32.to_le_bytes());
    buf[dir_at + 12..dir_at + 16].copy_from_slice(&0x2000_0000u32.to_le_bytes()); // mode 01
    buf[dir_at + 0x10] = 0x01;
    buf[dir_at + 0x14..dir_at + 0x18].copy_from_slice(&0x40u32.to_le_bytes()); // size
    buf[dir_at + 0x18..dir_at + 0x1C].copy_from_slice(&(dir_at as u32).to_le_bytes()); // body = dir

    let blob = SourceBytes::from_blob(buf);
    let Directory::Psp(dir) = Directory::parse_at(&blob, FlashOffset(dir_at as u64)).unwrap()
    else {
        panic!("fixture: not a $PSP directory");
    };
    let mut editor = BlobEditor::from_blob(blob);
    let result = replace_psp_entry_body(
        &mut editor,
        &dir,
        0,
        RomSize::MIB_8,
        FlashOffset::ZERO,
        &[0u8; 0x10],
    );
    assert!(result.is_err(), "fixture: the body patch must collide");
    assert!(
        editor.is_clean(),
        "failed replace ({:?}) left {} patch(es) in the editor",
        result.err(),
        editor.patch_count()
    );
}
