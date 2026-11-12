//! A harmless document that the scan takes for one with macros, as the
//! antivirus test file is harmless and yet refused: a zip archive whose
//! entry `word/vbaProject.bin` holds a line of text and no macro.
//!
//! The mail test sends it to see that the milter is asked and refuses.

use std::io::Write;

use flate2::Compression;
use flate2::write::DeflateEncoder;

/// The name the test document travels under.
pub const NAME: &str = "garrison-macro-test.docm";

/// One file for [`archive`]: its name, its content and whether to deflate it.
pub type Entry<'a> = (&'a str, &'a [u8], bool);

fn field(target: &mut Vec<u8>, value: usize, bytes: usize) {
    target.extend_from_slice(&value.to_le_bytes()[..bytes]);
}

/// A zip archive of `entries`, written as the format's specification has it,
/// with no checksums: nothing here unpacks it to use it.
#[must_use]
pub fn archive(entries: &[Entry<'_>]) -> Vec<u8> {
    let mut data = Vec::new();
    let mut directory = Vec::new();
    for (name, content, deflate) in entries {
        let packed = if *deflate {
            let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
            let _ = encoder.write_all(content);
            encoder.finish().unwrap_or_default()
        } else {
            content.to_vec()
        };
        let offset = data.len();
        let method = if *deflate { 8 } else { 0 };
        // The local header and the directory's entry share these fields.
        let mut shared = Vec::new();
        field(&mut shared, 20, 2); // version needed
        field(&mut shared, 0, 2); // flags
        field(&mut shared, method, 2);
        field(&mut shared, 0, 4); // time and date
        field(&mut shared, 0, 4); // checksum
        field(&mut shared, packed.len(), 4);
        field(&mut shared, content.len(), 4);
        field(&mut shared, name.len(), 2);
        field(&mut shared, 0, 2); // extra field
        data.extend_from_slice(b"PK\x03\x04");
        data.extend_from_slice(&shared);
        data.extend_from_slice(name.as_bytes());
        data.extend_from_slice(&packed);
        directory.extend_from_slice(b"PK\x01\x02");
        field(&mut directory, 20, 2); // version made by
        directory.extend_from_slice(&shared);
        field(&mut directory, 0, 2); // comment
        field(&mut directory, 0, 8); // disk, attributes
        field(&mut directory, offset, 4);
        directory.extend_from_slice(name.as_bytes());
    }
    let start = data.len();
    data.extend_from_slice(&directory);
    data.extend_from_slice(b"PK\x05\x06");
    field(&mut data, 0, 4); // disks
    field(&mut data, entries.len(), 2);
    field(&mut data, entries.len(), 2);
    field(&mut data, directory.len(), 4);
    field(&mut data, start, 4);
    field(&mut data, 0, 2); // comment
    data
}

/// The test document.
#[must_use]
pub fn document() -> Vec<u8> {
    archive(&[
        (
            "[Content_Types].xml",
            b"<?xml version=\"1.0\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"/>",
            true,
        ),
        (
            "word/vbaProject.bin",
            b"Garrison macro test: this file holds no macro.",
            false,
        ),
    ])
}
