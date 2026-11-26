//! The two documents the macro test sends. Neither holds a macro.
//!
//! The first is a `.docm` whose `word/vbaProject.bin` is a real VBA project
//! with no module in it: a compound file with the streams `VBA/dir`,
//! `VBA/_VBA_PROJECT` and `PROJECT`. A virus scanner that reports documents
//! with macros reports it, as it reports the antivirus test file: `ClamAV`
//! with `AlertOLE2Macros yes` does (1.0.9, 1.4.7 and 1.5.5, measured on
//! 2026-11-26), since it goes by the project and not by a file's name. The
//! second is built the same way without a project, so that a policy on
//! attachments is told from a macro filter.

/// The name the test document travels under.
pub(super) const NAME: &str = "garrison-macro-test.docm";
/// The harmless document's name.
pub(super) const HARMLESS: &str = "garrison-harmless-test.docx";

const TYPES: &[u8] = b"<?xml version=\"1.0\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"/>";
/// The stream `PROJECT`: the project's properties as text, with no module.
const PROPERTIES: &[u8] =
    b"ID=\"{00000000-0000-0000-0000-000000000000}\"\r\nName=\"GarrisonMailTest\"\r\n\
                            HelpContextID=\"0\"\r\nVersionCompatible32=\"393222000\"\r\n";
/// The stream `_VBA_PROJECT` as a project without compiled code has it.
const CACHE: &[u8] = &[0xCC, 0x61, 0xFF, 0xFF, 0, 0, 0];

/// Sector numbers a compound file gives a meaning to.
const FREE: usize = 0xFFFF_FFFF;
const END: usize = 0xFFFF_FFFE;
const TABLE: usize = 0xFFFF_FFFD;
const SECTOR: usize = 512;
const SHORT: usize = 64;

fn field(target: &mut Vec<u8>, value: usize, bytes: usize) {
    target.extend_from_slice(&value.to_le_bytes()[..bytes]);
}

/// The test document.
pub(super) fn with_project() -> Vec<u8> {
    archive(&[
        ("[Content_Types].xml", TYPES),
        ("word/vbaProject.bin", &project()),
    ])
}

/// A document built as the test document is, with no project in it.
pub(super) fn harmless() -> Vec<u8> {
    archive(&[
        ("[Content_Types].xml", TYPES),
        (
            "word/document.xml",
            b"Garrison mail test: this document holds no macro.",
        ),
    ])
}

/// The checksum a zip archive keeps of each file.
fn checksum(bytes: &[u8]) -> [u8; 4] {
    let mut sum = u32::MAX;
    for byte in bytes {
        sum ^= u32::from(*byte);
        for _ in 0..8 {
            sum = (sum >> 1) ^ (0xEDB8_8320 & 0_u32.wrapping_sub(sum & 1));
        }
    }
    (!sum).to_le_bytes()
}

/// A zip archive of `entries`, each stored as it is.
fn archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut data = Vec::new();
    let mut directory = Vec::new();
    for (name, content) in entries {
        let offset = data.len();
        // The local header and the directory's entry share these fields.
        let mut shared = Vec::new();
        field(&mut shared, 20, 2); // version needed
        field(&mut shared, 0, 8); // flags, method (stored), time and date
        shared.extend_from_slice(&checksum(content));
        field(&mut shared, content.len(), 4);
        field(&mut shared, content.len(), 4);
        field(&mut shared, name.len(), 2);
        field(&mut shared, 0, 2); // extra field
        data.extend_from_slice(b"PK\x03\x04");
        data.extend_from_slice(&shared);
        data.extend_from_slice(name.as_bytes());
        data.extend_from_slice(content);
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

/// The stream `dir`: the project's records (MS-OVBA 2.3.4.2) up to the
/// terminator, with no module among them, in the container the format packs
/// streams into (2.4.1), written with literal bytes only.
fn records() -> Vec<u8> {
    let mut records = Vec::new();
    for (id, value) in [
        (0x0001, &1_u32.to_le_bytes()[..]), // the platform: 32-bit Windows
        (0x0002, &0x0409_u32.to_le_bytes()[..]), // the language
        (0x0014, &0x0409_u32.to_le_bytes()[..]), // the language of calls
        (0x0003, &1252_u16.to_le_bytes()[..]), // the code page
        (0x0004, &b"GarrisonMailTest"[..]), // the project's name
        (0x000F, &0_u16.to_le_bytes()[..]), // its modules: none
        (0x0013, &0xFFFF_u16.to_le_bytes()[..]), // the cookie
        (0x0010, &[][..]),                  // the terminator
    ] {
        field(&mut records, id, 2);
        field(&mut records, value.len(), 4);
        records.extend_from_slice(value);
    }
    let mut packed = Vec::new();
    for group in records.chunks(8) {
        packed.push(0);
        packed.extend_from_slice(group);
    }
    let mut stream = vec![1];
    // One chunk: its length less one, marked as packed.
    field(&mut stream, (packed.len() - 1) | 0xB000, 2);
    stream.extend_from_slice(&packed);
    stream
}

/// One entry of a compound file's directory: its name, its kind (1 a
/// storage, 2 a stream, 5 the root, 0 none), the entries left, right and
/// below it, and where its content starts and how long it is.
fn entry(name: &str, kind: u8, around: [usize; 3], start: usize, size: usize) -> Vec<u8> {
    let mut entry: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let named = if name.is_empty() { 0 } else { entry.len() + 2 };
    entry.resize(64, 0);
    field(&mut entry, named, 2);
    entry.extend_from_slice(&[kind, u8::from(kind != 0)]);
    for other in around {
        field(&mut entry, other, 4);
    }
    entry.resize(116, 0); // class, state and the two times
    field(&mut entry, start, 4);
    field(&mut entry, size, 8);
    entry
}

/// `vbaProject.bin`: a compound file (MS-CFB, version 3) with the three
/// streams. Each is short, so all lie in the stream of short sectors.
fn project() -> Vec<u8> {
    let streams = [records(), CACHE.to_vec(), PROPERTIES.to_vec()];
    let mut short = Vec::new();
    let mut chains = Vec::new();
    let mut placed = Vec::new();
    for stream in &streams {
        let first = short.len() / SHORT;
        let sectors = stream.len().div_ceil(SHORT).max(1);
        placed.push((first, stream.len()));
        short.extend_from_slice(stream);
        short.resize((first + sectors) * SHORT, 0);
        chains.extend(first + 1..first + sectors);
        chains.push(END);
    }
    let used = short.len();
    short.resize(used.div_ceil(SECTOR) * SECTOR, 0);
    let sectors = short.len() / SECTOR;
    // Sector 0 is the table of sectors, 1 and 2 the directory, 3 the table
    // of short sectors; the stream of short sectors follows from 4.
    let mut table = vec![TABLE, 2, END, END];
    table.extend((0..sectors).map(|at| if at + 1 == sectors { END } else { at + 5 }));
    table.resize(SECTOR / 4, FREE);
    chains.resize(SECTOR / 4, FREE);

    let mut file = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
    file.resize(24, 0); // class
    for value in [0x3E, 3, 0xFFFE, 9, 6] {
        field(&mut file, value, 2); // versions, byte order, the two sector sizes
    }
    file.resize(40, 0);
    // Sectors of the directory (unsaid in version 3) and of the table, the
    // directory's first sector, a transaction number, the size below which a
    // stream is short, the short table's first sector and its count, no
    // further table of tables, and the table's own sector.
    for value in [0, 1, 1, 0, 4096, 3, 1, END, 0, 0] {
        field(&mut file, value, 4);
    }
    file.resize(SECTOR, 0xFF);
    for sector in &table {
        field(&mut file, *sector, 4);
    }
    let [dir, cache, properties] = [placed[0], placed[1], placed[2]];
    file.extend(entry("Root Entry", 5, [FREE, FREE, 1], 4, used));
    file.extend(entry("VBA", 1, [FREE, 4, 2], 0, 0));
    file.extend(entry("dir", 2, [FREE, 3, FREE], dir.0, dir.1));
    file.extend(entry("_VBA_PROJECT", 2, [FREE; 3], cache.0, cache.1));
    file.extend(entry("PROJECT", 2, [FREE; 3], properties.0, properties.1));
    for _ in 0..3 {
        file.extend(entry("", 0, [FREE; 3], 0, 0));
    }
    for sector in &chains {
        field(&mut file, *sector, 4);
    }
    file.extend_from_slice(&short);
    file
}

#[cfg(test)]
mod tests {
    use garrison_core::hex;
    use sha2::{Digest, Sha256};

    use super::*;

    fn digest(bytes: &[u8]) -> String {
        hex::encode(&Sha256::digest(bytes))
    }

    /// The bytes that `ClamAV` 1.0.9, 1.4.7 and 1.5.5 were shown on
    /// 2026-11-26: with `AlertOLE2Macros` each reported the first, as a file
    /// and in the test's message, and none the second. A change of either
    /// document is shown to a `ClamAV` again before this test follows it.
    #[test]
    fn the_documents_are_the_ones_a_virus_scanner_was_shown() {
        assert_eq!(
            digest(&with_project()),
            "446118292da9ed245507a17a8cc20e1cff16fa380a11c2435d1c855b1d2e16e7"
        );
        assert_eq!(
            digest(&harmless()),
            "a30c56432f660f2881cb31075279adfd8775833b656a5f43c2f0eaa93ae77b0f"
        );
    }

    /// What makes the first a document with a project and the second one
    /// without: the compound file under the name a project has, with its
    /// three streams, and no module among the project's records.
    #[test]
    fn only_the_test_document_carries_a_project_and_it_has_no_module() {
        let project = project();
        assert_eq!(
            project[..8],
            [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]
        );
        let named =
            |name: &str| -> Vec<u8> { name.encode_utf16().flat_map(u16::to_le_bytes).collect() };
        let holds = |all: &[u8], part: &[u8]| all.windows(part.len()).any(|window| window == part);
        for stream in ["VBA", "dir", "_VBA_PROJECT", "PROJECT"] {
            assert!(holds(&project, &named(stream)), "{stream}");
        }
        // The record of the modules, unpacked: its number, its length, none.
        let unpacked: Vec<u8> = records()[3..]
            .chunks(9)
            .flat_map(|group| group[1..].to_vec())
            .collect();
        assert!(holds(&unpacked, &[0x0F, 0, 2, 0, 0, 0, 0, 0]));
        assert!(holds(&with_project(), b"word/vbaProject.bin"));
        assert!(holds(&with_project(), &project));
        assert!(!holds(&harmless(), b"vbaProject"));
        assert!(!holds(&harmless(), &project[..8]));
    }
}
