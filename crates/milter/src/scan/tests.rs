use std::fmt::Write as _;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use super::*;
use crate::sample::{archive, document};

/// A message with `attachment` in base64, as a mail program writes it.
pub(crate) fn message(name: &str, attachment: &[u8]) -> Vec<u8> {
    let encoded = STANDARD.encode(attachment);
    let lines: Vec<&str> = encoded
        .as_bytes()
        .chunks(76)
        .map(|line| std::str::from_utf8(line).unwrap())
        .collect();
    format!(
        "From: a@example.net\r\nTo: b@example.test\r\nSubject: The invoice\r\nMIME-Version: 1.0\r\n\
         Content-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n--b1\r\nContent-Type: text/plain\r\n\r\n\
         Please see the attachment.\r\n--b1\r\nContent-Type: application/octet-stream; name=\"{name}\"\r\n\
         Content-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"{name}\"\r\n\r\n\
         {}\r\n--b1--\r\n",
        lines.join("\r\n")
    )
    .into_bytes()
}

/// An old Office file as far as the scan reads one: the compound file's
/// first bytes and a directory that names what `storages` names.
fn compound(storages: &[&str]) -> Vec<u8> {
    let mut data = OLE.to_vec();
    data.resize(512, 0);
    for name in storages {
        data.extend(name.encode_utf16().flat_map(u16::to_le_bytes));
        data.resize(data.len() + 100, 0);
    }
    data
}

const TEXT: &[u8] = b"<w:document><w:body><w:p>Nothing but text.</w:p></w:body></w:document>";

fn plain_document() -> Vec<u8> {
    archive(&[
        ("[Content_Types].xml", b"<Types/>", true),
        ("word/document.xml", TEXT, true),
    ])
}

#[test]
fn a_new_office_file_with_macros_is_found_whatever_it_is_called() {
    assert_eq!(
        macros(&message("invoice.docm", &document())),
        Some(Found::Zipped)
    );
    // The name is the sender's choice; the content is not.
    assert_eq!(
        macros(&message("invoice.docx", &document())),
        Some(Found::Zipped)
    );
    assert_eq!(
        macros(&message("holiday.jpg", &document())),
        Some(Found::Zipped)
    );
    let sheets = archive(&[
        ("xl/workbook.xml", b"<workbook/>", true),
        ("xl/macrosheets/sheet1.xml", b"<x/>", true),
    ]);
    assert_eq!(
        macros(&message("prices.xlsx", &sheets)),
        Some(Found::Zipped)
    );
    let upper = archive(&[("WORD/VBAPROJECT.BIN", b"x", true)]);
    assert_eq!(macros(&message("a.docm", &upper)), Some(Found::Zipped));
    assert_eq!(macros(&message("letter.docx", &plain_document())), None);
}

#[test]
fn macros_under_another_name_or_named_only_in_the_directory_are_found() {
    // The macros' file is a compound file with a VBA project whatever it is
    // called, and a document may call it anything.
    let project = compound(&["VBA", "_VBA_PROJECT", "dir"]);
    for deflate in [false, true] {
        let renamed = archive(&[
            ("[Content_Types].xml", b"<Types/>", true),
            ("word/media/image1.bin", &project, deflate),
        ]);
        assert_eq!(
            macros(&message("invoice.docx", &renamed)),
            Some(Found::Compound),
            "{deflate}"
        );
    }
    // Office reads the directory at the archive's end. A header before the
    // file that names it otherwise does not hide it.
    let mut listed = archive(&[("word/vbaProject.bin", b"x", false)]);
    let name = listed
        .windows(4)
        .position(|window| window == b"word")
        .unwrap();
    listed[name..name + 19].copy_from_slice(b"word/aaaaaaaaaa.xml");
    assert_eq!(macros(&message("a.docm", &listed)), Some(Found::Zipped));
    // A workbook's Excel 4.0 macro sheets.
    let sheets = archive(&[("xl/macrosheets/sheet1.xml", b"<macrosheet/>", true)]);
    assert_eq!(macros(&message("a.xlsm", &sheets)), Some(Found::Zipped));
    // An archive cut off inside a name still names it as far as it goes.
    let whole = archive(&[("word/vbaProject.bin", b"x", false)]);
    assert_eq!(macros(&whole[..30 + 19]), Some(Found::Zipped));
    assert_eq!(macros(&whole[..30 + 4]), None);
}

#[test]
fn an_old_office_file_with_a_vba_project_is_found() {
    let with = compound(&["WordDocument", "Macros", "VBA", "_VBA_PROJECT"]);
    assert_eq!(macros(&message("report.doc", &with)), Some(Found::Compound));
    let without = compound(&["WordDocument", "SummaryInformation"]);
    assert_eq!(macros(&message("report.doc", &without)), None);
    // The marker alone, without a compound file around it, is text.
    let text: Vec<u8> = "_VBA_PROJECT"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    assert_eq!(macros(&message("notes.txt", &text)), None);
}

#[test]
fn a_document_inside_archives_is_found_as_deep_as_the_scan_goes() {
    let inner = document();
    let one = archive(&[("invoice.docm", &inner, true)]);
    assert_eq!(macros(&message("invoice.zip", &one)), Some(Found::Zipped));
    let two = archive(&[("readme.txt", b"open me", true), ("more.zip", &one, true)]);
    assert_eq!(macros(&message("archive.zip", &two)), Some(Found::Zipped));
    // Stored, not deflated: its files are in plain sight.
    let stored = archive(&[("invoice.docm", &inner, false)]);
    assert_eq!(macros(&message("stored.zip", &stored)), Some(Found::Zipped));
    // An old file in an archive.
    let old = archive(&[("report.doc", &compound(&["_VBA_PROJECT"]), true)]);
    assert_eq!(macros(&message("old.zip", &old)), Some(Found::Compound));
    // Deeper than the scan goes. Each archive also holds a long text, so
    // that what is deflated in it is packed and not merely stored.
    let filler = TEXT.repeat(4000);
    let hidden = archive(&[
        ("word/document.xml", &filler, true),
        ("word/vbaProject.bin", b"x", true),
    ]);
    let mut nested = archive(&[("filler.txt", &filler, true), ("a.docm", &hidden, true)]);
    for _ in 0..DEPTH {
        nested = archive(&[("filler.txt", &filler, true), ("next.zip", &nested, true)]);
    }
    assert_eq!(macros(&message("deep.zip", &nested)), None);
    let clean = archive(&[("letter.docx", &plain_document(), true)]);
    assert_eq!(macros(&message("clean.zip", &clean)), None);
}

#[test]
fn a_message_written_wrongly_on_purpose_does_not_hide_the_document() {
    let encoded = STANDARD.encode(document());
    // No MIME at all: headers, then base64 broken by empty lines and of odd widths.
    let mut body = String::from("Subject: x\r\n\r\n");
    for (index, chunk) in encoded.as_bytes().chunks(60).enumerate() {
        body.push_str(std::str::from_utf8(chunk).unwrap());
        body.push_str(if index % 3 == 0 { "\r\n\r\n" } else { "\n" });
    }
    assert_eq!(macros(body.as_bytes()), Some(Found::Zipped));
    // A boundary that is not the one the header names, and no end.
    let odd = format!(
        "Content-Type: multipart/mixed; boundary=one\r\n\r\n--two\r\nContent-Transfer-Encoding: base64\r\n\r\n{encoded}\r\n"
    );
    assert_eq!(macros(odd.as_bytes()), Some(Found::Zipped));
    // Without padding.
    let unpadded = format!("Subject: x\r\n\r\n{}\r\n", encoded.trim_end_matches('='));
    assert_eq!(macros(unpadded.as_bytes()), Some(Found::Zipped));
    // As it stands, in a part that says it is binary.
    let mut binary = b"Content-Transfer-Encoding: binary\r\n\r\n".to_vec();
    binary.extend(document());
    assert_eq!(macros(&binary), Some(Found::Zipped));
    // Quoted-printable, which mail programs undo for any part that says so.
    let mut quoted = String::from("Content-Transfer-Encoding: quoted-printable\r\n\r\n");
    for (index, byte) in document().iter().enumerate() {
        write!(quoted, "={byte:02X}").unwrap();
        if index % 20 == 19 {
            quoted.push_str("=\r\n");
        }
    }
    assert_eq!(macros(quoted.as_bytes()), Some(Found::Zipped));
}

#[test]
fn text_about_macros_and_other_attachments_are_left_alone() {
    let talk = b"Subject: Question\r\n\r\nWhere in a .docm is word/vbaProject.bin kept? And what is _VBA_PROJECT? PK!\r\n";
    assert_eq!(macros(talk), None);
    let picture: Vec<u8> = (0..20_000u32)
        .flat_map(|value| value.wrapping_mul(2_654_435_761).to_le_bytes())
        .collect();
    assert_eq!(macros(&message("photo.jpg", &picture)), None);
    let page = [b"ActiveMime\0\0\x01\xf0".as_slice(), &[7u8; 200]].concat();
    assert_eq!(macros(&message("page.mso", &page)), Some(Found::ActiveMime));
    // The word alone is no such file: in a text, at a text's beginning, or
    // in an attachment that is text.
    let word =
        b"Subject: x\r\n\r\nActiveMime is how Word keeps macros in a web page.\r\nActiveMime\r\n";
    assert_eq!(macros(word), None);
    let notes = [
        b"ActiveMime: notes on the format. ".as_slice(),
        &[b'a'; 200],
    ]
    .concat();
    assert_eq!(macros(&message("notes.txt", &notes)), None);
    // Nor is an archive with a text that names the macros' file, stored or
    // deflated, or with a file whose name only comes near.
    let about = b"In a .docm the macros are word/vbaProject.bin; in a workbook, xl/macrosheets/.";
    for deflate in [false, true] {
        let manual = archive(&[
            ("manual/office.txt", about, deflate),
            ("manual/vbaproject.txt", b"See office.txt.", deflate),
        ]);
        assert_eq!(macros(&message("manual.zip", &manual)), None, "{deflate}");
    }
    assert_eq!(macros(b""), None);
    assert_eq!(
        Found::Zipped.name(),
        "an Office document (Open XML) with macros"
    );
}

#[test]
fn an_archive_that_unpacks_to_far_more_than_it_is_ends_the_scan_in_time() {
    // Forty megabytes of zeros deflate to a few kilobytes, eight times over.
    let zeros = vec![0u8; 40 * 1024 * 1024];
    let names: Vec<String> = (0..8).map(|index| format!("{index}.bin")).collect();
    let listed: Vec<(&str, &[u8], bool)> = names
        .iter()
        .map(|name| (name.as_str(), zeros.as_slice(), true))
        .collect();
    let bomb = archive(&listed);
    assert!(bomb.len() < 1024 * 1024, "{}", bomb.len());
    let began = Instant::now();
    assert_eq!(macros(&message("big.zip", &bomb)), None);
    assert!(
        began.elapsed() < Duration::from_secs(20),
        "{:?}",
        began.elapsed()
    );
}

#[test]
fn random_bytes_and_cut_archives_never_panic() {
    // The same bytes on every run: a xorshift generator from a fixed seed.
    let mut state: u64 = 23;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let whole = message("invoice.docm", &archive(&[("a.docm", &document(), true)]));
    for round in 0..400 {
        let mut data = whole.clone();
        // Cut somewhere, and change a few bytes.
        data.truncate(usize::try_from(next() % (whole.len() as u64 + 1)).unwrap());
        for _ in 0..(round % 5) {
            if !data.is_empty() {
                let at = usize::try_from(next() % data.len() as u64).unwrap();
                data[at] = next().to_le_bytes()[0];
            }
        }
        let _ = macros(&data);
        let noise: Vec<u8> = (0..(next() % 600))
            .map(|_| next().to_le_bytes()[0])
            .collect();
        let _ = macros(&noise);
        let _ = macros(&[b"PK\x03\x04".as_slice(), &noise].concat());
    }
}
