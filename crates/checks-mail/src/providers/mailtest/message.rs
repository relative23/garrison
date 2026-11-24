//! The test messages: what each carries and how it is written.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use garrison_milter::sample;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Test {
    Eicar,
    Gtube,
    /// A document that a macro filter takes for one with macros.
    Macro,
    /// A message that carries nothing to refuse, sent beside a test the
    /// server refused: only where the server takes it is that refusal the
    /// test's.
    Control,
    /// The same beside the macro test: a harmless document of the same
    /// build, so that a policy on attachments is no macro filter.
    Document,
}

/// The harmless document's name and type.
const HARMLESS: &str = "garrison-harmless-test.docx";
const DOCX: &str = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

/// A document built as the macro test's is, with no macro project in it.
fn harmless_document() -> Vec<u8> {
    sample::archive(&[
        (
            "[Content_Types].xml",
            b"<?xml version=\"1.0\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"/>",
            true,
        ),
        (
            "word/document.xml",
            b"Garrison mail test: this document holds no macro.",
            false,
        ),
    ])
}

/// Who a test message is from and for, and when it was written.
pub(super) struct Envelope<'a> {
    pub from: &'a str,
    pub to: &'a str,
    /// The date as a mail header has it.
    pub date: String,
    /// The two halves of the message ID.
    pub stamp: i64,
    pub host: &'a str,
    /// Whether this is the copy sent again at once, which has an ID of its
    /// own: a server may take a second message of one ID for the first.
    pub again: bool,
}

impl Test {
    pub(super) fn label(self) -> &'static str {
        match self {
            Test::Eicar => "Antivirus test file (EICAR)",
            Test::Gtube => "Spam test text (GTUBE)",
            Test::Macro => "Office document with macros (test document)",
            Test::Control => "Harmless message (control)",
            Test::Document => "Harmless document (control)",
        }
    }

    /// The harmless message of the same build, sent beside this test where
    /// the server refused it.
    pub(super) fn twin(self) -> Test {
        match self {
            Test::Macro | Test::Document => Test::Document,
            Test::Eicar | Test::Gtube | Test::Control => Test::Control,
        }
    }

    /// The subject of the test message. Stalwart's filter takes the spam text
    /// for the test only where it is the whole subject.
    fn subject(self) -> String {
        match self {
            Test::Eicar | Test::Macro | Test::Control | Test::Document => {
                format!("Garrison mail test: {}", self.label())
            }
            Test::Gtube => self.body(),
        }
    }

    /// The text a scanner or filter knows. The test file is put together
    /// here, so that this source and the program are not taken for it.
    pub(super) fn body(self) -> String {
        match self {
            Test::Eicar => [
                "X5O!P%@AP[4\\PZX54(P^)7CC)7}$",
                "EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
                "!$H+H*",
            ]
            .concat(),
            Test::Gtube => [
                "XJS*C4JDBQADN1.NSBN3*2IDNEN*",
                "GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL",
                "*C.34X",
            ]
            .concat(),
            Test::Macro => "The attached document is harmless: it holds no macro,\r\n\
                            only the name a macro project has in a document."
                .to_owned(),
            Test::Control => "This message carries nothing to refuse. Garrison sends it beside \
                              a test\r\nthe server refused, to tell a verdict from a server \
                              that refuses all mail."
                .to_owned(),
            Test::Document => "The attached document is harmless: it holds no macro project. \
                               Garrison sends it\r\nbeside the test document the server \
                               refused."
                .to_owned(),
        }
    }

    /// What tells the tests' message IDs apart.
    fn kind(self) -> &'static str {
        match self {
            Test::Eicar => "eicar",
            Test::Gtube => "gtube",
            Test::Macro => "macro",
            Test::Control => "control",
            Test::Document => "document",
        }
    }

    /// The content type and what follows the headers. The macro test's
    /// document, and the harmless one beside it, travel as an attachment, as
    /// such documents do.
    fn content(self) -> String {
        let (document, kind, name) = match self {
            Test::Macro => (
                sample::document(),
                "application/vnd.ms-word.document.macroEnabled.12",
                sample::NAME,
            ),
            Test::Document => (harmless_document(), DOCX, HARMLESS),
            Test::Eicar | Test::Gtube | Test::Control => {
                return format!(
                    "Content-Type: text/plain; charset=us-ascii\r\n\r\n{}",
                    self.body()
                );
            }
        };
        let encoded = STANDARD.encode(document);
        let lines: Vec<&str> = encoded
            .as_bytes()
            .chunks(76)
            .filter_map(|line| std::str::from_utf8(line).ok())
            .collect();
        format!(
            "Content-Type: multipart/mixed; boundary=\"garrison-mail-test\"\r\n\r\n\
             --garrison-mail-test\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\n{body}\r\n\
             --garrison-mail-test\r\n\
             Content-Type: {kind}; name=\"{name}\"\r\n\
             Content-Disposition: attachment; filename=\"{name}\"\r\n\
             Content-Transfer-Encoding: base64\r\n\r\n{document}\r\n--garrison-mail-test--",
            body = self.body(),
            document = lines.join("\r\n"),
        )
    }

    /// The whole message as it is sent after `DATA`, with the line that ends it.
    pub(super) fn message(self, envelope: &Envelope<'_>) -> String {
        format!(
            "From: Garrison mail test <{from}>\r\nTo: <{to}>\r\nSubject: {subject}\r\n\
             Date: {date}\r\nMessage-ID: <{stamp}.{kind}{again}@{host}>\r\nAuto-Submitted: auto-generated\r\n\
             MIME-Version: 1.0\r\n{content}\r\n.\r\n",
            from = envelope.from,
            to = envelope.to,
            subject = self.subject(),
            date = envelope.date,
            stamp = envelope.stamp,
            kind = self.kind(),
            again = if envelope.again { ".again" } else { "" },
            host = envelope.host,
            content = self.content(),
        )
    }
}
