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
}

impl Test {
    pub(super) fn label(self) -> &'static str {
        match self {
            Test::Eicar => "Antivirus test file (EICAR)",
            Test::Gtube => "Spam test text (GTUBE)",
            Test::Macro => "Office document with macros (test document)",
        }
    }

    /// The subject of the test message. Stalwart's filter takes the spam text
    /// for the test only where it is the whole subject.
    fn subject(self) -> String {
        match self {
            Test::Eicar | Test::Macro => format!("Garrison mail test: {}", self.label()),
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
        }
    }

    /// What tells the tests' message IDs apart.
    fn kind(self) -> &'static str {
        match self {
            Test::Eicar => "eicar",
            Test::Gtube => "gtube",
            Test::Macro => "macro",
        }
    }

    /// The content type and what follows the headers. The macro test's
    /// document travels as an attachment, as such documents do.
    fn content(self) -> String {
        if self != Test::Macro {
            return format!(
                "Content-Type: text/plain; charset=us-ascii\r\n\r\n{}",
                self.body()
            );
        }
        let encoded = STANDARD.encode(sample::document());
        let lines: Vec<&str> = encoded
            .as_bytes()
            .chunks(76)
            .filter_map(|line| std::str::from_utf8(line).ok())
            .collect();
        format!(
            "Content-Type: multipart/mixed; boundary=\"garrison-mail-test\"\r\n\r\n\
             --garrison-mail-test\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\n{body}\r\n\
             --garrison-mail-test\r\n\
             Content-Type: application/vnd.ms-word.document.macroEnabled.12; name=\"{name}\"\r\n\
             Content-Disposition: attachment; filename=\"{name}\"\r\n\
             Content-Transfer-Encoding: base64\r\n\r\n{document}\r\n--garrison-mail-test--",
            body = self.body(),
            name = sample::NAME,
            document = lines.join("\r\n"),
        )
    }

    /// The whole message as it is sent after `DATA`, with the line that ends it.
    pub(super) fn message(self, envelope: &Envelope<'_>) -> String {
        format!(
            "From: Garrison mail test <{from}>\r\nTo: <{to}>\r\nSubject: {subject}\r\n\
             Date: {date}\r\nMessage-ID: <{stamp}.{kind}@{host}>\r\nAuto-Submitted: auto-generated\r\n\
             MIME-Version: 1.0\r\n{content}\r\n.\r\n",
            from = envelope.from,
            to = envelope.to,
            subject = self.subject(),
            date = envelope.date,
            stamp = envelope.stamp,
            kind = self.kind(),
            host = envelope.host,
            content = self.content(),
        )
    }
}
