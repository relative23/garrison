//! Why a request of the HTTPS client got no answer, by the part of it that
//! failed.

use std::fmt;

/// Why a request got no answer: the part of it that failed, which a caller
/// that names what mends it decides by, and the words the functions that
/// give a text give, as `Display` writes them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failed {
    pub part: Part,
    words: String,
}

/// The part of a request that failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Part {
    /// The server's name: the system's lookup failed, gave no address, or
    /// gave none in time.
    Name,
    /// The server's certificate: not from an authority this host trusts,
    /// not for the server's name, or not valid at the time it is judged at.
    Certificate,
    /// Anything else: the address, the connection, TLS, the answer.
    Other,
}

impl Failed {
    pub(super) fn other(words: impl Into<String>) -> Self {
        Failed {
            part: Part::Other,
            words: words.into(),
        }
    }

    pub(super) fn name(words: String) -> Self {
        Failed {
            part: Part::Name,
            words,
        }
    }
}

impl fmt::Display for Failed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.words)
    }
}

impl From<Failed> for String {
    fn from(failed: Failed) -> String {
        failed.words
    }
}

/// Why TLS failed, by its part, the server's certificate or another.
pub(super) fn tls_failed(error: &std::io::Error) -> Failed {
    let certificate = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        .is_some_and(|tls| matches!(tls, rustls::Error::InvalidCertificate(_)));
    Failed {
        part: if certificate {
            Part::Certificate
        } else {
            Part::Other
        },
        words: super::tls_error(error),
    }
}
