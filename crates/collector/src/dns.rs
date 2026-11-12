//! A small DNS client: one question to one resolver, the answers as text.
//!
//! The collector asks this host's resolver for the records Stalwart names for
//! a domain. It asks over UDP and, where the answer was cut off, again over
//! TCP. Only the record types a mail domain publishes are read; everything
//! else in an answer is skipped. What comes back is data from the network:
//! every length is checked, and a name may point back only so often.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(3);
/// A name may follow this many pointers; more is a loop.
const MOST_POINTERS: usize = 16;
const MOST_ANSWERS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    A,
    Aaaa,
    Cname,
    Mx,
    Ptr,
    Txt,
    Srv,
    Tlsa,
}

impl Kind {
    pub const fn code(self) -> u16 {
        match self {
            Kind::A => 1,
            Kind::Cname => 5,
            Kind::Ptr => 12,
            Kind::Mx => 15,
            Kind::Txt => 16,
            Kind::Aaaa => 28,
            Kind::Srv => 33,
            Kind::Tlsa => 52,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Kind::A => "A",
            Kind::Aaaa => "AAAA",
            Kind::Cname => "CNAME",
            Kind::Mx => "MX",
            Kind::Ptr => "PTR",
            Kind::Txt => "TXT",
            Kind::Srv => "SRV",
            Kind::Tlsa => "TLSA",
        }
    }

    pub fn named(name: &str) -> Option<Kind> {
        [
            Kind::A,
            Kind::Aaaa,
            Kind::Cname,
            Kind::Mx,
            Kind::Ptr,
            Kind::Txt,
            Kind::Srv,
            Kind::Tlsa,
        ]
        .into_iter()
        .find(|kind| kind.name() == name)
    }
}

/// What a resolver said to one question.
#[derive(Debug, PartialEq, Eq)]
pub enum Answer {
    /// The records of the asked type, as text; none if the name has none.
    Records(Vec<String>),
    /// The name does not exist.
    NoSuchName,
}

/// The name under which an address's reverse record stands, or, with a
/// blocklist's `zone`, the name that list answers for it: the octets of an
/// IPv4 address, the 32 hexadecimal digits of an IPv6 address, last first.
pub fn reversed(address: IpAddr, zone: Option<&str>) -> String {
    let (labels, own): (Vec<String>, &str) = match address {
        IpAddr::V4(address) => (
            address.octets().iter().rev().map(u8::to_string).collect(),
            "in-addr.arpa",
        ),
        IpAddr::V6(address) => (
            address
                .octets()
                .iter()
                .rev()
                .flat_map(|byte| [byte & 0x0f, byte >> 4])
                .map(|digit| format!("{digit:x}"))
                .collect(),
            "ip6.arpa",
        ),
    };
    format!("{}.{}", labels.join("."), zone.unwrap_or(own))
}

/// The resolvers of `/etc/resolv.conf`, in its order.
pub fn resolvers(text: &str) -> Vec<IpAddr> {
    text.lines()
        .filter_map(|line| line.trim().strip_prefix("nameserver"))
        .filter_map(|rest| rest.split_whitespace().next())
        // An address with a zone (`fe80::1%eth0`) is asked without it.
        .filter_map(|address| address.split('%').next()?.parse().ok())
        .collect()
}

/// The question as it goes out: one name, one type, recursion wanted.
fn question(id: u16, name: &str, kind: Kind) -> Option<Vec<u8>> {
    let mut message = Vec::with_capacity(32 + name.len());
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.') {
        let length = u8::try_from(label.len())
            .ok()
            .filter(|length| (1..=63).contains(length))?;
        message.push(length);
        message.extend_from_slice(label.as_bytes());
    }
    message.push(0);
    message.extend_from_slice(&kind.code().to_be_bytes());
    message.extend_from_slice(&[0, 1]);
    (message.len() <= 512).then_some(message)
}

/// The name that starts at `at`, and where the record goes on after it.
fn name_at(message: &[u8], at: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let (mut position, mut after, mut pointers) = (at, None, 0);
    loop {
        let length = usize::from(*message.get(position)?);
        match length {
            0 => {
                position += 1;
                break;
            }
            1..=63 => {
                let label = message.get(position + 1..position + 1 + length)?;
                if !name.is_empty() {
                    name.push('.');
                }
                // Names are compared as text; bytes that are no text stay visible.
                name.extend(label.iter().map(|byte| match byte {
                    b'.' | b'\\' => '?',
                    0x21..=0x7e => char::from(*byte).to_ascii_lowercase(),
                    _ => '?',
                }));
                position += 1 + length;
            }
            192..=255 => {
                let low = usize::from(*message.get(position + 1)?);
                after.get_or_insert(position + 2);
                pointers += 1;
                if pointers > MOST_POINTERS {
                    return None;
                }
                position = ((length & 0x3f) << 8) | low;
            }
            _ => return None,
        }
        if name.len() > 255 {
            return None;
        }
    }
    Some((name, after.unwrap_or(position)))
}

fn number(message: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *message.get(at)?,
        *message.get(at + 1)?,
    ]))
}

/// The data of one record as text, the way a zone file writes it.
fn data(message: &[u8], kind: Kind, start: usize, end: usize) -> Option<String> {
    let bytes = message.get(start..end)?;
    Some(match kind {
        Kind::A => {
            let octets: [u8; 4] = bytes.try_into().ok()?;
            IpAddr::from(octets).to_string()
        }
        Kind::Aaaa => {
            let octets: [u8; 16] = bytes.try_into().ok()?;
            IpAddr::from(octets).to_string()
        }
        Kind::Cname | Kind::Ptr => name_at(message, start)?.0,
        Kind::Mx => format!(
            "{} {}",
            number(message, start)?,
            name_at(message, start + 2)?.0
        ),
        Kind::Txt => {
            // One record is a row of strings, each with its length; together
            // they are the text.
            let mut text = Vec::new();
            let mut rest = bytes;
            while let [length, tail @ ..] = rest {
                let piece = tail.get(..usize::from(*length))?;
                text.extend_from_slice(piece);
                rest = &tail[usize::from(*length)..];
            }
            String::from_utf8_lossy(&text).into_owned()
        }
        Kind::Srv => format!(
            "{} {} {} {}",
            number(message, start)?,
            number(message, start + 2)?,
            number(message, start + 4)?,
            name_at(message, start + 6)?.0
        ),
        Kind::Tlsa => {
            let [usage, selector, matching, digest @ ..] = bytes else {
                return None;
            };
            let hex = garrison_core::hex::encode(digest);
            format!("{usage} {selector} {matching} {hex}")
        }
    })
}

/// The answers to the question `id` asked, or why the message gives none.
/// `Ok(None)` means it was cut off and must be asked for again over TCP.
pub fn read(message: &[u8], id: u16, kind: Kind) -> Result<Option<Answer>, String> {
    let malformed = || "the resolver's answer is malformed".to_owned();
    if message.len() < 12 || number(message, 0) != Some(id) || message[2] & 0x80 == 0 {
        return Err(malformed());
    }
    if message[2] & 0x02 != 0 {
        return Ok(None);
    }
    match message[3] & 0x0f {
        0 => {}
        3 => return Ok(Some(Answer::NoSuchName)),
        2 => return Err("the resolver could not answer (SERVFAIL)".to_owned()),
        5 => return Err("the resolver refused the question".to_owned()),
        code => return Err(format!("the resolver answered with error {code}")),
    }
    let questions = number(message, 4).ok_or_else(malformed)?;
    let answers = usize::from(number(message, 6).ok_or_else(malformed)?);
    let mut position = 12;
    for _ in 0..questions {
        position = name_at(message, position).ok_or_else(malformed)?.1 + 4;
    }
    let mut records = Vec::new();
    for _ in 0..answers.min(MOST_ANSWERS) {
        position = name_at(message, position).ok_or_else(malformed)?.1;
        let found = number(message, position).ok_or_else(malformed)?;
        let length = usize::from(number(message, position + 8).ok_or_else(malformed)?);
        let start = position + 10;
        let end = start + length;
        if end > message.len() {
            return Err(malformed());
        }
        // A CNAME on the way to the asked type is followed by the resolver.
        if found == kind.code() {
            records.push(data(message, kind, start, end).ok_or_else(malformed)?);
        }
        position = end;
    }
    Ok(Some(Answer::Records(records)))
}

fn over_udp(server: SocketAddr, question: &[u8]) -> std::io::Result<Vec<u8>> {
    let local: SocketAddr = if server.is_ipv4() {
        ([0, 0, 0, 0], 0).into()
    } else {
        ([0u16; 8], 0).into()
    };
    let socket = UdpSocket::bind(local)?;
    socket.set_read_timeout(Some(TIMEOUT))?;
    socket.connect(server)?;
    socket.send(question)?;
    let mut answer = vec![0; 4096];
    let length = socket.recv(&mut answer)?;
    answer.truncate(length);
    Ok(answer)
}

fn over_tcp(server: SocketAddr, question: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect_timeout(&server, TIMEOUT)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    let length = u16::try_from(question.len()).unwrap_or(u16::MAX);
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(question)?;
    let mut size = [0; 2];
    stream.read_exact(&mut size)?;
    let mut answer = vec![0; usize::from(u16::from_be_bytes(size))];
    stream.read_exact(&mut answer)?;
    Ok(answer)
}

/// Ask `server` for the records of `kind` at `name`.
pub fn ask(server: SocketAddr, name: &str, kind: Kind, id: u16) -> Result<Answer, String> {
    let question = question(id, name, kind).ok_or_else(|| format!("{name} is no DNS name"))?;
    let unreachable =
        |error: std::io::Error| format!("the resolver {server} did not answer: {error}");
    let answer = over_udp(server, &question).map_err(unreachable)?;
    if let Some(answer) = read(&answer, id, kind)? {
        return Ok(answer);
    }
    let answer = over_tcp(server, &question).map_err(unreachable)?;
    read(&answer, id, kind)?.ok_or_else(|| "the resolver's answer is cut off".to_owned())
}

#[cfg(test)]
mod tests;
