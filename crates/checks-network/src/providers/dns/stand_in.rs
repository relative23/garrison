//! A resolver for the tests of the checks that ask DNS questions: it
//! answers from a zone of its own on a free port. Also the record data it
//! answers with.

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

/// A resolver on a free port that answers from `zone`: `(name, type)` to texts.
/// Names it does not hold do not exist; `silent` is never answered. The
/// thread ends with the numbers of the questions it was asked.
pub(crate) fn resolver(
    zone: BTreeMap<(String, u16), Vec<Vec<u8>>>,
    silent: Option<&'static str>,
    questions: usize,
) -> (SocketAddr, thread::JoinHandle<Vec<u16>>) {
    resolver_after(zone, silent, questions, Duration::ZERO)
}

/// Like [`resolver`], answering each question `delay` after it came.
pub(crate) fn resolver_after(
    zone: BTreeMap<(String, u16), Vec<Vec<u8>>>,
    silent: Option<&'static str>,
    questions: usize,
    delay: Duration,
) -> (SocketAddr, thread::JoinHandle<Vec<u16>>) {
    serve(zone, BTreeMap::new(), silent, questions, delay)
}

/// Like [`resolver`], answering each question of `errors`, `(name, type)`,
/// with its error code instead (SERVFAIL 2, REFUSED 5), as a resolver does
/// that cannot or will not answer it.
pub(crate) fn resolver_erring(
    zone: BTreeMap<(String, u16), Vec<Vec<u8>>>,
    errors: BTreeMap<(String, u16), u8>,
    questions: usize,
) -> (SocketAddr, thread::JoinHandle<Vec<u16>>) {
    serve(zone, errors, None, questions, Duration::ZERO)
}

/// A resolver like [`resolver`] that answers until it is stopped, and never
/// answers a question for a name that `silent` takes: [`Stopping::questions`]
/// stops it and gives every question it was asked, by name and type, in the
/// order they came.
pub(crate) fn resolver_until(
    zone: BTreeMap<(String, u16), Vec<Vec<u8>>>,
    silent: fn(&str) -> bool,
) -> (SocketAddr, Stopping) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    // Polled, so that the thread sees when it is stopped.
    socket
        .set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    let done = Arc::new(AtomicBool::new(false));
    let stopped = Arc::clone(&done);
    let handle = thread::spawn(move || {
        let mut questions = Vec::new();
        let mut buffer = [0; 512];
        while !stopped.load(Ordering::SeqCst) {
            let (length, client) = match socket.recv_from(&mut buffer) {
                Ok(received) => received,
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                {
                    continue;
                }
                Err(error) => panic!("{error}"),
            };
            let question = &buffer[..length];
            let (name, kind) = asked(question);
            if !silent(&name) {
                let message = answered(question, &name, kind, &zone, &BTreeMap::new());
                socket.send_to(&message, client).unwrap();
            }
            questions.push((name, kind));
        }
        questions
    });
    (address, Stopping { done, handle })
}

/// A [`resolver_until`] at work.
pub(crate) struct Stopping {
    done: Arc<AtomicBool>,
    handle: thread::JoinHandle<Vec<(String, u16)>>,
}

impl Stopping {
    /// Stop the resolver: every question it was asked, by name and type.
    pub(crate) fn questions(self) -> Vec<(String, u16)> {
        self.done.store(true, Ordering::SeqCst);
        self.handle.join().unwrap()
    }
}

fn serve(
    zone: BTreeMap<(String, u16), Vec<Vec<u8>>>,
    errors: BTreeMap<(String, u16), u8>,
    silent: Option<&'static str>,
    questions: usize,
    delay: Duration,
) -> (SocketAddr, thread::JoinHandle<Vec<u16>>) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let mut numbers = Vec::new();
        for _ in 0..questions {
            let mut buffer = [0; 512];
            let (length, client) = socket.recv_from(&mut buffer).unwrap();
            thread::sleep(delay);
            let question = &buffer[..length];
            numbers.push(u16::from_be_bytes([question[0], question[1]]));
            let (name, kind) = asked(question);
            if Some(name.as_str()) == silent {
                continue;
            }
            let message = answered(question, &name, kind, &zone, &errors);
            socket.send_to(&message, client).unwrap();
        }
        numbers
    });
    (address, handle)
}

/// The name a question asks, its labels from byte 12 to the zero, and its
/// type.
fn asked(question: &[u8]) -> (String, u16) {
    let mut name = Vec::new();
    let mut at = 12;
    while question[at] != 0 {
        let size = usize::from(question[at]);
        name.push(String::from_utf8_lossy(&question[at + 1..at + 1 + size]).into_owned());
        at += 1 + size;
    }
    let kind = u16::from_be_bytes([question[at + 1], question[at + 2]]);
    (name.join("."), kind)
}

/// The answer to `question`, which asks for the records of `kind` at
/// `name`: with its error code where `errors` names one, the records `zone`
/// holds, or that the name does not exist.
fn answered(
    question: &[u8],
    name: &str,
    kind: u16,
    zone: &BTreeMap<(String, u16), Vec<Vec<u8>>>,
    errors: &BTreeMap<(String, u16), u8>,
) -> Vec<u8> {
    let mut message = question.to_vec();
    message[2] = 0x81;
    let asked = (name.to_owned(), kind);
    if let Some(code) = errors.get(&asked) {
        message[3] = 0x80 | code;
        return message;
    }
    match zone.get(&asked) {
        Some(records) => {
            message[3] = 0x80;
            message[7] = u8::try_from(records.len()).unwrap();
            for data in records {
                message.extend_from_slice(&[0xc0, 12]);
                message.extend_from_slice(&kind.to_be_bytes());
                message.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
                message.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
                message.extend_from_slice(data);
            }
        }
        None => message[3] = 0x83,
    }
    message
}

/// Whether `numbers` are all one, or each one more than the one before:
/// numbers an answer from elsewhere could guess.
pub(crate) fn guessable(numbers: &[u16]) -> bool {
    numbers.windows(2).all(|pair| pair[1] == pair[0])
        || numbers
            .windows(2)
            .all(|pair| pair[1] == pair[0].wrapping_add(1))
}

pub(super) fn text(value: &str) -> Vec<u8> {
    let mut data = vec![u8::try_from(value.len()).unwrap()];
    data.extend_from_slice(value.as_bytes());
    data
}

pub(super) fn host(prefix: &[u8], name: &str) -> Vec<u8> {
    let mut data = prefix.to_vec();
    for label in name.split('.') {
        data.push(u8::try_from(label.len()).unwrap());
        data.extend_from_slice(label.as_bytes());
    }
    data.push(0);
    data
}
