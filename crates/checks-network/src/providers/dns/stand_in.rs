//! A resolver for the tests of the checks that ask DNS questions: it
//! answers from a zone of its own on a free port. Also the record data it
//! answers with.

use std::collections::BTreeMap;
use std::net::{SocketAddr, UdpSocket};
use std::thread;

/// A resolver on a free port that answers from `zone`: `(name, type)` to texts.
/// Names it does not hold do not exist; `silent` is never answered. The
/// thread ends with the numbers of the questions it was asked.
pub(crate) fn resolver(
    zone: BTreeMap<(String, u16), Vec<Vec<u8>>>,
    silent: Option<&'static str>,
    questions: usize,
) -> (SocketAddr, thread::JoinHandle<Vec<u16>>) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let mut numbers = Vec::new();
        for _ in 0..questions {
            let mut buffer = [0; 512];
            let (length, client) = socket.recv_from(&mut buffer).unwrap();
            let question = &buffer[..length];
            numbers.push(u16::from_be_bytes([question[0], question[1]]));
            // The name: labels from byte 12 to the zero.
            let mut name = Vec::new();
            let mut at = 12;
            while question[at] != 0 {
                let size = usize::from(question[at]);
                name.push(String::from_utf8_lossy(&question[at + 1..at + 1 + size]).into_owned());
                at += 1 + size;
            }
            let name = name.join(".");
            if Some(name.as_str()) == silent {
                continue;
            }
            let kind = u16::from_be_bytes([question[at + 1], question[at + 2]]);
            let mut message = question.to_vec();
            message[2] = 0x81;
            match zone.get(&(name, kind)) {
                Some(records) => {
                    message[3] = 0x80;
                    message[7] = u8::try_from(records.len()).unwrap();
                    for data in records {
                        message.extend_from_slice(&[0xc0, 12]);
                        message.extend_from_slice(&kind.to_be_bytes());
                        message.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
                        message
                            .extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
                        message.extend_from_slice(data);
                    }
                }
                None => message[3] = 0x83,
            }
            socket.send_to(&message, client).unwrap();
        }
        numbers
    });
    (address, handle)
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
