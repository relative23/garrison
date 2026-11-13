use std::net::{TcpListener, UdpSocket};
use std::thread;

use garrison_testing::noise::Noise;

use super::*;

/// A name in wire form, without compression.
fn wire(name: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        bytes.push(u8::try_from(label.len()).unwrap());
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
    bytes
}

/// An answer to `question` with the given records `(type, data)`; the owner
/// of each record is a pointer to the question's name.
fn answer(question: &[u8], flags: [u8; 2], records: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut message = question.to_vec();
    message[2] = flags[0];
    message[3] = flags[1];
    message[6..8].copy_from_slice(&u16::try_from(records.len()).unwrap().to_be_bytes());
    for (kind, data) in records {
        message.extend_from_slice(&[0xc0, 12]);
        message.extend_from_slice(&kind.to_be_bytes());
        message.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
        message.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
        message.extend_from_slice(data);
    }
    message
}

fn txt(pieces: &[&str]) -> Vec<u8> {
    let mut data = Vec::new();
    for piece in pieces {
        data.push(u8::try_from(piece.len()).unwrap());
        data.extend_from_slice(piece.as_bytes());
    }
    data
}

fn asked(kind: Kind, flags: [u8; 2], records: &[(u16, Vec<u8>)]) -> Result<Option<Answer>, String> {
    let question = question(7, "example.test", kind).unwrap();
    read(&answer(&question, flags, records), 7, kind)
}

const FINE: [u8; 2] = [0x81, 0x80];

#[test]
fn records_are_read_as_a_zone_file_writes_them() {
    let mut mx = vec![0, 10];
    mx.extend(wire("mail.Example.TEST"));
    let mut srv = vec![0, 0, 0, 1, 0x01, 0xbb];
    srv.extend(wire("mail.example.test"));
    for (kind, data, text) in [
        (Kind::A, vec![192, 0, 2, 1], "192.0.2.1"),
        (
            Kind::Aaaa,
            vec![0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            "2001:db8::1",
        ),
        (Kind::Mx, mx, "10 mail.example.test"),
        (
            Kind::Cname,
            wire("target.example.org"),
            "target.example.org",
        ),
        // A long text comes in pieces; together they are the record.
        (
            Kind::Txt,
            txt(&["v=DKIM1; p=AAAA", "BBBB"]),
            "v=DKIM1; p=AAAABBBB",
        ),
        (Kind::Srv, srv, "0 1 443 mail.example.test"),
        (Kind::Tlsa, vec![3, 1, 1, 0x7b, 0x26, 0xff], "3 1 1 7b26ff"),
    ] {
        assert_eq!(
            asked(kind, FINE, &[(kind.code(), data)]),
            Ok(Some(Answer::Records(vec![text.to_owned()]))),
            "{kind:?}"
        );
    }
    // Records of another type, such as the CNAME on the way, are passed over.
    assert_eq!(
        asked(
            Kind::Txt,
            FINE,
            &[
                (5, wire("alias.example.org")),
                (16, txt(&["v=spf1 mx -all"]))
            ]
        ),
        Ok(Some(Answer::Records(vec!["v=spf1 mx -all".to_owned()])))
    );
    assert_eq!(
        asked(Kind::Txt, FINE, &[]),
        Ok(Some(Answer::Records(Vec::new())))
    );
}

#[test]
fn what_a_resolver_says_instead_of_records() {
    assert_eq!(
        asked(Kind::Mx, [0x81, 0x83], &[]),
        Ok(Some(Answer::NoSuchName))
    );
    assert_eq!(asked(Kind::Mx, [0x83, 0x80], &[]), Ok(None), "cut off");
    assert_eq!(
        asked(Kind::Mx, [0x81, 0x82], &[]),
        Err("the resolver could not answer (SERVFAIL)".to_owned())
    );
    assert_eq!(
        asked(Kind::Mx, [0x81, 0x85], &[]),
        Err("the resolver refused the question".to_owned())
    );
    let question = question(7, "example.test", Kind::Mx).unwrap();
    let malformed = Err("the resolver's answer is malformed".to_owned());
    // Another question's answer, a question sent back, a record longer than
    // the message, a name that points at itself.
    assert_eq!(read(&answer(&question, FINE, &[]), 8, Kind::Mx), malformed);
    assert_eq!(read(&question, 7, Kind::Mx), malformed);
    let mut cut = answer(&question, FINE, &[(15, vec![0, 10, 0])]);
    cut.truncate(cut.len() - 2);
    assert_eq!(read(&cut, 7, Kind::Mx), malformed);
    let looping = answer(&question, FINE, &[(5, vec![0xc0, 0x25])]);
    let at = looping.len() - 2;
    let mut looping = looping;
    looping[at + 1] = u8::try_from(at).unwrap();
    assert_eq!(read(&looping, 7, Kind::Cname), malformed);
}

#[test]
fn names_and_resolvers() {
    assert_eq!(question(1, "a..b", Kind::A), None);
    assert_eq!(question(1, &"a".repeat(64), Kind::A), None);
    assert!(question(1, "example.test.", Kind::A).is_some());
    assert_eq!(
        resolvers(
            "# comment\nsearch example.test\nnameserver 192.0.2.53\nnameserver 2001:db8::53\nnameserver fe80::1%eth0\nnameserver nonsense\n"
        ),
        [
            "192.0.2.53".parse::<IpAddr>().unwrap(),
            "2001:db8::53".parse().unwrap(),
            "fe80::1".parse().unwrap()
        ]
    );
    assert_eq!(Kind::named("TLSA"), Some(Kind::Tlsa));
    assert_eq!(Kind::named("NS"), None);
}

#[test]
fn an_answer_cut_off_over_udp_is_asked_for_again_over_tcp() {
    // One port for both, as a resolver has it. A port that is free for UDP
    // may be taken for TCP by another test, so the pair is looked for.
    let (udp, tcp) = (0..50)
        .find_map(|_| {
            let udp = UdpSocket::bind("127.0.0.1:0").ok()?;
            let tcp = TcpListener::bind(udp.local_addr().ok()?).ok()?;
            Some((udp, tcp))
        })
        .expect("a port that is free for UDP and TCP");
    let server = udp.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let mut buffer = [0; 512];
        let (length, client) = udp.recv_from(&mut buffer).unwrap();
        let question = buffer[..length].to_vec();
        udp.send_to(&answer(&question, [0x83, 0x80], &[]), client)
            .unwrap();
        let (mut stream, _) = tcp.accept().unwrap();
        let mut size = [0; 2];
        stream.read_exact(&mut size).unwrap();
        let mut asked = vec![0; usize::from(u16::from_be_bytes(size))];
        stream.read_exact(&mut asked).unwrap();
        assert_eq!(asked, question);
        let full = answer(&question, FINE, &[(16, txt(&["v=spf1 mx -all"]))]);
        stream
            .write_all(&u16::try_from(full.len()).unwrap().to_be_bytes())
            .unwrap();
        stream.write_all(&full).unwrap();
    });
    assert_eq!(
        ask(server, "example.test", Kind::Txt, 99),
        Ok(Answer::Records(vec!["v=spf1 mx -all".to_owned()]))
    );
    handle.join().unwrap();
    // Nothing listens there.
    let silent = UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    assert!(
        ask(silent, "example.test", Kind::Txt, 1)
            .unwrap_err()
            .contains("did not answer")
    );
}

#[test]
fn random_answers_never_panic() {
    let mut noise = Noise::new(0x0d15_ea5e_0bad_f00d);
    let question = question(7, "example.test", Kind::Txt).unwrap();
    for round in 0..40_000 {
        // Random bytes after a header that passes, and real answers with bytes changed.
        let mut message = answer(
            &question,
            FINE,
            &[(16, txt(&["v=spf1 mx -all"])), (15, vec![0, 10, 0xc0, 12])],
        );
        if round % 2 == 0 {
            message.truncate(12);
            message[5] = 0;
            message[7] = u8::try_from(noise.below(4)).unwrap();
            for _ in 0..noise.below(80) {
                message.push(u8::try_from(noise.below(256)).unwrap());
            }
        } else {
            for _ in 0..=noise.below(4) {
                let at = 4 + noise.below(message.len() - 4);
                message[at] = u8::try_from(noise.below(256)).unwrap();
            }
        }
        for kind in [
            Kind::A,
            Kind::Aaaa,
            Kind::Cname,
            Kind::Mx,
            Kind::Txt,
            Kind::Srv,
            Kind::Tlsa,
        ] {
            let _ = read(&message, 7, kind);
        }
    }
}
