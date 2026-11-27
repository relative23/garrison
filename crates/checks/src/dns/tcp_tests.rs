//! The questions the DNS client asks again over TCP, where the answer over
//! UDP was cut off.

use std::net::{TcpListener, UdpSocket};
use std::thread;

use super::tests::{FINE, answer, txt};
use super::*;

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
        ask(server, "example.test", Kind::Txt),
        Ok(Answer::Records(vec!["v=spf1 mx -all".to_owned()]))
    );
    handle.join().unwrap();
    // Nothing listens there.
    let silent = UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let error = ask(silent, "example.test", Kind::Txt).unwrap_err();
    assert!(
        matches!(error, Error::NoAnswer { server, .. } if server == silent),
        "{error:?}"
    );
    // Something takes the question and says nothing: its time runs out.
    let quiet = UdpSocket::bind("127.0.0.1:0").unwrap();
    let error = ask(quiet.local_addr().unwrap(), "example.test", Kind::Txt).unwrap_err();
    let waited = format!(
        "{} did not answer: no answer within 3 s",
        quiet.local_addr().unwrap()
    );
    assert_eq!(error.to_string(), format!("the resolver {waited}"));
}

/// The words of a question over TCP that failed after an answer cut off
/// over UDP.
const OVER_TCP: &str = "the resolver's answer is cut off, and the question over TCP failed";

/// An answer cut off over UDP is asked for over TCP: where nothing listens
/// for TCP, the question failed, which concerns this question alone, since
/// the resolver answered; where TCP cuts it off as well, it is cut off.
#[test]
fn the_question_over_tcp_fails_or_is_cut_off_again() {
    let cut = |question: &[u8]| answer(question, [0x83, 0x80], &[]);
    // No listener for TCP on the UDP port: the connection is refused.
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let server = udp.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let mut buffer = [0; 512];
        let (length, client) = udp.recv_from(&mut buffer).unwrap();
        udp.send_to(&cut(&buffer[..length]), client).unwrap();
    });
    let error = ask(server, "example.test", Kind::Txt).unwrap_err();
    assert!(!matches!(error, Error::NoAnswer { .. }), "{error:?}");
    assert_eq!(
        error.to_string(),
        format!("{OVER_TCP}: Connection refused (os error 111)")
    );
    handle.join().unwrap();
    // TCP answers, cut off again.
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
        udp.send_to(&cut(&buffer[..length]), client).unwrap();
        let (mut stream, _) = tcp.accept().unwrap();
        let mut size = [0; 2];
        stream.read_exact(&mut size).unwrap();
        let mut asked = vec![0; usize::from(u16::from_be_bytes(size))];
        stream.read_exact(&mut asked).unwrap();
        let again = cut(&asked);
        stream
            .write_all(&u16::try_from(again.len()).unwrap().to_be_bytes())
            .unwrap();
        stream.write_all(&again).unwrap();
    });
    assert_eq!(ask(server, "example.test", Kind::Txt), Err(Error::CutOff));
    handle.join().unwrap();
}

/// A resolver whose answer over UDP is cut off and that answers over TCP
/// as `tcp` does with its listener.
fn cut_off_then(tcp: fn(TcpListener)) -> SocketAddr {
    let (udp, listener) = (0..50)
        .find_map(|_| {
            let udp = UdpSocket::bind("127.0.0.1:0").ok()?;
            let listener = TcpListener::bind(udp.local_addr().ok()?).ok()?;
            Some((udp, listener))
        })
        .expect("a port that is free for UDP and TCP");
    let server = udp.local_addr().unwrap();
    thread::spawn(move || {
        let mut buffer = [0; 512];
        let (length, client) = udp.recv_from(&mut buffer).unwrap();
        let cut = answer(&buffer[..length], [0x83, 0x80], &[]);
        udp.send_to(&cut, client).unwrap();
    });
    thread::spawn(move || tcp(listener));
    server
}

/// A resolver that takes the connection over TCP and closes it without an
/// answer, at once or once it read the question, closed it: the system's
/// words for that ("failed to fill whole buffer", "Connection reset by
/// peer") say nothing of the kind.
#[test]
fn a_connection_over_tcp_closed_before_the_answer_says_so() {
    let closed = format!("{OVER_TCP}: the resolver closed the connection before it answered");
    let at_once = cut_off_then(|listener| {
        let (stream, _) = listener.accept().unwrap();
        drop(stream);
    });
    let read = cut_off_then(|listener| {
        let (mut stream, _) = listener.accept().unwrap();
        let mut size = [0; 2];
        stream.read_exact(&mut size).unwrap();
        let mut question = vec![0; usize::from(u16::from_be_bytes(size))];
        stream.read_exact(&mut question).unwrap();
    });
    for server in [at_once, read] {
        let error = ask(server, "example.test", Kind::Txt).unwrap_err();
        assert!(!matches!(error, Error::NoAnswer { .. }), "{error:?}");
        assert_eq!(error.to_string(), closed);
    }
}

/// A resolver that sends its answer over TCP an octet now and then holds
/// the question no longer than one that says nothing: the question's time
/// is one for the whole answer, not one for each octet.
#[test]
fn an_answer_over_tcp_that_comes_an_octet_at_a_time_does_not_hold_the_question() {
    let dripping = cut_off_then(|listener| {
        let (mut stream, _) = listener.accept().unwrap();
        let mut size = [0; 2];
        stream.read_exact(&mut size).unwrap();
        let mut question = vec![0; usize::from(u16::from_be_bytes(size))];
        stream.read_exact(&mut question).unwrap();
        // An answer of 600 octets is promised; one comes every half second
        // for ten seconds, each well inside a wait of three.
        let _ = stream.write_all(&600_u16.to_be_bytes());
        for _ in 0..20 {
            thread::sleep(Duration::from_millis(500));
            if stream.write_all(&[0]).is_err() {
                break;
            }
        }
    });
    let asked = Instant::now();
    let error = ask(dripping, "example.test", Kind::Txt).unwrap_err();
    let waited = asked.elapsed();
    assert_eq!(
        error.to_string(),
        format!("{OVER_TCP}: no answer within 3 s")
    );
    assert!(waited < Duration::from_millis(4500), "{waited:?}");
}
