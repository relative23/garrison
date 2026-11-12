//! A loopback HTTP server: answers each connection with the next canned
//! response and records the raw requests it received.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// How long the server waits for each request. A request that never comes
/// fails the test that collects the requests instead of letting it hang.
const PATIENCE: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub struct Server {
    pub url: String,
    handle: JoinHandle<Vec<String>>,
}

impl Server {
    /// Raw requests (head and body), in the order they arrived; fails unless
    /// every canned response was asked for.
    pub fn requests(self) -> Vec<String> {
        self.handle.join().unwrap()
    }
}

pub fn answer(status: u16, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

pub fn json(body: &serde_json::Value) -> String {
    answer(200, &body.to_string())
}

pub fn serve(responses: Vec<String>) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    // Polled, so that waiting for a connection can end.
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        for response in responses {
            let mut reader = BufReader::new(next(&listener, requests.len() + 1));
            let mut head = String::new();
            let mut length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap();
                }
                head.push_str(&line);
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            requests.push(head + &String::from_utf8(body).unwrap());
            reader.into_inner().write_all(response.as_bytes()).unwrap();
        }
        requests
    });
    Server { url, handle }
}

/// The connection of request `number`, which must arrive and be read within
/// `PATIENCE`.
fn next(listener: &TcpListener, number: usize) -> TcpStream {
    let deadline = Instant::now() + PATIENCE;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                stream.set_read_timeout(Some(PATIENCE)).unwrap();
                return stream;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "request {number} did not arrive within {PATIENCE:?}"
                );
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("{error}"),
        }
    }
}
