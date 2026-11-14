//! A loopback relay in front of a server that passes every connection's
//! bytes both ways. Before it passes a request that begins as named, it runs
//! a probe: a test looks at the server while the client waits there.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

/// A relay to `upstream` (`http://host:port`) at the returned URL; `probe`
/// runs before each request whose first bytes are `start`, such as
/// `GET /jmap/session `. It serves until the test process ends.
pub fn relay(
    upstream: &str,
    start: &'static str,
    probe: impl Fn() + Send + Sync + 'static,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let upstream = upstream.trim_start_matches("http://").to_owned();
    let probe = Arc::new(probe);
    thread::spawn(move || {
        for client in listener.incoming().flatten() {
            let server = TcpStream::connect(&upstream).unwrap();
            let (mut answers, mut back) =
                (server.try_clone().unwrap(), client.try_clone().unwrap());
            thread::spawn(move || {
                let _ = io::copy(&mut answers, &mut back);
                let _ = back.shutdown(Shutdown::Write);
            });
            let probe = Arc::clone(&probe);
            thread::spawn(move || forward(client, server, start, probe.as_ref()));
        }
    });
    url
}

/// The client's bytes on to the server, the probe first where a request
/// begins with `start`. A client writes each request's head at once, so it
/// begins a read.
fn forward(mut client: TcpStream, mut server: TcpStream, start: &str, probe: &dyn Fn()) {
    let mut buffer = vec![0; 64 * 1024];
    while let Ok(read) = client.read(&mut buffer) {
        if read == 0 {
            break;
        }
        if buffer[..read].starts_with(start.as_bytes()) {
            probe();
        }
        if server.write_all(&buffer[..read]).is_err() {
            break;
        }
    }
    let _ = server.shutdown(Shutdown::Write);
}
