//! The time a run has for its checks: the page, Stalwart's own page and the
//! files are asked only while there is time left, and what was not asked is
//! said.

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use garrison_testing::http::serve;
use garrison_testing::silent::Silent;

use super::*;
use crate::context::Deadline;
use crate::fetch::roots;

/// A page that loads three files of its own host.
const PAGE: &str = r#"<html><head><link rel="stylesheet" href="/a.css">
<script src="/b.js"></script><script src="/c.js"></script></head></html>"#;

fn html(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// The page's host: each connection gets the next of `answers` after its
/// delay, and every one after them is held without a word.
struct PageHost {
    url: String,
    address: SocketAddr,
    done: Arc<AtomicBool>,
    handle: JoinHandle<usize>,
}

impl PageHost {
    fn new(answers: Vec<(String, Duration)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let done = Arc::new(AtomicBool::new(false));
        let ended = Arc::clone(&done);
        let handle = thread::spawn(move || {
            let (mut taken, mut held) = (0, Vec::new());
            loop {
                let (mut stream, _) = listener.accept().unwrap();
                // The connection that `finish` makes to end the wait.
                if ended.load(Ordering::SeqCst) {
                    return taken;
                }
                taken += 1;
                let Some((answer, delay)) = answers.get(taken - 1) else {
                    held.push(stream);
                    continue;
                };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                while reader.read_line(&mut line).unwrap() > 0 && line != "\r\n" {
                    line.clear();
                }
                thread::sleep(*delay);
                stream.write_all(answer.as_bytes()).unwrap();
            }
        });
        PageHost {
            url: format!("http://{address}"),
            address,
            done,
            handle,
        }
    }

    /// How many connections it took.
    fn finish(self) -> usize {
        self.done.store(true, Ordering::SeqCst);
        drop(TcpStream::connect(self.address));
        self.handle.join().unwrap()
    }
}

#[test]
fn a_file_that_never_comes_costs_one_wait_and_the_others_are_said() {
    let public = PageHost::new(vec![(html(PAGE), Duration::ZERO)]);
    let own = serve(vec![html(PAGE)]);
    let page = format!("{}/login", public.url);
    let began = Instant::now();
    let examined = examine(
        &page,
        &format!("{}/login", own.url),
        "a=b",
        &roots(),
        Deadline::within(Duration::from_secs(1)),
    );
    let took = began.elapsed();
    own.requests();
    // The page and its first file, whose wait used up the run's time.
    assert_eq!(public.finish(), 2);
    assert!(took < Duration::from_secs(14), "{took:?}");
    assert_eq!(examined.state, State::Failed);
    assert!(
        examined.what.starts_with(&format!(
            "Stalwart's sign-in page {page} cannot load /a.css ("
        )),
        "{}",
        examined.what
    );
    assert!(
        examined
            .what
            .ends_with("; 2 more were not asked: the collection run's time was used up"),
        "{}",
        examined.what
    );
    assert_eq!(examined.files, Some(3));
}

#[test]
fn nothing_is_asked_once_the_runs_time_is_over() {
    let (public, own) = (Silent::new(), Silent::new());
    let page = format!("{}/login", public.url);
    let examined = examine(
        &page,
        &format!("{}/login", own.url),
        "a=b",
        &roots(),
        Deadline::within(Duration::ZERO),
    );
    assert_eq!((public.finish(), own.finish()), (0, 0));
    assert_eq!(examined.state, State::Unknown);
    assert_eq!(
        examined.what,
        format!(
            "Stalwart's sign-in page {page} was not asked: the collection run's time was used up"
        )
    );
}

#[test]
fn a_page_that_came_late_is_not_held_against_stalwarts_own() {
    let public = PageHost::new(vec![(html(PAGE), Duration::from_millis(1200))]);
    let own = Silent::new();
    let page = format!("{}/login", public.url);
    let stalwart = format!("{}/login", own.url);
    let examined = examine(
        &page,
        &stalwart,
        "a=b",
        &roots(),
        Deadline::within(Duration::from_secs(1)),
    );
    assert_eq!((public.finish(), own.finish()), (1, 0));
    assert_eq!(examined.state, State::Unknown);
    assert_eq!(
        examined.what,
        format!(
            "{page} answered, but Stalwart's own page at {stalwart} and the files it loads were \
             not asked: the collection run's time was used up"
        )
    );
}

#[test]
fn files_in_order_that_used_up_the_time_leave_the_page_unknown() {
    let style = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Type: text/css\r\nConnection: close\r\n\r\na{}";
    let public = PageHost::new(vec![
        (html(PAGE), Duration::ZERO),
        (style.to_owned(), Duration::from_millis(1200)),
    ]);
    let own = serve(vec![html(PAGE)]);
    let page = format!("{}/login", public.url);
    let examined = examine(
        &page,
        &format!("{}/login", own.url),
        "a=b",
        &roots(),
        Deadline::within(Duration::from_secs(1)),
    );
    own.requests();
    assert_eq!(public.finish(), 2);
    // What came was in order, and the rest is not known.
    assert_eq!(examined.state, State::Unknown);
    assert_eq!(
        examined.what,
        format!(
            "Of the 3 files the sign-in page at {page} loads, 2 were not asked: the collection \
             run's time was used up"
        )
    );
    assert_eq!(examined.files, Some(3));
}
