//! A loopback listener that takes every connection and never says a word,
//! for the tests of a client that must give up on a server that does not
//! answer. It keeps the connections open until it is finished, and counts
//! them.

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};

#[derive(Debug)]
pub struct Silent {
    pub address: SocketAddr,
    /// `http://` and the address.
    pub url: String,
    done: Arc<AtomicBool>,
    held: JoinHandle<Vec<TcpStream>>,
}

impl Silent {
    #[must_use]
    pub fn new() -> Silent {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let done = Arc::new(AtomicBool::new(false));
        let ended = Arc::clone(&done);
        let held = thread::spawn(move || {
            let mut held = Vec::new();
            for stream in listener.incoming() {
                // The connection that `finish` makes to end the wait.
                if ended.load(Ordering::SeqCst) {
                    break;
                }
                held.push(stream.unwrap());
            }
            held
        });
        Silent {
            address,
            url: format!("http://{address}"),
            done,
            held,
        }
    }

    /// How many connections it took. The connections a client made before
    /// are all counted: they wait in line before the one that ends it.
    #[must_use]
    pub fn finish(self) -> usize {
        self.done.store(true, Ordering::SeqCst);
        drop(TcpStream::connect(self.address));
        self.held.join().unwrap().len()
    }
}

impl Default for Silent {
    fn default() -> Self {
        Silent::new()
    }
}
