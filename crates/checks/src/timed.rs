//! A connection whose every read and write must be done by one time, each
//! step within a shorter one. A server that says nothing is given up after a
//! step; one that sends a byte now and then cannot hold the caller beyond
//! the time of the whole exchange either.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct Timed {
    stream: TcpStream,
    until: Instant,
    step: Duration,
}

impl Timed {
    /// `stream`, with everything said over it done by `until`, and no step
    /// waiting longer than `step`.
    #[must_use]
    pub fn new(stream: TcpStream, until: Instant, step: Duration) -> Self {
        Timed {
            stream,
            until,
            step,
        }
    }

    /// How long the next step may wait; an error once the time is up.
    fn patience(&self) -> io::Result<Duration> {
        let left = self.until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the request was not done in its time",
            ));
        }
        Ok(left.min(self.step))
    }

    /// A step that waited out its time says so in words: the system's own
    /// error for it reads "Resource temporarily unavailable".
    fn waited<T>(&self, step: io::Result<T>) -> io::Result<T> {
        use io::ErrorKind::{TimedOut, WouldBlock};
        step.map_err(|error| match error.kind() {
            WouldBlock | TimedOut => match self.patience() {
                Ok(_) => io::Error::new(
                    TimedOut,
                    format!("the server was silent for {} s", self.step.as_secs()),
                ),
                Err(over) => over,
            },
            _ => error,
        })
    }
}

impl Read for Timed {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.patience()?))?;
        let read = self.stream.read(buffer);
        self.waited(read)
    }
}

impl Write for Timed {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.patience()?))?;
        let written = self.stream.write(data);
        self.waited(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}
