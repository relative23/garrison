//! The memory all connections of one filter share, and the turn to scan.
//!
//! The room counts what the messages' buffers hold, not what was written
//! into them: a buffer that grows takes more than it is given at once, and
//! the unit's memory limit is about what is held. A buffer grows by half,
//! so that a message's many pieces are not copied one by one, never beyond
//! what a message may hold, and only by what the room still has.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, PoisonError};
use std::time::Instant;

/// What the messages being received may hold together, unless one message
/// alone may be larger.
pub(super) const HELD: usize = 256 * 1024 * 1024;

/// The turn to scan, which one connection has at a time: a scan holds
/// copies of the message it unpacks.
#[derive(Debug, Default)]
pub(super) struct Turn {
    taken: Mutex<bool>,
    free: Condvar,
}

/// The turn, until it is dropped.
pub(super) struct Taken<'a>(&'a Turn);

impl Turn {
    /// Wait for the turn, but not beyond `until`.
    pub(super) fn take(&self, until: Instant) -> Option<Taken<'_>> {
        let mut taken = self.taken.lock().unwrap_or_else(PoisonError::into_inner);
        while *taken {
            let left = until.checked_duration_since(Instant::now())?;
            if left.is_zero() {
                return None;
            }
            taken = self
                .free
                .wait_timeout(taken, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        *taken = true;
        Some(Taken(self))
    }
}

impl Drop for Taken<'_> {
    fn drop(&mut self) {
        *self.0.taken.lock().unwrap_or_else(PoisonError::into_inner) = false;
        self.0.free.notify_one();
    }
}

/// What all connections of one filter share: the room their messages take
/// and the turn to scan.
#[derive(Debug)]
pub struct Shared {
    /// The bytes all messages' buffers together may hold.
    pub(super) room: usize,
    pub(super) held: AtomicUsize,
    pub(super) scanning: Turn,
}

impl Shared {
    /// Room for the messages of a filter that scans messages of up to
    /// `max_bytes`: always enough for one message of that size.
    #[must_use]
    pub(crate) fn of(max_bytes: usize) -> Shared {
        Shared::with_room(HELD.max(max_bytes))
    }

    pub(super) fn with_room(room: usize) -> Shared {
        Shared {
            room,
            held: AtomicUsize::new(0),
            scanning: Turn::default(),
        }
    }

    /// Take `bytes` of the room, if they are there.
    fn take(&self, bytes: usize) -> bool {
        let mut held = self.held.load(Ordering::SeqCst);
        loop {
            let Some(sum) = held.checked_add(bytes).filter(|sum| *sum <= self.room) else {
                return false;
            };
            match self
                .held
                .compare_exchange(held, sum, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return true,
                Err(now) => held = now,
            }
        }
    }

    fn give_back(&self, bytes: usize) {
        self.held.fetch_sub(bytes, Ordering::SeqCst);
    }
}

/// One message as it arrives.
pub(super) struct Message<'a> {
    pub(super) shared: &'a Shared,
    pub(super) data: Vec<u8>,
    /// What this message has of the room: what its buffer holds.
    counted: usize,
    /// Whether the empty line between headers and body is written.
    headed: bool,
    /// More arrived than is scanned.
    pub(super) too_large: bool,
    /// The filter had no room left for it.
    pub(super) crowded: bool,
}

impl Drop for Message<'_> {
    fn drop(&mut self) {
        self.shared.give_back(self.counted);
    }
}

impl<'a> Message<'a> {
    pub(super) fn new(shared: &'a Shared) -> Self {
        Message {
            shared,
            data: Vec::new(),
            counted: 0,
            headed: false,
            too_large: false,
            crowded: false,
        }
    }

    /// Keep nothing of the message any more.
    fn let_go(&mut self) {
        self.shared.give_back(self.counted);
        self.counted = 0;
        self.data = Vec::new();
    }

    /// Make the buffer hold `length` bytes, of which none may exceed
    /// `limit`: by half as much again where the room has that, else by what
    /// is needed. `false` where the room has neither.
    fn holds(&mut self, length: usize, limit: usize) -> bool {
        let capacity = self.data.capacity();
        if length <= capacity {
            return true;
        }
        let ahead = capacity.saturating_add(capacity / 2).min(limit);
        for target in [ahead.max(length), length] {
            let more = target - capacity;
            if !self.shared.take(more) {
                continue;
            }
            if self
                .data
                .try_reserve_exact(target - self.data.len())
                .is_err()
            {
                // The system has no memory for it: no room either.
                self.shared.give_back(more);
                return false;
            }
            // An allocator may give more than it was asked for. What the
            // buffer holds is what counts, also where that passes the room.
            let surplus = self.data.capacity().saturating_sub(target);
            self.shared.held.fetch_add(surplus, Ordering::SeqCst);
            self.counted += more + surplus;
            return true;
        }
        false
    }

    pub(super) fn add(&mut self, bytes: &[u8], limit: usize) {
        if self.too_large || self.crowded {
            return;
        }
        let length = self.data.len().saturating_add(bytes.len());
        if length > limit {
            self.too_large = true;
            self.let_go();
        } else if self.holds(length, limit) {
            // Within what the buffer holds: this does not allocate.
            self.data.extend_from_slice(bytes);
        } else {
            self.crowded = true;
            self.let_go();
        }
    }

    pub(super) fn body(&mut self, limit: usize) {
        if !self.headed {
            self.headed = true;
            self.add(b"\r\n", limit);
        }
    }
}
