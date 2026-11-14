//! The connections that are open at one time.
//!
//! A place is given back when its connection ends, however it ends: a
//! thread that panics gives it back as it unwinds. Counted by hand, every
//! such end would have cost a place for as long as the filter runs, until
//! none was left and it answered nobody.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// How many connections are open, and how many found no place.
#[derive(Debug, Default)]
pub(super) struct Places {
    open: AtomicUsize,
    turned_away: AtomicU64,
}

/// One connection's place, until it is dropped.
#[derive(Debug)]
pub(super) struct Place(Arc<Places>);

impl Places {
    /// A place, unless `most` are taken.
    pub(super) fn take(self: &Arc<Self>, most: usize) -> Option<Place> {
        let mut open = self.open.load(Ordering::SeqCst);
        loop {
            if open >= most {
                return None;
            }
            match self
                .open
                .compare_exchange(open, open + 1, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return Some(Place(Arc::clone(self))),
                Err(now) => open = now,
            }
        }
    }

    /// Count a connection that found no place: how many there were, where
    /// that is worth a line in the journal (the first and every hundredth).
    pub(super) fn turned_away(&self) -> Option<u64> {
        let count = self.turned_away.fetch_add(1, Ordering::SeqCst) + 1;
        (count == 1 || count.is_multiple_of(100)).then_some(count)
    }

    #[cfg(test)]
    pub(super) fn open(&self) -> usize {
        self.open.load(Ordering::SeqCst)
    }
}

impl Drop for Place {
    fn drop(&mut self) {
        self.0.open.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_place_is_free_again_however_its_connection_ends() {
        let places = Arc::new(Places::default());
        let first = places.take(2).unwrap();
        let second = places.take(2).unwrap();
        assert!(places.take(2).is_none());
        // A connection ends as it should.
        drop(first);
        assert_eq!(places.open(), 1);
        // Another ends in a panic of its thread.
        let ended = std::thread::spawn(move || {
            let _place = second;
            panic!("a session that fails");
        })
        .join();
        assert!(ended.is_err());
        assert_eq!(places.open(), 0);
        assert!(places.take(2).is_some());
    }

    #[test]
    fn the_journal_gets_the_first_refusal_and_every_hundredth() {
        let places = Places::default();
        let said: Vec<u64> = (0..250).filter_map(|_| places.turned_away()).collect();
        assert_eq!(said, [1, 100, 200]);
    }
}
