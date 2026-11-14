//! One question at a time for each session.
//!
//! A page asks for a dozen things at once. When the session's grant had run
//! out, each of those requests asked the broker, which serves sixteen at a
//! time: two such pages kept everyone else waiting or out. Here the first
//! request of a session asks, and those that arrive before the answer wait
//! for it and take it.

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex, PoisonError};

/// How a question that is under way stands.
enum State<T> {
    Asked,
    Answered(T),
    /// Whoever asked went away without an answer, as in a panic.
    Abandoned,
}

struct Flight<T> {
    state: Mutex<State<T>>,
    landed: Condvar,
}

impl<T: Clone> Flight<T> {
    /// The answer, once it is there; `None` if none will come.
    fn awaited(&self) -> Option<T> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            match &*state {
                State::Asked => {
                    state = self
                        .landed
                        .wait(state)
                        .unwrap_or_else(PoisonError::into_inner);
                }
                State::Answered(answer) => return Some(answer.clone()),
                State::Abandoned => return None,
            }
        }
    }
}

/// The questions that are under way, by what they are about.
pub(super) struct Flights<T> {
    under_way: Mutex<HashMap<String, Arc<Flight<T>>>>,
}

/// The end of a question, however it ends: its entry goes, and those who
/// wait for it are woken.
struct Landing<'a, T> {
    flights: &'a Flights<T>,
    key: &'a str,
    flight: &'a Arc<Flight<T>>,
}

impl<T> Drop for Landing<'_, T> {
    fn drop(&mut self) {
        let mut state = self
            .flight
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if matches!(*state, State::Asked) {
            *state = State::Abandoned;
        }
        drop(state);
        self.flights
            .under_way
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(self.key);
        self.flight.landed.notify_all();
    }
}

impl<T: Clone> Flights<T> {
    pub(super) fn new() -> Self {
        Flights {
            under_way: Mutex::new(HashMap::new()),
        }
    }

    /// The answer of `ask` about `key`: this caller's own, or that of the
    /// caller who is asking about `key` at this moment.
    pub(super) fn share(&self, key: &str, ask: impl FnOnce() -> T) -> T {
        let (flight, first) = {
            let mut under_way = self
                .under_way
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(flight) = under_way.get(key) {
                (Arc::clone(flight), false)
            } else {
                let flight = Arc::new(Flight {
                    state: Mutex::new(State::Asked),
                    landed: Condvar::new(),
                });
                under_way.insert(key.to_owned(), Arc::clone(&flight));
                (flight, true)
            }
        };
        if !first {
            // Whoever asked may have gone without an answer: then this
            // caller asks for itself.
            return flight.awaited().unwrap_or_else(ask);
        }
        let landing = Landing {
            flights: self,
            key,
            flight: &flight,
        };
        let answer = ask();
        *flight.state.lock().unwrap_or_else(PoisonError::into_inner) =
            State::Answered(answer.clone());
        drop(landing);
        answer
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::time::Duration;

    use super::*;

    #[test]
    fn those_who_wait_for_a_question_that_ended_without_an_answer_ask_for_themselves() {
        let flights: Arc<Flights<u32>> = Arc::new(Flights::new());
        let asked = Arc::new(AtomicUsize::new(0));
        // The first asks, and its thread ends in a panic before an answer.
        let first = {
            let (flights, asked) = (Arc::clone(&flights), Arc::clone(&asked));
            thread::spawn(move || {
                flights.share("session", || {
                    asked.fetch_add(1, Ordering::SeqCst);
                    thread::sleep(Duration::from_millis(300));
                    panic!("the question failed");
                })
            })
        };
        while asked.load(Ordering::SeqCst) == 0 {
            thread::sleep(Duration::from_millis(5));
        }
        // The second waits for it, is woken, and asks.
        let answer = flights.share("session", || {
            asked.fetch_add(1, Ordering::SeqCst);
            7
        });
        assert!(first.join().is_err());
        assert_eq!((answer, asked.load(Ordering::SeqCst)), (7, 2));
        // Nothing is under way any more: the next question is a new one.
        assert_eq!(flights.share("session", || 8), 8);
        assert!(flights.under_way.lock().unwrap().is_empty());
    }
}
