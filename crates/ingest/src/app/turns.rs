//! Whose turn it is to send a batch.
//!
//! A batch is read into memory whole and parsed there, so the batches that
//! arrive at one time decide what the service needs: without a bound, a
//! handful of large ones together pass the unit's memory limit, and the
//! kernel ends the receiver with whatever it had not stored. So only a few
//! are read at a time, the others wait before any of their body is read,
//! and none waits or arrives for longer than a batch has.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, timeout_at};

/// A turn; the next batch gets it when this is dropped.
pub(super) type Turn = OwnedSemaphorePermit;

/// Why a batch got no turn or lost it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Late {
    /// The batches before it took all the time it had.
    Busy,
    /// It got its turn and did not arrive whole in time.
    Slow,
}

#[derive(Clone, Debug)]
pub(super) struct Turns {
    free: Arc<Semaphore>,
    within: Duration,
}

impl Turns {
    /// `at_a_time` batches arrive together; each has `within` to get its
    /// turn and to arrive.
    pub(super) fn new(at_a_time: usize, within: Duration) -> Self {
        Turns {
            free: Arc::new(Semaphore::new(at_a_time)),
            within,
        }
    }

    /// Waits for a turn and then for `arriving`, which is not begun before.
    /// The turn is the caller's until it drops it.
    pub(super) async fn take<T>(
        &self,
        arriving: impl Future<Output = T>,
    ) -> Result<(Turn, T), Late> {
        let deadline = Instant::now() + self.within;
        // The semaphore is never closed, so an error is the time that ran out.
        let Ok(Ok(turn)) = timeout_at(deadline, Arc::clone(&self.free).acquire_owned()).await
        else {
            return Err(Late::Busy);
        };
        match timeout_at(deadline, arriving).await {
            Ok(arrived) => Ok((turn, arrived)),
            Err(_) => Err(Late::Slow),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    const WITHIN: Duration = Duration::from_secs(10);

    /// A batch whose body never ends; counts itself once it is being read.
    async fn stalled(begun: Arc<AtomicUsize>) {
        begun.fetch_add(1, Ordering::SeqCst);
        std::future::pending::<()>().await;
    }

    #[tokio::test(start_paused = true)]
    async fn no_more_than_the_given_number_arrive_at_a_time() {
        let turns = Turns::new(2, WITHIN);
        let begun = Arc::new(AtomicUsize::new(0));
        let waiting: Vec<_> = (0..5)
            .map(|_| {
                let (turns, begun) = (turns.clone(), Arc::clone(&begun));
                tokio::spawn(async move { turns.take(stalled(begun)).await.map(|_| ()) })
            })
            .collect();
        tokio::time::sleep(WITHIN / 2).await;
        // Two are being read; of the other three nothing was read yet.
        assert_eq!(begun.load(Ordering::SeqCst), 2);
        // None of them stays for longer than a batch has.
        tokio::time::sleep(WITHIN).await;
        for task in waiting {
            assert!(task.is_finished());
            assert!(task.await.unwrap().is_err());
        }
        // And the turns are free again.
        let (_turn, value) = turns.take(async { 7 }).await.unwrap();
        assert_eq!(value, 7);
    }

    #[tokio::test(start_paused = true)]
    async fn a_batch_keeps_its_turn_until_it_gives_it_back() {
        let turns = Turns::new(1, WITHIN);
        let (first, ()) = turns.take(async {}).await.unwrap();
        let begun = Arc::new(AtomicUsize::new(0));
        let next = {
            let (turns, begun) = (turns.clone(), Arc::clone(&begun));
            tokio::spawn(async move {
                turns
                    .take(async move { begun.fetch_add(1, Ordering::SeqCst) })
                    .await
                    .map(|_| ())
            })
        };
        // The first is being stored: the next waits, and nothing of it is read.
        tokio::time::sleep(WITHIN / 2).await;
        assert_eq!(begun.load(Ordering::SeqCst), 0);
        drop(first);
        assert_eq!(next.await.unwrap(), Ok(()));
        assert_eq!(begun.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_batch_says_whether_it_waited_or_arrived_too_long() {
        let turns = Turns::new(1, WITHIN);
        let (held, ()) = turns.take(async {}).await.unwrap();
        assert_eq!(turns.take(async {}).await.map(|_| ()), Err(Late::Busy));
        drop(held);
        let slow = turns.take(std::future::pending::<()>()).await;
        assert_eq!(slow.map(|_| ()), Err(Late::Slow));
    }
}
