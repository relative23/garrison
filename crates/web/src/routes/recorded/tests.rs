use super::*;

/// The coverage of a receiver that runs, with its last batch at `at`.
fn last_batch(at: Option<i64>) -> answers::Coverage {
    answers::Coverage {
        available: true,
        receiver: answers::Receiver::Running,
        heartbeat_at: Some(1_800_000_000),
        recording_since: Some(1_799_000_000),
        last_batch_at: at,
        failing_since: None,
        retention_days: Some(30),
        event_count: 1,
        trimmed: None,
        gap_count: 0,
        gaps: Vec::new(),
        limitations: Vec::new(),
    }
}

#[test]
fn the_last_batch_has_an_age_only_where_it_came_at_a_time_a_clock_gives_and_not_ahead() {
    let now = 1_800_000_000;
    let age_at = |at| coverage(last_batch(at), now).last_batch_age;
    assert_eq!(age_at(Some(now - 300)), Some(300));
    assert_eq!(age_at(Some(now)), Some(0));
    assert_eq!(age_at(None), None);
    // Dated ahead of the clock: it came before the clock went back.
    assert_eq!(age_at(Some(now + 1)), None);
    // No time a clock gives, as only a damaged history holds.
    assert_eq!(age_at(Some(i64::MIN)), None);
    assert_eq!(age_at(Some(i64::MAX)), None);
    // The edges of the times a clock gives are times.
    assert_eq!(age_at(Some(-377_705_023_201)), Some(now + 377_705_023_201));
    assert_eq!(age_at(Some(-377_705_023_202)), None);
    // The time itself is passed on as it was stored.
    assert_eq!(
        coverage(last_batch(Some(i64::MIN)), now).last_batch_at,
        Some(i64::MIN)
    );
}
