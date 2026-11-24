use super::*;

fn job(id: &str, status: JobStatus) -> Job {
    Job {
        id: id.into(),
        action_id: "run_monitor".into(),
        actor: "1".into(),
        actor_email: "1@example.test".into(),
        request_id: format!("request-{id}"),
        status,
        created_at: now(),
        started_at: None,
        finished_at: None,
        message: "Accepted for execution.".into(),
        may_still_run: false,
    }
}

#[test]
fn a_restart_marks_pending_jobs_uncertain() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("jobs.sqlite");
    let store = JobStore::open(&path).unwrap();
    store.insert(&job("a", JobStatus::Queued)).unwrap();
    store.insert(&job("b", JobStatus::Succeeded)).unwrap();
    drop(store);
    let store = JobStore::open(&path).unwrap();
    let pending = store.get("a").unwrap().unwrap();
    assert_eq!(pending.status, JobStatus::Uncertain);
    assert!(pending.may_still_run && pending.finished_at.is_some());
    assert_eq!(
        store.get("b").unwrap().unwrap().status,
        JobStatus::Succeeded
    );
    assert_eq!(store.active().unwrap().len(), 1);
}

#[test]
fn updates_change_only_the_given_fields() {
    let directory = tempfile::tempdir().unwrap();
    let store = JobStore::open(&directory.path().join("jobs.sqlite")).unwrap();
    store.insert(&job("a", JobStatus::Queued)).unwrap();
    let change = Change {
        status: Some(JobStatus::Running),
        started_at: Some(1_793_000_000),
        ..Change::default()
    };
    store.update("a", &change).unwrap();
    let updated = store.get("a").unwrap().unwrap();
    assert_eq!(
        (updated.status, updated.message.as_str()),
        (JobStatus::Running, "Accepted for execution.")
    );
    let view = updated.view();
    assert_eq!(
        view.started_at.as_deref(),
        Some("2026-10-26T07:33:20+00:00")
    );
    assert_eq!((view.status, view.finished_at), (JobStatus::Running, None));
    assert!(store.by_request("request-a").unwrap().is_some());
    assert_eq!(store.count().unwrap(), 1);
    assert!(store.latest_created(Some("other")).unwrap().is_none());
}

#[test]
fn a_view_is_sent_with_the_names_the_audit_stores() {
    let view = Job {
        created_at: 1_793_000_000,
        ..job("a", JobStatus::Queued)
    }
    .view();
    let sent = serde_json::to_value(&view).unwrap();
    assert_eq!(
        sent,
        serde_json::json!({
            "id": "a",
            "actionId": "run_monitor",
            "actor": "1",
            "actorEmail": "1@example.test",
            "requestId": "request-a",
            "status": "queued",
            "createdAt": "2026-10-26T07:33:20+00:00",
            "startedAt": null,
            "finishedAt": null,
            "message": "Accepted for execution.",
        })
    );
    assert_eq!(serde_json::from_value::<JobView>(sent).unwrap(), view);
    for status in JobStatus::ALL {
        assert_eq!(serde_json::to_value(status).unwrap(), status.as_str());
    }
}

#[test]
fn timestamps_are_seconds_since_the_epoch() {
    let real = time::now().as_second();
    assert!((now() - real).abs() < 5, "{} vs {real}", now());
}

#[test]
fn finished_jobs_expire_after_thirty_days() {
    let directory = tempfile::tempdir().unwrap();
    let store = JobStore::open(&directory.path().join("jobs.sqlite")).unwrap();
    let day = 86400;
    let aged = |id: &str, days: i64, status: JobStatus, may_still_run: bool| Job {
        created_at: now() - days * day,
        may_still_run,
        ..job(id, status)
    };
    // Recorded before jobs dated earlier, as after the clock went back.
    for record in [
        aged("old", 31, JobStatus::Succeeded, false),
        aged("recent", 29, JobStatus::Failed, false),
        aged("unsure", 31, JobStatus::Uncertain, true),
        aged("waiting", 31, JobStatus::Queued, false),
    ] {
        store.insert(&record).unwrap();
    }
    assert_eq!(store.count().unwrap(), 4);
    store.prune().unwrap();
    assert_eq!(store.count().unwrap(), 3);
    assert!(store.get("old").unwrap().is_none());
    for kept in ["recent", "unsure", "waiting"] {
        assert!(store.get(kept).unwrap().is_some(), "{kept}");
    }
}

/// Jobs recorded while the host's clock ran ahead, then one after it was
/// put right: the audit's own order says which came last, not their dates.
#[test]
fn after_the_clock_went_back_the_job_recorded_last_is_listed_first() {
    let directory = tempfile::tempdir().unwrap();
    let store = JobStore::open(&directory.path().join("jobs.sqlite")).unwrap();
    let day = 86400;
    for (id, created_at) in [
        ("before", now() - day),
        ("ahead-1", now() + 2 * day),
        ("ahead-2", now() + day),
        ("after", now()),
    ] {
        let record = Job {
            created_at,
            ..job(id, JobStatus::Succeeded)
        };
        store.insert(&record).unwrap();
    }
    let listed: Vec<String> = store
        .recent(3)
        .unwrap()
        .into_iter()
        .map(|job| job.id)
        .collect();
    assert_eq!(listed, ["after", "ahead-2", "ahead-1"]);
}

/// A job recorded while the clock ran behind, then the clock put right: its
/// own date is old, and the jobs recorded before it are not. Each record
/// leaves by its own date, so that no other record's date takes it out of
/// the audit.
#[test]
fn a_job_dated_behind_takes_no_other_job_out_of_the_audit() {
    let directory = tempfile::tempdir().unwrap();
    let store = JobStore::open(&directory.path().join("jobs.sqlite")).unwrap();
    let day = 86400;
    for (id, created_at) in [
        ("yesterday", now() - day),
        ("an-hour-ago", now() - 3600),
        ("behind", now() - 400 * day),
        ("after", now()),
    ] {
        let record = Job {
            created_at,
            ..job(id, JobStatus::Succeeded)
        };
        store.insert(&record).unwrap();
    }
    store.prune().unwrap();
    let left: Vec<String> = store
        .recent(10)
        .unwrap()
        .into_iter()
        .map(|job| job.id)
        .collect();
    assert_eq!(left, ["after", "an-hour-ago", "yesterday"]);
}

/// A job dated ahead of the clock, as one recorded while it ran ahead,
/// stays until thirty days after its own date, since when it ran is not
/// known: a job recorded after it with an old date does not take it out,
/// and one recorded later with a recent date keeps no job before it.
#[test]
fn a_job_dated_ahead_stays_by_its_own_date_alone() {
    let directory = tempfile::tempdir().unwrap();
    let store = JobStore::open(&directory.path().join("jobs.sqlite")).unwrap();
    let day = 86400;
    let aged = |id: &str, days: i64| Job {
        created_at: now() - days * day,
        ..job(id, JobStatus::Succeeded)
    };
    for record in [
        aged("old", 31),
        aged("ahead", -400),
        aged("later", 31),
        aged("recent", 1),
    ] {
        store.insert(&record).unwrap();
    }
    store.prune().unwrap();
    let left: Vec<String> = store
        .recent(10)
        .unwrap()
        .into_iter()
        .map(|job| job.id)
        .collect();
    assert_eq!(left, ["recent", "ahead"]);
}

/// A row whose number is the greatest integer, as a damaged or hand-edited
/// audit may hold, has SQLite number every later row at random. It costs
/// that row's place alone: the jobs recorded after it are listed in their
/// order, and the one recorded last is the newest that the settle time and
/// the cooldown wait for.
#[test]
fn a_row_of_the_greatest_integer_keeps_the_later_jobs_in_order() {
    let directory = tempfile::tempdir().unwrap();
    let store = JobStore::open(&directory.path().join("jobs.sqlite")).unwrap();
    let damaged = Job {
        created_at: now() - 3600,
        ..job("damaged", JobStatus::Succeeded)
    };
    store.insert(&damaged).unwrap();
    store
        .db
        .execute("UPDATE jobs SET rowid = ?1", [i64::MAX])
        .unwrap();
    let start = now() - 600;
    let ids: Vec<String> = (0..30).map(|index| format!("job-{index:02}")).collect();
    for (at, id) in (start..).zip(&ids) {
        let record = Job {
            created_at: at,
            ..job(id, JobStatus::Succeeded)
        };
        store.insert(&record).unwrap();
    }
    let listed: Vec<String> = store
        .recent(10)
        .unwrap()
        .into_iter()
        .map(|job| job.id)
        .collect();
    let newest: Vec<String> = ids.iter().rev().take(10).cloned().collect();
    assert_eq!(listed, newest);
    assert_eq!(store.latest_created(None).unwrap(), Some(start + 29));
}

#[test]
fn the_audit_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("jobs.sqlite");
    JobStore::open(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}
