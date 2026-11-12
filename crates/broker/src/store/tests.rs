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

#[test]
fn the_audit_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("jobs.sqlite");
    JobStore::open(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}
