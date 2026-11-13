//! What a backup tool says of its repository, as the report holds it that
//! `garrison backup-check` writes and the `backup-check` provider reads.
//!
//! The backup's password opens every message on the server, so it stays with
//! root: the operator's own backup job calls the command, which asks restic
//! or borg and writes down what they answer. The collector reads that report
//! and never the repository.

use garrison_core::time;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The tools the command asks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Tool {
    Restic,
    Borg,
}

impl Tool {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Tool::Restic => "restic",
            Tool::Borg => "borg",
        }
    }

    #[must_use]
    pub fn named(name: &str) -> Option<Tool> {
        [Tool::Restic, Tool::Borg]
            .into_iter()
            .find(|tool| tool.name() == name)
    }
}

/// The snapshots (restic) or archives (borg) of a repository.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshots {
    /// When they were listed.
    pub at: String,
    pub count: u64,
    /// When the newest was made; `None` for an empty repository.
    pub newest: Option<String>,
    /// The stored size of the repository, after deduplication.
    pub size_bytes: Option<u64>,
}

/// An integrity check of the repository, or a test restore from it.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Run {
    pub at: String,
    pub ok: bool,
    /// The tool's last line, shortened; what was restored, for a restore.
    pub detail: String,
}

/// The report of one repository. A part that was not run this time keeps
/// what the run before wrote.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub tool: Tool,
    /// The repository as the tool was given it, without a password in it.
    pub repository: String,
    pub snapshots: Option<Snapshots>,
    /// Why the snapshots could not be listed, where they could not.
    pub problem: Option<String>,
    pub verify: Option<Run>,
    pub restore: Option<Run>,
}

/// A repository's name without what may sign in to it: of
/// `rest:https://user:secret@host/path` the `user:secret@` goes.
#[must_use]
pub fn named(repository: &str) -> String {
    match repository.split_once("://") {
        Some((scheme, rest)) => {
            let (host, path) = rest
                .split_once('/')
                .map_or((rest, ""), |(host, path)| (host, path));
            let host = host.rsplit_once('@').map_or(host, |(_, host)| host);
            let slash = if rest.contains('/') { "/" } else { "" };
            format!("{scheme}://{host}{slash}{path}")
        }
        None => repository.to_owned(),
    }
}

/// `restic snapshots --json`: how many there are and when the newest was made.
pub fn restic_snapshots(output: &str) -> Result<(u64, Option<String>), String> {
    let listed: Vec<Value> = serde_json::from_str(output)
        .map_err(|_| "restic's list of snapshots is not as expected")?;
    let newest = listed
        .iter()
        .filter_map(|snapshot| time::parse(snapshot["time"].as_str()?))
        .max()
        // Whole seconds: a report is read by people.
        .and_then(|made| time::Timestamp::from_second(made.as_second()).ok())
        .map(time::isoformat);
    Ok((listed.len() as u64, newest))
}

/// `restic stats --json --mode raw-data`: the stored size.
#[must_use]
pub fn restic_size(output: &str) -> Option<u64> {
    serde_json::from_str::<Value>(output).ok()?["total_size"].as_u64()
}

/// `borg list --json`, run with `TZ=UTC`: borg writes its times without an
/// offset, in the time zone it runs in.
pub fn borg_archives(output: &str) -> Result<(u64, Option<String>, Option<String>), String> {
    let listed: Value =
        serde_json::from_str(output).map_err(|_| "borg's list of archives is not as expected")?;
    let archives = listed["archives"]
        .as_array()
        .ok_or("borg's list of archives is not as expected")?;
    let newest = archives
        .iter()
        .filter_map(|archive| {
            let made = time::parse(&format!("{}Z", archive["time"].as_str()?))?;
            Some((made, archive["name"].as_str()?.to_owned()))
        })
        .max_by_key(|(made, _)| *made);
    Ok(match newest {
        Some((made, name)) => (
            archives.len() as u64,
            Some(time::isoformat(made)),
            Some(name),
        ),
        None => (archives.len() as u64, None, None),
    })
}

/// `borg info --json`: the stored size, deduplicated and compressed.
#[must_use]
pub fn borg_size(output: &str) -> Option<u64> {
    serde_json::from_str::<Value>(output).ok()?["cache"]["stats"]["unique_csize"].as_u64()
}

#[cfg(test)]
mod tests {
    use super::*;

    // As restic 0.18.0 and borg 1.4.0 print them.
    const RESTIC: &str = r#"[{"time":"2026-11-11T19:16:37.839457992Z","tree":"9fcf","paths":["/data"],"hostname":"host","username":"root","program_version":"restic 0.18.0","summary":{"backup_start":"2026-11-11T19:16:37.839457992Z","total_files_processed":2,"total_bytes_processed":300006},"id":"c92ca1ccd6fd","short_id":"c92ca1cc"},{"time":"2026-11-11T19:16:38.601910362Z","parent":"c92ca1ccd6fd","paths":["/data"],"hostname":"host","id":"0039082a75f5","short_id":"0039082a"}]"#;
    const RESTIC_STATS: &str = r#"{"total_size":301876,"total_uncompressed_size":303491,"compression_ratio":1.0053,"total_blob_count":9,"snapshots_count":2}"#;
    const BORG: &str = r#"{"archives": [{"archive": "first", "barchive": "first", "id": "9435", "name": "first", "start": "2026-11-11T19:16:21.000000", "time": "2026-11-11T19:16:21.000000"}, {"archive": "second", "barchive": "second", "id": "0843", "name": "second", "start": "2026-11-11T19:16:22.000000", "time": "2026-11-11T19:16:22.000000"}], "encryption": {"mode": "repokey"}, "repository": {"id": "477c", "location": "/srv/borg"}}"#;
    const BORG_INFO: &str = r#"{"cache": {"path": "/root/.cache/borg/477c", "stats": {"total_chunks": 10, "total_csize": 600280, "total_size": 600022, "total_unique_chunks": 6, "unique_csize": 301541, "unique_size": 301652}}, "encryption": {"mode": "repokey"}}"#;

    #[test]
    fn restic_names_its_snapshots_and_its_size() {
        assert_eq!(
            restic_snapshots(RESTIC),
            Ok((2, Some("2026-11-11T19:16:38+00:00".to_owned())))
        );
        assert_eq!(restic_snapshots("[]"), Ok((0, None)));
        assert_eq!(
            restic_snapshots(r#"{"message_type":"exit_error","code":12}"#).unwrap_err(),
            "restic's list of snapshots is not as expected"
        );
        assert_eq!(restic_size(RESTIC_STATS), Some(301_876));
        assert_eq!(restic_size("Fatal: wrong password"), None);
    }

    #[test]
    fn borg_names_its_archives_in_utc_and_its_size() {
        assert_eq!(
            borg_archives(BORG),
            Ok((
                2,
                Some("2026-11-11T19:16:22+00:00".to_owned()),
                Some("second".to_owned())
            ))
        );
        assert_eq!(borg_archives(r#"{"archives": []}"#), Ok((0, None, None)));
        assert!(borg_archives("[]").is_err());
        assert_eq!(borg_size(BORG_INFO), Some(301_541));
    }

    #[test]
    fn a_repository_is_named_without_what_signs_in_to_it() {
        assert_eq!(named("/srv/restic"), "/srv/restic");
        assert_eq!(
            named("rest:https://backup:s3cret@host.example:8000/mail"),
            "rest:https://host.example:8000/mail"
        );
        assert_eq!(
            named("sftp:backup@host.example:/srv/restic"),
            "sftp:backup@host.example:/srv/restic"
        );
        assert_eq!(
            named("ssh://backup@host.example/srv/borg"),
            "ssh://host.example/srv/borg"
        );
        assert_eq!(
            named("s3:https://s3.example.org/bucket"),
            "s3:https://s3.example.org/bucket"
        );
    }

    #[test]
    fn a_report_reads_back_as_it_was_written() {
        let report = Report {
            tool: Tool::Restic,
            repository: "/srv/restic".to_owned(),
            snapshots: Some(Snapshots {
                at: "2026-11-11T19:20:00+00:00".to_owned(),
                count: 2,
                newest: Some("2026-11-11T19:16:38+00:00".to_owned()),
                size_bytes: Some(301_876),
            }),
            problem: None,
            verify: Some(Run {
                at: "2026-11-10T03:00:00+00:00".to_owned(),
                ok: true,
                detail: "no errors were found".to_owned(),
            }),
            restore: None,
        };
        let text = serde_json::to_string(&report).unwrap();
        assert!(
            text.contains(r#""tool":"restic""#) && text.contains(r#""sizeBytes":301876"#),
            "{text}"
        );
        assert_eq!(serde_json::from_str::<Report>(&text).unwrap(), report);
        assert_eq!(Tool::named("borg"), Some(Tool::Borg));
        assert_eq!(Tool::named("tar"), None);
    }
}
