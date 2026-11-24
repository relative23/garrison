use std::path::Path;

use garrison_core::hex;
use garrison_core::observations::{Observation, State};
use garrison_testing::http::{answer, serve};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::*;
use crate::context::Provider;
use crate::testing::{Canned, config, context, table};

pub(super) fn value_of<'a>(observation: &'a Observation, label: &str) -> &'a Value {
    &observation
        .fields
        .iter()
        .find(|field| field.label == label)
        .unwrap()
        .value
}

#[test]
fn systemd_states_and_idle_jobs() {
    let output = "Id=unbound.service\nLoadState=loaded\nActiveState=active\nSubState=running\nResult=success\n\n\
        Id=backup.service\nLoadState=loaded\nActiveState=inactive\nSubState=dead\nResult=success\n\n\
        Id=broken.service\nLoadState=loaded\nActiveState=failed\nSubState=failed\nResult=exit-code\n\n\
        Id=backup.timer\nLoadState=loaded\nActiveState=active\nSubState=waiting\nResult=success\n\
        TimersCalendar={ OnCalendar=*-*-* 03:00:00 ; next_elapse=... }\n\
        NextElapseUSecRealtime=Fri 2026-10-30 03:00:00 UTC\nLastTriggerUSec=Thu 2026-10-29 03:00:00 CET\n";
    let provider = Systemd::new(&table(
        r#"type = "systemd"
units = [
  { unit = "unbound.service", label = "DNS", modules = ["services"] },
  { unit = "backup.service", label = "Backup job", modules = ["backups"], expect = "idle" },
  { unit = "broken.service", label = "Broken", modules = ["services"] },
  { unit = "backup.timer", label = "Schedule", modules = ["backups"] },
  { unit = "missing.service", label = "Missing", modules = ["services"] },
]"#,
    ))
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    let runner = Canned(output.into());
    let report = provider.collect(&context(&config, &runner)).unwrap();
    let states: Vec<State> = report.observations.iter().map(|o| o.state).collect();
    assert_eq!(
        states,
        [
            State::Ok,
            State::Ok,
            State::Failed,
            State::Ok,
            State::Unknown
        ]
    );
    let timer = &report.observations[3];
    assert_eq!(
        value_of(timer, "Next run"),
        &json!("2026-10-30T03:00:00+00:00")
    );
    assert_eq!(value_of(timer, "Schedule"), &json!("*-*-* 03:00:00"));
    assert_eq!(
        value_of(timer, "Last trigger"),
        &Value::Null,
        "only UTC is unambiguous"
    );
    assert_eq!(
        value_of(&report.observations[4], "Active state"),
        &json!("unknown (unknown)")
    );
    assert_eq!(report.gauges["healthy_services"], 3.0);
}

#[test]
fn the_http_probe_reads_only_the_status_of_large_pages() {
    let body = "x".repeat(2 * 1024 * 1024);
    let server = serve(vec![answer(200, &body)]);
    let provider = Http::new(&table(&format!(
        "type = \"http\"\nid = \"big\"\ntitle = \"Big\"\nurl = \"{}/\"",
        server.url
    )))
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    let observation = provider
        .collect(&context(&config, &runner))
        .unwrap()
        .observations
        .remove(0);
    assert_eq!(observation.state, State::Ok);
    assert_eq!(observation.fields[0].value, json!(200));
}

#[test]
fn versions_come_from_the_first_group() {
    let provider = VersionCommand::new(&table(
        "type = \"version-command\"\ncomponent = \"ClamAV Scanner\"\ncommand = [\"/usr/bin/clamdscan\", \"--version\"]\npattern = \"^ClamAV (\\\\d+\\\\.\\\\d+\\\\.\\\\d+)\"",
    ))
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    let runner = Canned("ClamAV 1.4.3/27800/Wed Oct 29 2026\n".into());
    let observation = provider
        .collect(&context(&config, &runner))
        .unwrap()
        .observations
        .remove(0);
    assert_eq!(observation.id, "version.clamav-scanner");
    assert_eq!(observation.value["version"], json!("1.4.3"));
    let other = Canned("something else".into());
    let unknown = provider
        .collect(&context(&config, &other))
        .unwrap()
        .observations
        .remove(0);
    assert_eq!(unknown.state, State::Unknown);
    let error = VersionCommand::new(&table(
        "type = \"version-command\"\ncomponent = \"X\"\ncommand = [\"relative\"]",
    ));
    assert_eq!(
        error.unwrap_err().0,
        "providers[version-command].command must be an absolute command"
    );
}

#[test]
fn host_resources_come_from_proc_files() {
    let directory = tempfile::tempdir().unwrap();
    let proc = directory.path().join("proc");
    std::fs::create_dir(&proc).unwrap();
    std::fs::write(
        proc.join("meminfo"),
        "MemTotal: 1000 kB\nMemAvailable: 50 kB\nSwapTotal: 0 kB\n",
    )
    .unwrap();
    std::fs::write(proc.join("loadavg"), "0.52 0.58 0.59 1/100 1234\n").unwrap();
    std::fs::write(proc.join("uptime"), "12345.67 1000.00\n").unwrap();
    let provider = Host::new(&table(&format!(
        "type = \"host\"\nproc = \"{}\"\ndisk_path = \"{}\"",
        proc.display(),
        directory.path().display()
    )))
    .unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    let report = provider.collect(&context(&config, &runner)).unwrap();
    let observation = &report.observations[0];
    assert_eq!(observation.state, State::Warning);
    assert!(
        observation
            .findings
            .contains(&"Less than 10% of the memory is available.".to_owned())
    );
    assert_eq!(
        value_of(observation, "Load (1 / 5 / 15 min)"),
        &json!("0.52 / 0.58 / 0.59")
    );
    assert_eq!(value_of(observation, "Uptime"), &json!(12345));
    assert_eq!(value_of(observation, "Memory total"), &json!(1_024_000));
    assert_eq!(report.gauges["load_1m"], 0.52);
    // A file that cannot be read costs only its own values, and says so.
    std::fs::remove_file(proc.join("uptime")).unwrap();
    let without = provider
        .collect(&context(&config, &runner))
        .unwrap()
        .observations
        .remove(0);
    assert_eq!(without.state, State::Warning);
    assert_eq!(
        without.findings[0],
        "uptime could not be read: No such file or directory (os error 2)."
    );
    assert_eq!(value_of(&without, "Uptime"), &Value::Null);
    assert_eq!(
        value_of(&without, "Load (1 / 5 / 15 min)"),
        &json!("0.52 / 0.58 / 0.59")
    );
}

/// The webmail plugins card for the plugins `named` in a Bulwark folder at
/// `directory`.
fn plugins_card(directory: &Path, named: &str) -> Observation {
    let raw = format!(
        "admin_directory = \"{}\"\nplugins = [{named}]",
        directory.display()
    );
    let provider = Bulwark::new(&table(&raw)).unwrap();
    let (config, runner) = (config(directory), Canned(String::new()));
    provider
        .collect(&context(&config, &runner))
        .unwrap()
        .observations
        .remove(0)
}

/// A Bulwark folder whose registry lists `rows`, with the bundles `files`.
fn webmail(rows: &Value, files: &[(&str, &[u8])]) -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    let plugins = directory.path().join("plugins");
    std::fs::create_dir_all(&plugins).unwrap();
    for (name, content) in files {
        std::fs::write(plugins.join(name), content).unwrap();
    }
    let registry = json!({ "plugins": rows });
    std::fs::write(plugins.join("registry.json"), registry.to_string()).unwrap();
    directory
}

/// A bundle and the registry's row that records its hash.
fn recorded(id: &str, code: &[u8]) -> Value {
    let hash = hex::encode(&Sha256::digest(code));
    json!({"id": id, "version": "1.0.0", "enabled": true, "bundleHash": hash})
}

/// A registry's rows, the bundles beside it, and why the integrity of the
/// one bundle named is not known.
type Unchecked<'a> = (Value, Vec<(&'a str, &'a [u8])>, &'a str);

/// Where a bundle's integrity cannot be checked, the card names the plugin
/// and why: Partial beside a bundle that was verified, Unknown where none
/// could be, and a mismatch first where one is found, as the notifications
/// carry the first finding.
#[test]
fn a_bundle_whose_integrity_is_not_known_is_named_and_not_in_order() {
    let code = b"bundle".as_slice();
    let folder = webmail(&json!([recorded("spam", code)]), &[("spam.js", code)]);
    let beside = plugins_card(folder.path(), "\"spam\", \"absent\"");
    assert_eq!(
        (beside.state, beside.findings.as_slice()),
        (
            State::Partial,
            &[
                "The integrity of the absent bundle is not known: plugins/registry.json does not \
               list it."
                    .to_owned()
            ][..]
        )
    );
    let large = vec![b'x'; 2 * 1024 * 1024 + 1];
    let cases: [Unchecked<'_>; 4] = [
        (
            json!([recorded("spam", code), recorded("spam", code)]),
            vec![("spam.js", code)],
            "plugins/registry.json lists it 2 times",
        ),
        (
            json!([{"id": "spam", "bundleHash": "not-a-hash"}]),
            vec![("spam.js", code)],
            "plugins/registry.json records no SHA-256 of it",
        ),
        (
            json!([recorded("spam", code)]),
            vec![],
            "plugins/spam.js is not there, though plugins/registry.json lists it; Bulwark writes \
             it when it installs the plugin",
        ),
        (
            json!([recorded("spam", &large)]),
            vec![("spam.js", large.as_slice())],
            "plugins/spam.js is larger than 2 MiB",
        ),
    ];
    for (rows, files, why) in cases {
        let folder = webmail(&rows, &files);
        let alone = plugins_card(folder.path(), "\"spam\"");
        assert_eq!(
            (alone.state, alone.findings.as_slice()),
            (
                State::Unknown,
                &[format!(
                    "The integrity of the spam bundle is not known: {why}."
                )][..]
            ),
            "{why}"
        );
    }
    // A bundle in place of a link is not followed; one this user may not
    // read is named so, where its mode keeps the user out.
    let folder = webmail(&json!([recorded("spam", code)]), &[("real.js", code)]);
    let plugins = folder.path().join("plugins");
    std::os::unix::fs::symlink(plugins.join("real.js"), plugins.join("spam.js")).unwrap();
    assert_eq!(
        plugins_card(folder.path(), "\"spam\"").findings,
        [
            "The integrity of the spam bundle is not known: plugins/spam.js is a link, which is \
          not followed."
        ]
    );
    let folder = webmail(&json!([recorded("spam", code)]), &[("spam.js", code)]);
    let bundle = folder.path().join("plugins/spam.js");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bundle, std::fs::Permissions::from_mode(0o000)).unwrap();
    }
    if std::fs::read(&bundle).is_err() {
        assert_eq!(
            plugins_card(folder.path(), "\"spam\"").findings,
            [
                "The integrity of the spam bundle is not known: the collector may not read \
              plugins/spam.js."
            ]
        );
    }
    // A mismatch comes first.
    let folder = webmail(&json!([recorded("spam", code)]), &[("spam.js", b"changed")]);
    let both = plugins_card(folder.path(), "\"absent\", \"spam\"");
    assert_eq!(both.state, State::Failed);
    assert_eq!(
        both.findings,
        [
            "The spam bundle does not match its recorded hash.",
            "The integrity of the absent bundle is not known: plugins/registry.json does not \
             list it."
        ]
    );
}

/// A registry that cannot be read leaves every bundle unknown, and says why:
/// one that is not there names the option that names the folder, which
/// `admin_directory` may name wrongly, and the folder it names.
#[test]
fn a_plugin_registry_that_cannot_be_read_says_why() {
    let missing = tempfile::tempdir().unwrap();
    let card = plugins_card(missing.path(), "\"spam\"");
    assert_eq!(
        (card.state, card.findings),
        (
            State::Unknown,
            vec![format!(
                "No bundle's integrity is known: there is no plugins/registry.json in {}; set \
                 `admin_directory` to Bulwark's administration folder, which holds it.",
                missing.path().display()
            )]
        )
    );
    for (text, why) in [
        ("{\"plugins\": ", "plugins/registry.json is no valid JSON"),
        (
            "{\"plugins\": 3}",
            "plugins/registry.json holds no list of plugins",
        ),
    ] {
        let folder = webmail(&json!([]), &[]);
        std::fs::write(folder.path().join("plugins/registry.json"), text).unwrap();
        assert_eq!(
            plugins_card(folder.path(), "\"spam\"").findings,
            [format!("No bundle's integrity is known: {why}.")],
            "{text}"
        );
    }
}

/// A command's exit code and output, or the error of running it.
type Given = Result<(Option<i32>, String), fn() -> std::io::Error>;

/// Answers every command with an output or an error, as given.
struct Gives(Given);

impl crate::command::Runner for Gives {
    fn run(&self, _: &[&str]) -> std::io::Result<crate::command::Output> {
        match &self.0 {
            Ok((code, stdout)) => Ok(crate::command::Output {
                code: *code,
                stdout: stdout.clone(),
            }),
            Err(error) => Err(error()),
        }
    }
}

/// A version command that gives no version says why: it could not be run,
/// gave no answer in the collector's time for a command, ended with a
/// status or by a signal, wrote nothing to the output that is read, or
/// nothing that `pattern` finds there, within the part that is read.
#[test]
fn a_version_command_without_a_version_says_why() {
    let provider = VersionCommand::new(&table(
        "component = \"C\"\ncommand = [\"/usr/bin/c\", \"--version\"]",
    ))
    .unwrap();
    let output = |code: Option<i32>, text: &str| Gives(Ok((code, text.to_owned())));
    let cases = [
        (
            Gives(Err(|| std::io::Error::from_raw_os_error(2))),
            "/usr/bin/c could not be run: No such file or directory (os error 2).",
        ),
        (
            Gives(Err(|| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "command timed out")
            })),
            "/usr/bin/c did not answer within 8 seconds.",
        ),
        (
            output(Some(2), "c 1.2.3\n"),
            "/usr/bin/c exited with status 2.",
        ),
        (output(None, ""), "/usr/bin/c was ended by a signal."),
        (
            output(Some(0), ""),
            "/usr/bin/c wrote nothing to its standard output, the only output that is read.",
        ),
        (
            output(Some(0), "c, a build of today\n"),
            "The output of /usr/bin/c holds nothing that `pattern` finds.",
        ),
        (
            output(Some(0), &format!("{}c 1.2.3\n", "x".repeat(4096))),
            "The first 4096 characters of the output of /usr/bin/c hold nothing that \
             `pattern` finds.",
        ),
    ];
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    for (runner, said) in cases {
        let card = provider
            .collect(&context(&config, &runner))
            .unwrap()
            .observations
            .remove(0);
        assert_eq!(
            (card.state, card.findings),
            (State::Unknown, vec![said.to_owned()])
        );
    }
}

/// The webmail card and a version command whose file system gives no
/// answer by the check's time, as a folder or a program on a hard NFS mount
/// whose server is gone, say so: here the time is past before they begin.
#[test]
fn a_file_system_that_does_not_answer_is_named_by_the_card_that_reads_it() {
    let code = b"bundle".as_slice();
    let folder = webmail(&json!([recorded("spam", code)]), &[("spam.js", code)]);
    let raw = format!(
        "admin_directory = \"{}\"\nplugins = [\"spam\"]",
        folder.path().display()
    );
    let (config, runner) = (config(folder.path()), Canned(String::new()));
    let card = Bulwark::new(&table(&raw))
        .unwrap()
        .card(&context(&config, &runner), std::time::Instant::now())
        .unwrap()
        .observations
        .remove(0);
    assert_eq!(
        (card.state, card.findings),
        (
            State::Unknown,
            vec![
                "No bundle's integrity is known: the file system of plugins/registry.json did \
                 not answer within 8 seconds."
                    .to_owned()
            ]
        )
    );
    let version = VersionCommand::new(&table(
        "component = \"C\"\ncommand = [\"/usr/bin/c\", \"--version\"]",
    ))
    .unwrap();
    assert_eq!(
        version.version(&context(&config, &runner), std::time::Instant::now()),
        Err("/usr/bin/c was not run: its file system did not answer within 8 seconds.".to_owned())
    );
}
