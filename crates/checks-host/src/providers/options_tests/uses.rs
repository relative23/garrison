//! The uses of every option of every check of the crate: two
//! configurations each, which differ by the option alone.

use std::fs;
use std::path::Path;

use super::{Use, file, uses};

/// The uses of the options of host and host care.
pub(super) fn host_uses(at: &dyn Fn(&str) -> String) -> Vec<Use> {
    for (proc, total) in [("proc-a", 1000), ("proc-b", 2000)] {
        file(
            Path::new(&at(&format!("{proc}/meminfo"))),
            &format!("MemTotal: {total} kB\nMemAvailable: 500 kB\n"),
        );
        file(
            Path::new(&at(&format!("{proc}/loadavg"))),
            "0.10 0.20 0.30 1/100 1234\n",
        );
        file(Path::new(&at(&format!("{proc}/uptime"))), "3600.0 100.0\n");
    }
    file(
        Path::new(&at("other/proc/sys/kernel/osrelease")),
        "6.12.107+deb13-amd64\n",
    );
    fs::create_dir_all(at("root")).unwrap();
    let host = format!(
        "proc = \"{}\"\ndisk_path = \"{}\"",
        at("proc-a"),
        at("root")
    );
    let care = format!("root = \"{}\"\ndisk_path = \"{}\"", at("root"), at("root"));
    let mut all = uses(
        "host.rs",
        "host",
        &host,
        &[
            (
                "proc",
                format!(
                    "proc = \"{}\"\ndisk_path = \"{}\"",
                    at("proc-b"),
                    at("root")
                ),
            ),
            (
                "disk_path",
                format!("proc = \"{}\"\ndisk_path = \"/proc\"", at("proc-a")),
            ),
            ("modules", format!("{host}\nmodules = [\"dashboard\"]")),
        ],
    );
    all.extend(uses(
        "hostcare.rs",
        "host-care",
        &care,
        &[
            (
                "root",
                format!("root = \"{}\"\ndisk_path = \"{}\"", at("other"), at("root")),
            ),
            (
                "disk_path",
                format!("root = \"{}\"\ndisk_path = \"/proc\"", at("root")),
            ),
            ("modules", format!("{care}\nmodules = [\"dashboard\"]")),
            (
                "checks",
                format!("{care}\nchecks = [\"updates\", \"disk\"]"),
            ),
            (
                "firewall_units",
                format!("{care}\nfirewall_units = [\"edge.service\"]"),
            ),
        ],
    ));
    all
}

/// The uses of the options of systemd and of its units.
pub(super) fn systemd_uses() -> Vec<Use> {
    let unit = |more: &str| {
        format!(
            "units = [{{ unit = \"a.service\", label = \"A\", modules = [\"services\"]{more} }}]"
        )
    };
    let idle = unit(", expect = \"idle\"");
    uses(
        "systemd.rs",
        "systemd",
        &unit(""),
        &[
            (
                "units",
                "units = [{ unit = \"a.service\", label = \"A\", modules = [\"services\"] }, \
             { unit = \"b.service\", label = \"B\", modules = [\"services\"] }]"
                    .to_owned(),
            ),
            (
                "unit",
                "units = [{ unit = \"b.service\", label = \"A\", modules = [\"services\"] }]"
                    .to_owned(),
            ),
            (
                "label",
                "units = [{ unit = \"a.service\", label = \"B\", modules = [\"services\"] }]"
                    .to_owned(),
            ),
            (
                "modules",
                "units = [{ unit = \"a.service\", label = \"A\", modules = [\"backups\"] }]"
                    .to_owned(),
            ),
            ("expect", idle.clone()),
        ],
    )
    .into_iter()
    .chain(uses(
        "systemd.rs",
        "systemd",
        &idle,
        &[(
            "max_age_hours",
            unit(", expect = \"idle\", max_age_hours = 24"),
        )],
    ))
    .collect()
}

/// The uses of the options of a receipt and of its entries.
pub(super) fn receipt_uses(at: &dyn Fn(&str) -> String) -> Vec<Use> {
    let object = r#"{"date": "2026-10-29T10:00:00Z", "finished": "2026-10-28T10:00:00Z",
        "result": "passed", "n": 3, "results": [{"ok": true}]}"#;
    file(Path::new(&at("a.json")), object);
    file(Path::new(&at("b.json")), object);
    let list = r#"[{"ok": true, "at": "2026-10-29T09:00:00Z", "other": "2026-10-29T08:00:00Z"}]"#;
    file(Path::new(&at("list.json")), list);
    let named = |path: &str, more: &str| {
        format!(
            "id = \"r\"\ntitle = \"R\"\npath = \"{}\"\nmodules = [\"backups\"]\n{more}",
            at(path)
        )
    };
    let base = named("a.json", "");
    let rows = named("a.json", "rows = [\"results\"]");
    let field = |entry: &str| named("a.json", &format!("fields = [{entry}]"));
    let listed = named("list.json", "rows = []\nrow_date = \"at\"");
    let mut all = uses(
        "receipt.rs",
        "receipt",
        &base,
        &[
            ("id", base.replace("id = \"r\"", "id = \"s\"")),
            ("title", base.replace("title = \"R\"", "title = \"S\"")),
            ("path", named("b.json", "")),
            ("modules", base.replace("[\"backups\"]", "[\"services\"]")),
            ("date", named("a.json", "date = \"finished\"")),
            ("max_age_hours", named("a.json", "max_age_hours = 1")),
            ("fields", field("{ key = \"n\", label = \"N\" }")),
            (
                "ok_when",
                named(
                    "a.json",
                    "ok_when = { key = \"result\", equals = [\"failed\"] }",
                ),
            ),
            ("rows", rows.clone()),
            ("scope", named("a.json", "scope = \"Another scope.\"")),
        ],
    );
    all.extend(uses(
        "receipt.rs",
        "receipt",
        &rows,
        &[
            (
                "columns",
                format!("{rows}\ncolumns = [{{ key = \"ok\", label = \"OK\" }}]"),
            ),
            (
                "ok_rows",
                format!("{rows}\nok_rows = {{ key = \"ok\", equals = [false] }}"),
            ),
        ],
    ));
    all.extend(uses(
        "receipt.rs",
        "receipt",
        &listed,
        &[(
            "row_date",
            named("list.json", "rows = []\nrow_date = \"other\""),
        )],
    ));
    all.extend(uses(
        "receipt/keys.rs",
        "receipt",
        &field("{ key = \"n\", label = \"N\" }"),
        &[
            ("key", field("{ key = \"result\", label = \"N\" }")),
            ("label", field("{ key = \"n\", label = \"M\" }")),
            (
                "format",
                field("{ key = \"n\", label = \"N\", format = \"number\" }"),
            ),
        ],
    ));
    all
}

/// The uses of the options of the backup report, a version command, an
/// endpoint and the webmail plugins.
pub(super) fn other_uses(at: &dyn Fn(&str) -> String, url: &str) -> Vec<Use> {
    let report = r#"{"tool": "restic", "repository": "/srv/restic",
        "snapshots": {"at": "2026-10-29T11:50:00+00:00", "count": 2,
            "newest": "2026-10-29T10:00:00+00:00", "sizeBytes": 1000},
        "problem": null,
        "verify": {"at": "2026-10-26T03:00:00+00:00", "ok": true, "detail": "no errors"},
        "restore": {"at": "2026-10-26T03:00:00+00:00", "ok": true, "detail": "3 files"}}"#;
    file(Path::new(&at("restic.json")), report);
    file(Path::new(&at("restic-b.json")), report);
    let backup = format!("path = \"{}\"", at("restic.json"));
    let version = "component = \"C\"\ncommand = [\"/usr/bin/c\", \"--version\"]".to_owned();
    let endpoint = format!("id = \"x\"\ntitle = \"X\"\nurl = \"{url}/\"");
    file(Path::new(&at("bulwark/plugins/spam.js")), "bundle");
    let hash = garrison_core::hex::encode(&<sha2::Sha256 as sha2::Digest>::digest(b"bundle"));
    file(
        Path::new(&at("bulwark/plugins/registry.json")),
        &format!(r#"{{"plugins": [{{"id": "spam", "bundleHash": "{hash}"}}, {{"id": "other"}}]}}"#),
    );
    fs::create_dir_all(at("bulwark-b/plugins")).unwrap();
    fs::copy(
        at("bulwark/plugins/registry.json"),
        at("bulwark-b/plugins/registry.json"),
    )
    .unwrap();
    fs::copy(
        at("bulwark/plugins/spam.js"),
        at("bulwark-b/plugins/spam.js"),
    )
    .unwrap();
    let plugins = format!(
        "admin_directory = \"{}\"\nplugins = [\"spam\"]",
        at("bulwark")
    );
    let mut all = uses(
        "backupcheck.rs",
        "backup-check",
        &backup,
        &[
            ("tool", format!("{backup}\ntool = \"borg\"")),
            ("path", format!("path = \"{}\"", at("restic-b.json"))),
            ("modules", format!("{backup}\nmodules = [\"services\"]")),
            ("max_age_hours", format!("{backup}\nmax_age_hours = 1")),
            ("verify_days", format!("{backup}\nverify_days = 1")),
            ("restore_days", format!("{backup}\nrestore_days = 1")),
        ],
    );
    all.extend(uses(
        "version.rs",
        "version-command",
        &version,
        &[
            ("component", version.replace("\"C\"", "\"D\"")),
            ("command", version.replace("/usr/bin/c", "/usr/bin/d")),
            (
                "pattern",
                format!("{version}\npattern = \"with (\\\\d+\\\\.\\\\d+\\\\.\\\\d+)\""),
            ),
            ("modules", format!("{version}\nmodules = [\"dashboard\"]")),
        ],
    ));
    all.extend(uses(
        "web.rs",
        "http",
        &endpoint,
        &[
            ("id", endpoint.replace("id = \"x\"", "id = \"y\"")),
            ("title", endpoint.replace("title = \"X\"", "title = \"Y\"")),
            (
                "url",
                endpoint.replace(&format!("{url}/"), &format!("{url}/other")),
            ),
            ("expect_status", format!("{endpoint}\nexpect_status = 204")),
            ("modules", format!("{endpoint}\nmodules = [\"dashboard\"]")),
        ],
    ));
    all.extend(uses(
        "web.rs",
        "bulwark",
        &plugins,
        &[
            (
                "admin_directory",
                format!(
                    "admin_directory = \"{}\"\nplugins = [\"spam\"]",
                    at("bulwark-b")
                ),
            ),
            ("plugins", plugins.replace("[\"spam\"]", "[\"other\"]")),
        ],
    ));
    all
}
