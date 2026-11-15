//! Host care's restart check: whether installed updates need a restart of
//! the host.

use std::fs;

use garrison_core::observations::{Field, State};

use super::{HostCare, Made, reading};
use crate::context::Context;

impl HostCare {
    /// The distribution's own marker, or a kernel newer than the one that runs.
    pub(super) fn restart(&self, context: &Context<'_>) -> Made {
        let text = |path: &str| fs::read_to_string(self.root.join(path)).ok();
        let running = text("proc/sys/kernel/osrelease").map(|release| release.trim().to_owned());
        let mut installed: Vec<String> = fs::read_dir(self.root.join("lib/modules"))
            .into_iter()
            .flatten()
            .flatten()
            .filter(|entry| entry.path().join("modules.dep").exists())
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect();
        installed.sort_by(|left, right| reading::by_version(left, right));
        let newest = installed.last().cloned();
        let marked = self.root.join("run/reboot-required").exists();
        let (state, finding) = match (&running, &newest) {
            _ if marked => {
                let packages = text("run/reboot-required.pkgs").unwrap_or_default();
                let mut names: Vec<&str> =
                    packages.lines().filter(|line| !line.is_empty()).collect();
                names.sort_unstable();
                names.dedup();
                let because = if names.is_empty() {
                    String::new()
                } else {
                    format!(
                        " ({})",
                        names.iter().take(5).copied().collect::<Vec<_>>().join(", ")
                    )
                };
                (
                    State::Warning,
                    Some(format!(
                        "Installed updates need a restart of the host{because}."
                    )),
                )
            }
            (Some(running), Some(newest)) if reading::by_version(newest, running).is_gt() => (
                State::Warning,
                Some(format!(
                    "Kernel {newest} is installed and {running} runs: a restart of the host is due."
                )),
            ),
            (Some(_), _) => (State::Ok, None),
            (None, _) => (
                State::Unknown,
                Some("The running kernel's release could not be read.".to_owned()),
            ),
        };
        Ok(self
            .observation(context, "restart", "Restart of the host", state, "/run/reboot-required, /lib/modules")?
            .with_scope("The distribution's own marker where it writes one, and the installed kernels against the running one.")
            .with_fields(vec![
                Field::text("Running kernel", running),
                Field::text("Newest installed kernel", newest),
            ])
            .with_findings(finding.into_iter().collect())
            .with_max_age(180))
    }
}
