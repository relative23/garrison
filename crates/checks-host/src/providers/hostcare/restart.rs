//! Host care's restart check: whether installed updates need a restart of
//! the host.

use std::{fs, io};

use garrison_core::observations::{Field, State};

use super::{HostCare, Made, reading};
use crate::context::Context;

impl HostCare {
    /// The kernels installed in `<root>/lib/modules`, by their release, the
    /// newest last: a folder with its `modules.dep`, which a removed kernel
    /// does not leave behind. None where the folder is missing, as in a
    /// container, which runs the host's kernel; an error where it cannot be
    /// read, as where a sandbox hides it (`ProtectKernelModules=true`).
    fn kernels(&self) -> io::Result<Vec<String>> {
        let folder = self.root.join("lib/modules");
        let entries = match fs::read_dir(&folder) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            entries => entries?,
        };
        let mut installed = Vec::new();
        for entry in entries {
            let entry = entry?;
            if entry.path().join("modules.dep").try_exists()? {
                installed.extend(entry.file_name().into_string().ok());
            }
        }
        installed.sort_by(|left, right| reading::by_version(left, right));
        Ok(installed)
    }

    /// The distribution's own marker, or a kernel newer than the one that
    /// runs, of its flavor: another flavor beside it, such as a debug kernel,
    /// is no update of it.
    pub(super) fn restart(&self, context: &Context<'_>) -> Made {
        let text = |path: &str| fs::read_to_string(self.root.join(path)).ok();
        let running = text("proc/sys/kernel/osrelease").map(|release| release.trim().to_owned());
        let kernels = self.kernels();
        let flavor = running.as_deref().map(reading::flavor);
        let newest = kernels.as_ref().ok().and_then(|kernels| {
            kernels
                .iter()
                .rev()
                .find(|kernel| flavor.is_none_or(|flavor| reading::flavor(kernel) == flavor))
                .cloned()
        });
        let marked = self.root.join("run/reboot-required").exists();
        let (state, finding) = match (&running, &newest) {
            _ if marked => {
                let packages = text("run/reboot-required.pkgs").unwrap_or_default();
                let mut names: Vec<&str> =
                    packages.lines().filter(|line| !line.is_empty()).collect();
                names.sort_unstable();
                names.dedup();
                // Five are named; the finding says how many more there are.
                let shown = names.iter().take(5).copied().collect::<Vec<_>>().join(", ");
                let because = match names.len() {
                    0 => String::new(),
                    1..=5 => format!(" ({shown})"),
                    count => format!(" ({shown} and {} more)", count - 5),
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
            // Without the kernels, no update of one shows: that is no order.
            (Some(_), _) if kernels.is_err() => (
                State::Unknown,
                kernels.err().map(|error| {
                    format!(
                        "The installed kernels in {} could not be read: {error}.",
                        self.root.join("lib/modules").display()
                    )
                }),
            ),
            (Some(_), _) => (State::Ok, None),
            (None, _) => (
                State::Unknown,
                Some("The running kernel's release could not be read.".to_owned()),
            ),
        };
        Ok(self
            .observation(context, "restart", "Restart of the host", state, "/run/reboot-required, /lib/modules")?
            .with_scope("The distribution's own marker where it writes one, and the installed kernels of the running one's flavor against it.")
            .with_fields(vec![
                Field::text("Running kernel", running),
                Field::text("Newest installed kernel", newest),
            ])
            .with_findings(finding.into_iter().collect())
            .with_max_age(180))
    }
}
