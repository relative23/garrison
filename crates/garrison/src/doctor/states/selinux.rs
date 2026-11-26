//! The states of SELinux's check (`doctor/host.rs`): whether nginx may
//! reach the web service.

use crate::doctor::host::Unread;
use crate::state::State;

pub(in crate::doctor) fn everywhere() -> State {
    let text = "SELinux lets nginx connect to every port (httpd_can_network_connect)";
    State::new("doctor-selinux-everywhere", text)
}

pub(in crate::doctor) fn unloaded() -> State {
    let text = "SELinux is enforcing and the module garrison is not loaded, so nginx cannot reach \
     Garrison";
    State::new("doctor-selinux-unloaded", text)
        .with_fix("Run the installer again; it loads the module.")
}

pub(in crate::doctor) fn unloaded_permissive() -> State {
    let text = "SELinux is permissive and the module garrison is not loaded";
    State::new("doctor-selinux-unloaded-permissive", text).with_fix("Run the installer again.")
}

pub(in crate::doctor) fn port_reached(port: u16) -> State {
    let text = format!(
        "the SELinux module garrison is loaded and lets nginx reach the web service on port \
         {port}"
    );
    State::new("doctor-selinux-port-reached", text)
}

/// The module SELinux has loaded lets nginx reach `labelled`, not `port`.
fn elsewhere(labelled: u16, port: u16) -> String {
    format!("the SELinux module garrison lets nginx reach port {labelled}, not {port} (web.port)")
}

/// What mends a module for another port, where the installer's file names
/// another port too.
const INSTALL: &str = "Run the installer again; it loads the module for web.port.";

/// What mends it where the installer's file names `web.port`, as after a
/// load that failed, which the installer does not repeat.
fn load(module: &str) -> String {
    format!("Load the module the installer wrote for web.port: semodule -i {module}")
}

pub(in crate::doctor) fn other_port(labelled: u16, port: u16) -> State {
    let what = elsewhere(labelled, port);
    let text = format!("{what}, so nginx answers 502");
    State::new("doctor-selinux-other-port", text).with_fix(INSTALL)
}

pub(in crate::doctor) fn other_port_permissive(labelled: u16, port: u16) -> State {
    let what = elsewhere(labelled, port);
    let text = format!("{what}; SELinux is permissive and only logs the denial");
    State::new("doctor-selinux-other-port-permissive", text).with_fix(INSTALL)
}

pub(in crate::doctor) fn load_failed(labelled: u16, port: u16, module: &str) -> State {
    let what = elsewhere(labelled, port);
    let text = format!("{what}, so nginx answers 502");
    State::new("doctor-selinux-load-failed", text).with_fix(load(module))
}

pub(in crate::doctor) fn load_failed_permissive(labelled: u16, port: u16, module: &str) -> State {
    let what = elsewhere(labelled, port);
    let text = format!("{what}; SELinux is permissive and only logs the denial");
    State::new("doctor-selinux-load-failed-permissive", text).with_fix(load(module))
}

pub(in crate::doctor) fn port_unknown(why: &Unread) -> State {
    let why = match why {
        Unread::Unnamed(error) => format!("no folder name could be drawn ({error})"),
        Unread::Folder(folder, error) => format!("{}: {error}", folder.display()),
        Unread::Unextracted(said) => {
            format!("`semodule -c -E garrison` extracted no module ({said})")
        }
        Unread::Unrun(error) => format!("`semodule` did not run ({error})"),
        Unread::NoPort => "the loaded module names no port".to_owned(),
    };
    let text = format!("which port the SELinux module garrison lets nginx reach: {why}");
    State::new("doctor-selinux-port-unknown", text)
}

#[cfg(test)]
pub(super) fn rows() -> Vec<State> {
    let ready = Unread::Unextracted("libsemanage.semanage_direct_get_module_info: error".into());
    vec![
        everywhere(),
        unloaded(),
        unloaded_permissive(),
        port_reached(8091),
        other_port(8091, 9443),
        other_port_permissive(8091, 9443),
        load_failed(8091, 9443, "/opt/garrison/selinux/garrison.cil"),
        load_failed_permissive(8091, 9443, "/opt/garrison/selinux/garrison.cil"),
        port_unknown(&ready),
    ]
}
