//! `garrison notify-test`: a test message on every configured channel.

use garrison_core::config::Config;

use crate::{complain, credentials, loaded, say};

/// One message on every configured channel, so that an operator sees them
/// work before a check depends on them.
pub(crate) fn run(config: &Config) -> u8 {
    use garrison_collector::notify::{Channels, Secrets, test};
    // Root reads what the collector's unit would not hand to the collector.
    let unloaded: Vec<loaded::Unloaded> = loaded::unloaded(config)
        .into_iter()
        .filter(|secret| secret.setting.starts_with("notifications."))
        .collect();
    if !unloaded.is_empty() {
        for secret in &unloaded {
            complain(&format!("Not tested: {}", secret.line()));
        }
        return 2;
    }
    let credentials = credentials(config);
    let secrets = Secrets::read(&credentials, &config.notifications);
    let channels = Channels::of(config, secrets).located(&credentials);
    if channels.is_empty() {
        complain(
            "No channel is configured: set ntfy_url, webhook_url or the mail settings under \
             [notifications] in garrison.toml.",
        );
        return 2;
    }
    let mut failed = false;
    for (channel, outcome) in test(&channels, garrison_core::time::now()) {
        match outcome {
            Ok(()) => say(&format!("{channel}: the test message is out.")),
            Err(error) => {
                failed = true;
                complain(&format!(
                    "{channel}: the test message did not go out: {error}. Check its address and \
                     its secret in /etc/garrison/credentials."
                ));
            }
        }
    }
    u8::from(failed)
}
