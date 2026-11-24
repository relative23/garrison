//! `garrison notify-test`: a test message on every configured channel.

use garrison_core::config::Config;

use crate::states::commands as states;
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
            complain(&states::notify_unloaded(&secret.line()).to_string());
        }
        return 2;
    }
    // Without root no secret reads, and every channel would look broken.
    if !rustix::process::geteuid().is_root() {
        complain(&states::notify_not_root().to_string());
        return 2;
    }
    let credentials = credentials(config);
    let secrets = Secrets::read(&credentials, &config.notifications);
    let channels = Channels::of(config, secrets).located(&credentials);
    if channels.is_empty() {
        complain(&states::no_channel().to_string());
        return 2;
    }
    let mut failed = false;
    for (channel, outcome) in test(&channels, garrison_core::time::now()) {
        match outcome {
            Ok(()) => say(&states::notify_sent(channel).to_string()),
            Err(error) => {
                failed = true;
                complain(&states::notify_failed(channel, error).to_string());
            }
        }
    }
    u8::from(failed)
}
