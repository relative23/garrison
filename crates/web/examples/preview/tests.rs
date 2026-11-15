use std::time::Duration;

/// Stopped by its process ID, as a script stops it, the preview ends as it
/// does on Ctrl+C: `main` returns, and its temporary state goes with it.
#[test]
fn sigterm_ends_the_preview_as_ctrl_c_does() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let ended = super::ended().unwrap();
        let sent = std::process::Command::new("kill")
            .args(["-TERM", &std::process::id().to_string()])
            .status()
            .unwrap();
        assert!(sent.success());
        tokio::time::timeout(Duration::from_secs(10), ended)
            .await
            .expect("SIGTERM ends the preview");
    });
}
