//! Stalwart's metrics exporter as `garrison doctor` reads it from outside
//! (doctor/public.rs, `metrics`): a scrape without its credential is
//! refused with 401, and one with it is answered with Prometheus text,
//! samples and no markup, which tells it from a web page.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

use super::{Setup, forget, lab, text};

#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn the_exporter_answers_as_doctor_reads_it() {
    let (_guard, lab) = lab();
    let setup = Setup::new(&lab, "http://127.0.0.1:9/webhook");
    let credentials = setup.directory.join("credentials");
    forget(&lab, &credentials);
    let ran = setup.run(&[]);
    assert_eq!(ran.status.code(), Some(0), "{}", text(&ran));
    let url = format!("{}/metrics/prometheus", lab.url);
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();
    let anonymous = agent.get(&url).call().unwrap();
    assert_eq!(anonymous.status(), 401, "{url} without the credential");
    let file = std::fs::read(credentials.join("metrics-credential")).unwrap();
    let credential: Value = serde_json::from_slice(&file).unwrap();
    let user = format!(
        "{}:{}",
        credential["username"].as_str().unwrap(),
        credential["secret"].as_str().unwrap()
    );
    let mut scraped = agent
        .get(&url)
        .header("Authorization", &format!("Basic {}", STANDARD.encode(user)))
        .call()
        .unwrap();
    assert_eq!(scraped.status(), 200, "{url} with the credential");
    let body = scraped.body_mut().read_to_string().unwrap();
    forget(&lab, &credentials);
    assert!(!body.contains('<'), "{body}");
    let sample = body.lines().any(|line| {
        !line.starts_with('#')
            && line
                .split_whitespace()
                .last()
                .is_some_and(|value| value.parse::<f64>().is_ok())
    });
    assert!(sample, "no sample in the exporter's text:\n{body}");
}
