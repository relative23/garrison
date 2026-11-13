//! A disposable Stalwart instance for the contract tests.
//!
//! ```sh
//! eval "$(cargo xtask lab start)"   # prints the GARRISON_LAB_* variables
//! cargo xtask lab stop
//! ```
//!
//! The images are pinned to the releases Garrison supports. The container
//! has a 2 GiB memory limit, publishes its HTTP listener only on 127.0.0.1 and
//! is removed when stopped. State lives in a temporary directory that `stop`
//! deletes. `start` refuses while the container exists, so one run cannot
//! remove a lab that another run still uses.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};

/// The supported Stalwart releases, newest first, each pinned by the digest
/// of its image. `start` takes the first unless it is given another. The
/// contract job in `.github/workflows/ci.yml` runs every one of them.
const IMAGES: [(&str, &str); 1] = [(
    "1.1.0",
    "stalwartlabs/stalwart:v1.1.0\
     @sha256:f772aa6ef8cd8018969fa491640f1436b0270eb14e2c219b5f37f1a77020837e",
)];
/// Stalwart's newest release, pinned by the digest of its image. Renovate
/// moves it to each new release and to a new image of the same release
/// (`customManagers` in renovate.json). The job contract-newest in
/// `.github/workflows/ci.yml` runs it while it is none of [`IMAGES`], so the
/// pull request shows whether Garrison still fits before the release becomes
/// a supported one (CONTRIBUTING.md, "Supporting a new Stalwart release").
const NEWEST: &str = "stalwartlabs/stalwart:v1.1.0@sha256:f772aa6ef8cd8018969fa491640f1436b0270eb14e2c219b5f37f1a77020837e";
const NAME: &str = "garrison-lab-stalwart";
const PORT: u16 = 18180;
const RECOVERY: &str = "contract-recovery:Contract-Recovery-2026";

fn state() -> PathBuf {
    std::env::temp_dir().join("garrison-lab")
}

fn bootstrap() -> Value {
    json!({
        "defaultHostname": "mail.example.test",
        "defaultDomain": "example.test",
        "requestTlsCertificate": false,
        "generateDkimKeys": false,
        "dataStore": {"@type": "RocksDb", "path": "/var/lib/stalwart/"},
        "blobStore": {"@type": "Default"},
        "searchStore": {"@type": "Default"},
        "inMemoryStore": {"@type": "Default"},
        "directory": {"@type": "Internal"},
        "dnsServer": {"@type": "Manual"},
        "tracer": {"@type": "Stdout", "enable": true, "level": "info", "ansi": false},
    })
}

fn docker(arguments: &[&str]) -> Result<String, String> {
    let output = Command::new("docker")
        .args(arguments)
        .output()
        .map_err(|error| format!("docker: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "docker {}: {}",
            arguments.first().unwrap_or(&""),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .proxy(None)
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .into()
}

/// Any HTTP answer means the listener is up.
fn wait_http(url: &str) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if agent().get(url).call().is_ok() {
            return Ok(());
        }
        sleep(Duration::from_secs(1));
    }
    Err(format!("Stalwart did not answer on {url}"))
}

/// The image of a supported release, of `newest` ([`NEWEST`]), or of the
/// newest supported one.
fn image(release: Option<&str>) -> Result<&'static str, String> {
    let Some(release) = release else {
        return Ok(IMAGES[0].1);
    };
    if release == "newest" {
        return Ok(NEWEST);
    }
    IMAGES
        .iter()
        .find(|(name, _)| *name == release)
        .map(|(_, image)| *image)
        .ok_or_else(|| {
            let known: Vec<&str> = IMAGES.iter().map(|(name, _)| *name).collect();
            format!(
                "no supported Stalwart release {release:?}; the lab has {}",
                known.join(", ")
            )
        })
}

fn run_container(image: &str, extra: &[&str]) -> Result<(), String> {
    let (etc, data) = (
        format!("{}:/etc/stalwart", state().join("etc").display()),
        format!("{}:/var/lib/stalwart", state().join("data").display()),
    );
    let port = format!("127.0.0.1:{PORT}:8080");
    let mut arguments = vec![
        "run",
        "-d",
        "--rm",
        "--name",
        NAME,
        "--memory=2g",
        "--memory-swap=2g",
        "-p",
        &port,
        "-v",
        &etc,
        "-v",
        &data,
    ];
    arguments.extend_from_slice(extra);
    arguments.push(image);
    docker(&arguments)?;
    wait_http(&format!("http://127.0.0.1:{PORT}/"))
}

fn jmap(credentials: &str, method: &str, arguments: &Value) -> Result<Value, String> {
    let body = json!({
        "using": ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"],
        "methodCalls": [[method, arguments, "0"]],
    });
    let mut answer = agent()
        .post(&format!("http://127.0.0.1:{PORT}/jmap/"))
        .header("Content-Type", "application/json")
        .header(
            "Authorization",
            &format!("Basic {}", STANDARD.encode(credentials)),
        )
        .send(body.to_string())
        .map_err(|error| format!("{method}: {error}"))?;
    let text = answer
        .body_mut()
        .read_to_string()
        .map_err(|error| format!("{method}: {error}"))?;
    let value: Value = serde_json::from_str(&text).map_err(|error| format!("{method}: {error}"))?;
    Ok(value["methodResponses"][0][1].clone())
}

fn start(release: Option<&str>) -> Result<(), String> {
    let image = image(release)?;
    if docker(&["container", "inspect", "--format", "{{.Id}}", NAME]).is_ok() {
        return Err(format!(
            "{NAME} already exists; if no other run uses it, `cargo xtask lab stop` removes it"
        ));
    }
    // Without a container, the state is left over from an aborted start.
    let _ = fs::remove_dir_all(state());
    for folder in ["etc", "data"] {
        let path = state().join(folder);
        fs::create_dir_all(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        // The container runs as its own UID.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o777))
            .map_err(|error| format!("{}: {error}", path.display()))?;
    }
    let recovery = format!("STALWART_RECOVERY_ADMIN={RECOVERY}");
    run_container(image, &["-e", &recovery])?;
    let result = jmap(
        RECOVERY,
        "x:Bootstrap/set",
        &json!({"update": {"singleton": bootstrap()}}),
    )?;
    let admin = &result["updated"]["singleton"];
    let (Some(username), Some(secret)) = (admin["username"].as_str(), admin["secret"].as_str())
    else {
        return Err(format!("unexpected bootstrap answer: {result}"));
    };
    docker(&["stop", NAME])?;
    sleep(Duration::from_secs(2));
    run_container(image, &[])?;
    let credentials = format!("{username}:{secret}");
    let file = state().join("admin");
    fs::write(&file, &credentials).map_err(|error| format!("{}: {error}", file.display()))?;
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("{}: {error}", file.display()))?;
    let networks = |field: &str| {
        docker(&[
            "inspect",
            "-f",
            &format!("{{{{range .NetworkSettings.Networks}}}}{{{{.{field}}}}}{{{{end}}}}"),
            NAME,
        ])
    };
    let (address, gateway) = (networks("IPAddress")?, networks("Gateway")?);
    println!("export GARRISON_LAB_URL=http://127.0.0.1:{PORT}");
    println!("export GARRISON_LAB_ADMIN='{credentials}'");
    println!("export GARRISON_LAB_SMTP={address}");
    println!("export GARRISON_LAB_CALLBACK_HOST={gateway}");
    println!("export GARRISON_LAB_CONTAINER={NAME}");
    Ok(())
}

fn stop() {
    let _ = docker(&["rm", "-f", NAME]);
    let _ = fs::remove_dir_all(state());
}

/// `stalwartlabs/stalwart:v1.2.3@sha256:…` is the release 1.2.3.
fn release_of(image: &str) -> Option<&str> {
    image
        .strip_prefix("stalwartlabs/stalwart:v")?
        .split_once('@')
        .map(|(release, _)| release)
}

/// The release of [`NEWEST`] while no supported release has its image.
fn unsupported_newest() -> Option<&'static str> {
    if IMAGES.iter().any(|(_, image)| *image == NEWEST) {
        return None;
    }
    release_of(NEWEST)
}

pub(crate) fn lab(command: Option<&str>, release: Option<&str>) -> Result<(), String> {
    match command {
        Some("start") => start(release),
        Some("stop") => {
            stop();
            Ok(())
        }
        // For the job contract-newest: nothing while the newest release is a
        // supported one, which the contract job runs already.
        Some("newest") => {
            if let Some(release) = unsupported_newest() {
                println!("{release}");
            }
            Ok(())
        }
        _ => Err("usage: cargo xtask lab start [RELEASE|newest]|stop|newest".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lab_starts_a_supported_release_only() {
        assert_eq!(image(None), Ok(IMAGES[0].1));
        for (release, pinned) in IMAGES {
            assert_eq!(image(Some(release)), Ok(pinned));
            let (name, digest) = pinned.split_once("@sha256:").unwrap();
            assert_eq!(name, format!("stalwartlabs/stalwart:v{release}"));
            assert!(digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
        }
        assert_eq!(
            image(Some("0.16.0")),
            Err("no supported Stalwart release \"0.16.0\"; the lab has 1.1.0".to_owned())
        );
    }

    #[test]
    fn the_newest_release_is_pinned_and_run_while_it_is_not_supported() {
        assert_eq!(image(Some("newest")), Ok(NEWEST));
        let (name, digest) = NEWEST.split_once("@sha256:").unwrap();
        assert_eq!(
            name,
            format!("stalwartlabs/stalwart:v{}", release_of(NEWEST).unwrap())
        );
        assert!(digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(
            release_of("stalwartlabs/stalwart:v1.2.3@sha256:00"),
            Some("1.2.3")
        );
        assert_eq!(release_of("other/image:v1.2.3@sha256:00"), None);
        // A supported release's image is the contract job's to run.
        let supported = IMAGES.iter().any(|(_, image)| *image == NEWEST);
        assert_eq!(unsupported_newest().is_none(), supported);
    }

    /// The README states what is supported and the contract job proves it,
    /// so both must name exactly the releases a lab can start.
    #[test]
    fn the_readme_and_the_contract_job_name_the_same_releases() {
        let mut releases: Vec<&str> = IMAGES.iter().map(|(name, _)| *name).collect();
        releases.sort_unstable();
        let workflow = include_str!("../../.github/workflows/ci.yml");
        let matrix = workflow
            .lines()
            .find_map(|line| line.trim().strip_prefix("stalwart: ["))
            .and_then(|rest| rest.strip_suffix(']'))
            .expect("the contract job's matrix");
        let mut tested: Vec<&str> = matrix
            .split(',')
            .map(|name| name.trim().trim_matches('"'))
            .collect();
        tested.sort_unstable();
        assert_eq!(tested, releases);
        let readme = include_str!("../../README.md");
        let supported = readme
            .lines()
            .skip_while(|line| !line.contains("Supported Stalwart releases:"))
            .take(2)
            .collect::<Vec<&str>>()
            .join(" ");
        let mut stated: Vec<&str> = supported.split("**").skip(1).step_by(2).collect();
        stated.sort_unstable();
        assert_eq!(stated, releases, "{supported}");
    }
}
