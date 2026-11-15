//! `garrison nginx`: the server block for Garrison's own host name, written
//! for the nginx installed here, the lines that belong in Stalwart's server
//! blocks and, as optional ones, the forwarding of the client's address to
//! Stalwart. It prints and changes nothing: the nginx configuration stays
//! the operator's.
//!
//! `garrison nginx --snippet` prints the include that block names, for the
//! configured web port; the installer writes it to [`SNIPPET`].

use std::io::Write;
use std::process::Command;

use garrison_core::config::Config;

use crate::say;

const NGINX: &str = "/usr/sbin/nginx";
/// From nginx 1.25.1 on, `http2 on;` replaces `listen ... http2`; older
/// releases (Debian 12, Ubuntu 24.04, the RHEL 9 family) refuse it.
const HTTP2_DIRECTIVE: (u32, u32, u32) = (1, 25, 1);
/// Where the installer writes the include of Garrison's server block.
pub(crate) const SNIPPET: &str = "/etc/nginx/snippets/garrison.conf";
/// The include as the release ships it, for the default web port.
const SHIPPED: &str = include_str!("../../../deploy/nginx/garrison.conf");
/// The port the shipped include names, `web.port`'s default.
const SHIPPED_PORT: u16 = 8091;
/// The line of it that names the web service's port.
const UPSTREAM: (&str, &str) = ("proxy_pass http://127.0.0.1:", ";");
/// The optional forwarding of the client's address to Stalwart, as
/// installation.md shows it ("Client addresses for Stalwart's limits"): the
/// map in nginx's `http` block and the header in each location that
/// proxies to Stalwart. Stalwart refuses (400) a header that names a
/// loopback address, so the map names no client on this host.
const FORWARDED_MAP: &str = r#"map $remote_addr $stalwart_forwarded_for {
    ~^(127\.|::1$|::ffff:127\.)  "";
    default                     $proxy_add_x_forwarded_for;
}"#;
const FORWARDED_HEADER: &str = "proxy_set_header X-Forwarded-For $stalwart_forwarded_for;";

/// `text` as comment lines, each indented under the comment before it.
fn commented(text: &str) -> String {
    text.lines().fold(String::new(), |mut lines, line| {
        lines.push_str("\n#     ");
        lines.push_str(line);
        lines
    })
}

/// The include for a web service on `port`: the shipped one with that port.
pub(crate) fn snippet(port: u16) -> String {
    let (before, after) = UPSTREAM;
    SHIPPED.replacen(
        &format!("{before}{SHIPPED_PORT}{after}"),
        &format!("{before}{port}{after}"),
        1,
    )
}

/// The port an include sends Garrison's requests to, where it names one.
pub(crate) fn port_of(include: &str) -> Option<u16> {
    let (before, after) = UPSTREAM;
    include.lines().find_map(|line| {
        line.trim()
            .strip_prefix(before)?
            .strip_suffix(after)?
            .parse()
            .ok()
    })
}

/// `nginx version: nginx/1.22.1` (nginx writes it to standard error).
fn version(text: &str) -> Option<(u32, u32, u32)> {
    let number = text.split("nginx/").nth(1)?.split_whitespace().next()?;
    let mut parts = number.split('.').map(str::parse::<u32>);
    match (parts.next(), parts.next(), parts.next()) {
        (Some(Ok(major)), Some(Ok(minor)), Some(Ok(patch))) => Some((major, minor, patch)),
        _ => None,
    }
}

#[cfg(test)]
pub(crate) fn version_of(text: &str) -> Option<(u32, u32, u32)> {
    version(text)
}

fn installed() -> Option<(u32, u32, u32)> {
    let output = Command::new(NGINX).arg("-v").output().ok()?;
    version(&String::from_utf8_lossy(&output.stderr))
}

/// The host of an origin or URL, without scheme, port or path.
fn host(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split('/').next().unwrap_or(rest);
    authority
        .rsplit_once(':')
        .map_or(authority, |(host, _)| host)
}

/// The block for `config`, for nginx `found` (unknown: the current syntax).
fn site(config: &Config, found: Option<(u32, u32, u32)>) -> String {
    let own = host(&config.deployment.public_origin);
    let old = found.is_some_and(|version| version < HTTP2_DIRECTIVE);
    let (listen, http2) = if old {
        (" http2", "")
    } else {
        ("", "\n    http2 on;")
    };
    let written_for = match found {
        Some((major, minor, patch)) => format!("nginx {major}.{minor}.{patch}"),
        None => "nginx 1.25.1 or newer (no nginx found here)".to_owned(),
    };
    let mut stalwart = vec![host(&config.deployment.issuer)];
    let admin = host(&config.deployment.admin_url);
    if !stalwart.contains(&admin) {
        stalwart.push(admin);
    }
    format!(
        "# Garrison's own server block, for {written_for}. Save it as
# /etc/nginx/conf.d/garrison.conf, get a certificate for {own} (certbot or your
# usual way; adjust the two paths if they differ), then:
#     nginx -t && systemctl reload nginx

server {{
    listen 80;
    listen [::]:80;
    server_name {own};
    access_log off;
    # With certbot --webroot, serve its challenge here before the redirect:
    # location /.well-known/acme-challenge/ {{ root /var/lib/letsencrypt; }}
    location / {{ return 301 https://$host$request_uri; }}
}}

server {{
    listen 443 ssl{listen};
    listen [::]:443 ssl{listen};{http2}
    server_name {own};
    ssl_certificate     /etc/letsencrypt/live/{own}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{own}/privkey.pem;
    # Searches and the sign-in's answer travel in the address of a request:
    # none of them is written to a log.
    access_log off;
    include /etc/nginx/snippets/garrison.conf;
}}

# In each server block that proxies to Stalwart ({hosts}), at the
# server level, so that Stalwart's metrics exporter stays private:
#     include /etc/nginx/snippets/garrison-stalwart-server*.conf;
# Optional, inside the location that serves the Stalwart WebUI, for its
# \"Switch to Garrison WebUI\" row:
#     include /etc/nginx/snippets/garrison-stalwart-switch*.conf;
# Optional, so that Stalwart counts and blocks each client under its own
# address (the installation guide's \"Client addresses for Stalwart's limits\"
# has every step): in nginx's http block, for example as
# /etc/nginx/conf.d/stalwart-forwarded-for.conf:{map}
# and in every location that proxies to Stalwart:{header}
# then set Stalwart's \"Client IP source\" to \"X-Forwarded-For header\", and
# let nothing but nginx and Garrison reach Stalwart's HTTP listeners.
",
        hosts = stalwart.join(", "),
        map = commented(FORWARDED_MAP),
        header = commented(FORWARDED_HEADER),
    )
}

pub(crate) fn run(config: &Config, include: bool) -> u8 {
    if include {
        let _ = std::io::stdout()
            .lock()
            .write_all(snippet(config.web.port).as_bytes());
    } else {
        say(site(config, installed()).trim_end());
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deploy/config/garrison.example.toml"
        ))
        .unwrap();
        garrison_core::config::from_text(&text).unwrap()
    }

    #[test]
    fn the_version_comes_from_nginx_minus_v() {
        assert_eq!(version("nginx version: nginx/1.22.1\n"), Some((1, 22, 1)));
        assert_eq!(
            version("nginx version: nginx/1.30.6 (Ubuntu)"),
            Some((1, 30, 6))
        );
        assert_eq!(version("something else"), None);
    }

    #[test]
    fn http2_is_written_the_way_the_installed_nginx_reads_it() {
        let current = site(&config(), Some((1, 26, 3)));
        assert!(current.contains("    listen 443 ssl;\n    listen [::]:443 ssl;\n    http2 on;"));
        assert!(current.contains("server_name garrison.example.org;"));
        let older = site(&config(), Some((1, 22, 1)));
        assert!(older.contains(
            "    listen 443 ssl http2;\n    listen [::]:443 ssl http2;\n    server_name"
        ));
        assert!(!older.contains("http2 on"));
        assert!(site(&config(), None).contains("http2 on;"));
    }

    #[test]
    fn nothing_of_garrisons_requests_goes_into_an_access_log() {
        // Searches travel in query strings, and so does the sign-in's
        // callback: with the log most distributions switch on for all of
        // nginx, addresses and codes would lie in a file that no retention
        // and no privacy filter of Garrison's reaches.
        let text = site(&config(), Some((1, 26, 3)));
        let blocks: Vec<&str> = text.split("\nserver {").skip(1).collect();
        assert_eq!(blocks.len(), 2);
        for block in blocks {
            assert!(block.contains("\n    access_log off;\n"), "{block}");
        }
        // The snippet every installation includes says so for itself, in
        // case the server block around it is the operator's own.
        let location = SHIPPED.split("location / {").nth(1).unwrap();
        assert!(location.contains("\n    access_log off;\n"), "{location}");
    }

    #[test]
    fn the_include_sends_requests_to_the_configured_web_port() {
        // The shipped file is the include for the default port, byte for byte.
        assert_eq!(snippet(config().web.port), SHIPPED);
        assert_eq!(SHIPPED.matches("127.0.0.1:8091").count(), 1);
        let moved = snippet(9443);
        assert!(
            moved.contains("\n    proxy_pass http://127.0.0.1:9443;\n"),
            "{moved}"
        );
        // Nothing but the port differs.
        assert_eq!(moved.replace("9443", "8091"), SHIPPED);
        assert_eq!(port_of(&moved), Some(9443));
        assert_eq!(port_of(SHIPPED), Some(8091));
        assert_eq!(port_of("location / { return 404; }"), None);
    }

    /// The web service answers only under `public_origin`, port included, so
    /// the include passes the Host as the browser sent it: `$host` drops the
    /// port (measured on nginx 1.18 to 1.31, over HTTP/1.1 and HTTP/2).
    #[test]
    fn the_include_passes_the_host_with_its_port() {
        let location = SHIPPED.split("location / {").nth(1).unwrap();
        let hosts: Vec<&str> = location
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("proxy_set_header Host "))
            .collect();
        assert_eq!(hosts, ["proxy_set_header Host $http_host;"]);
    }

    /// The `nginx` blocks of installation.md's section on Stalwart's client
    /// addresses, each without its comments and the list's indentation.
    fn documented_forwarding() -> Vec<String> {
        let guide = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/operator/installation.md"
        ))
        .unwrap();
        let section = guide
            .split("### Client addresses for Stalwart's limits\n")
            .nth(1)
            .unwrap();
        let section = section.split("\n## ").next().unwrap();
        section
            .split("```nginx\n")
            .skip(1)
            .map(|block| {
                let block = block.split("```").next().unwrap();
                let lines: Vec<&str> = block.lines().map(str::trim_end).collect();
                let indent = lines
                    .iter()
                    .filter(|line| !line.trim().is_empty())
                    .map(|line| line.len() - line.trim_start().len())
                    .min()
                    .unwrap();
                lines
                    .iter()
                    .filter(|line| !line.trim().is_empty() && !line.trim().starts_with('#'))
                    .map(|line| format!("#     {}", &line[indent..]))
                    .collect::<Vec<String>>()
                    .join("\n")
            })
            .collect()
    }

    /// An operator who forwards the client's address finds the same lines
    /// in what `garrison nginx` prints as in the installation guide, marked
    /// as optional, with the section that has every step.
    #[test]
    fn the_optional_forwarding_is_the_one_the_guide_documents() {
        let documented = documented_forwarding();
        assert_eq!(documented.len(), 2, "{documented:?}");
        assert!(documented[0].starts_with("#     map $remote_addr "));
        assert_eq!(
            documented[1],
            "#     proxy_set_header X-Forwarded-For $stalwart_forwarded_for;"
        );
        for found in [None, Some((1, 22, 1)), Some((1, 26, 3))] {
            let text = site(&config(), found);
            let at: Vec<usize> = documented
                .iter()
                .map(|block| text.find(&format!("\n{block}\n")).unwrap_or(usize::MAX))
                .collect();
            assert!(at[0] < at[1] && at[1] < usize::MAX, "{at:?}\n{text}");
            let before = &text[..at[0]];
            let lead = before[before.rfind("\n# Optional").unwrap_or(0)..].replace("\n# ", " ");
            assert!(
                lead.contains("\"Client addresses for Stalwart's limits\"")
                    && !lead.contains("\nserver"),
                "{lead}"
            );
        }
    }

    #[test]
    fn stalwart_hosts_are_named_once() {
        let text = site(&config(), None);
        assert!(text.contains("proxies to Stalwart (mail.example.org), at the"));
        assert_eq!(
            host("https://mail.example.org:8443/admin/"),
            "mail.example.org"
        );
    }
}
