//! `garrison nginx`: the server block for Garrison's own host name, written
//! for the nginx installed here, and the lines that belong in Stalwart's
//! server blocks. It prints and changes nothing: the nginx configuration
//! stays the operator's.

use std::process::Command;

use garrison_core::config::Config;

use crate::say;

const NGINX: &str = "/usr/sbin/nginx";
/// From nginx 1.25.1 on, `http2 on;` replaces `listen ... http2`; older
/// releases (Debian 12, Ubuntu 24.04, the RHEL 9 family) refuse it.
const HTTP2_DIRECTIVE: (u32, u32, u32) = (1, 25, 1);

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
    include /etc/nginx/snippets/garrison.conf;
}}

# In each server block that proxies to Stalwart ({hosts}), at the
# server level, so that Stalwart's metrics exporter stays private:
#     include /etc/nginx/snippets/garrison-stalwart-server*.conf;
# Optional, inside the location that serves the Stalwart WebUI, for its
# \"Switch to Garrison WebUI\" row:
#     include /etc/nginx/snippets/garrison-stalwart-switch*.conf;
",
        hosts = stalwart.join(", ")
    )
}

pub(crate) fn run(config: &Config) -> u8 {
    say(site(config, installed()).trim_end());
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
    fn stalwart_hosts_are_named_once() {
        let text = site(&config(), None);
        assert!(text.contains("proxies to Stalwart (mail.example.org), at the"));
        assert_eq!(
            host("https://mail.example.org:8443/admin/"),
            "mail.example.org"
        );
    }
}
