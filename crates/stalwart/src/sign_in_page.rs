//! What Garrison assumes about the page Stalwart shows for signing in.
//!
//! Garrison sends everybody to [`PATH`] under the issuer. The page is HTML
//! that loads scripts and style sheets of its own, named in `script` and
//! `link` tags, and is of use only if those reach Stalwart as well: a proxy
//! that passes the page but not its files leaves a page that shows and does
//! nothing. `garrison doctor` reads the page with these functions; the
//! contract test holds them against the page of every supported release.

use url::Url;

/// Where Stalwart serves the page, under the issuer.
pub const PATH: &str = "/login";

/// A file a page loads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Script,
    Style,
}

/// The value of the attribute `name` in the text of one tag.
fn attribute<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    // Lowered ASCII keeps every byte position, so positions found here hold in `tag`.
    let lower = tag.to_ascii_lowercase();
    let mut from = 0;
    while let Some(found) = lower[from..].find(name) {
        let start = from + found;
        let end = start + name.len();
        from = end;
        // A name of its own: after white space and before `=`.
        if !lower[..start]
            .chars()
            .next_back()
            .is_some_and(char::is_whitespace)
        {
            continue;
        }
        let Some(value) = tag[end..].trim_start().strip_prefix('=') else {
            continue;
        };
        let value = value.trim_start();
        return Some(match value.chars().next() {
            Some(quote @ ('"' | '\'')) => value[1..].split(quote).next().unwrap_or(""),
            _ => value
                .split(|character: char| character.is_whitespace() || character == '>')
                .next()
                .unwrap_or(""),
        });
    }
    None
}

/// The scripts and style sheets a page loads, as the page writes them: `src`
/// of its script tags and `href` of its style sheet links.
#[must_use]
pub fn files(html: &str) -> Vec<(Kind, String)> {
    let mut found = Vec::new();
    for piece in html.split('<').skip(1) {
        let tag = piece.split('>').next().unwrap_or("");
        let name = tag
            .split(|character: char| character.is_whitespace() || character == '/')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        let reference = match name.as_str() {
            "script" => attribute(tag, "src").map(|value| (Kind::Script, value)),
            "link" => attribute(tag, "rel")
                .filter(|rel| {
                    rel.split_whitespace()
                        .any(|word| word.eq_ignore_ascii_case("stylesheet"))
                })
                .and_then(|_| attribute(tag, "href"))
                .map(|value| (Kind::Style, value)),
            _ => None,
        };
        if let Some((kind, value)) = reference
            && !value.is_empty()
        {
            found.push((kind, value.to_owned()));
        }
    }
    found
}

/// Where a reference of the page at `page` leads, if that is on the page's
/// own host. Files on other hosts are not this installation's to answer for.
#[must_use]
pub fn address(page: &str, reference: &str) -> Option<String> {
    let page = Url::parse(page).ok()?;
    let file = page.join(reference).ok()?;
    (file.origin() == page.origin() && matches!(file.scheme(), "http" | "https"))
        .then(|| file.into())
}

/// Whether a content type is that of the file the page asked for. A proxy
/// that sends the request elsewhere answers with a page of its own.
#[must_use]
pub fn media_fits(kind: Kind, content_type: &str) -> bool {
    let media = content_type.to_ascii_lowercase();
    match kind {
        Kind::Script => media.contains("javascript") || media.contains("ecmascript"),
        Kind::Style => media.starts_with("text/css"),
    }
}

#[cfg(test)]
mod tests {
    use garrison_testing::noise::Noise;

    use super::*;

    /// The head of Stalwart 1.1.0's sign-in page, as it is served.
    const STALWART: &str = r#"<!DOCTYPE html> <html lang="en"> <head> <meta charset="UTF-8">
<title>Sign in</title> <link rel="stylesheet" href="/ui-c2d53b4371a7.css">
<script src="/ui-c2d53b4371a7.js"></script> <style>.app-header{display:flex}</style></head>"#;

    #[test]
    fn a_page_names_its_scripts_and_style_sheets() {
        assert_eq!(
            files(STALWART),
            [
                (Kind::Style, "/ui-c2d53b4371a7.css".to_owned()),
                (Kind::Script, "/ui-c2d53b4371a7.js".to_owned()),
            ]
        );
        // Other links, inline scripts, other quoting and attributes that only end alike.
        let page = "<LINK REL='icon' HREF='/favicon.ico'><link href=a.css rel=\"preload stylesheet\">\
                    <script>let src = '/no.js'</script><script data-src=\"/no.js\" type=module SRC = '/m.js' ></script>\
                    <a href=\"/login\">x</a><script src=\"\"></script><link rel=stylesheet>";
        assert_eq!(
            files(page),
            [
                (Kind::Style, "a.css".to_owned()),
                (Kind::Script, "/m.js".to_owned()),
            ]
        );
        assert_eq!(files("no tags at all"), []);
    }

    #[test]
    fn a_reference_leads_to_the_pages_own_host_or_nowhere() {
        let page = "https://mail.example.test/auth/login?client_id=x";
        let leads = |reference| address(page, reference);
        assert_eq!(
            leads("/ui-1.js").as_deref(),
            Some("https://mail.example.test/ui-1.js")
        );
        assert_eq!(
            leads("ui-1.js").as_deref(),
            Some("https://mail.example.test/auth/ui-1.js")
        );
        assert_eq!(
            leads("https://mail.example.test/a.css").as_deref(),
            Some("https://mail.example.test/a.css")
        );
        assert_eq!(
            address("http://127.0.0.1:8080/login", "/ui-1.js").as_deref(),
            Some("http://127.0.0.1:8080/ui-1.js")
        );
        // Another host, also one whose name only begins alike, another port,
        // another scheme.
        assert_eq!(leads("https://cdn.example.org/a.js"), None);
        assert_eq!(leads("https://mail.example.test.evil.example/a.js"), None);
        assert_eq!(leads("https://mail.example.test:8443/a.js"), None);
        assert_eq!(leads("//cdn.example.org/a.js"), None);
        assert_eq!(leads("http://mail.example.test/a.js"), None);
        assert_eq!(leads("data:text/css,a{}"), None);
        assert_eq!(address("not an address", "/a.js"), None);
    }

    #[test]
    fn a_file_is_known_by_its_content_type() {
        assert!(media_fits(Kind::Script, "text/javascript; charset=utf-8"));
        assert!(media_fits(Kind::Script, "Application/JavaScript"));
        assert!(media_fits(Kind::Style, "text/css; charset=utf-8"));
        // What a webmail or a proxy's error page answers instead.
        assert!(!media_fits(Kind::Script, "text/html; charset=utf-8"));
        assert!(!media_fits(Kind::Style, "text/html"));
        assert!(!media_fits(Kind::Style, "text/javascript"));
        assert!(!media_fits(Kind::Script, ""));
    }

    #[test]
    fn random_pages_never_panic() {
        let mut noise = Noise::new(0x51f1_5eed_0bad_cafe);
        let pieces = [
            "<",
            ">",
            "script",
            "link",
            " src",
            " href",
            " rel",
            "=",
            "\"",
            "'",
            "stylesheet",
            "/a.js",
            " ",
            "ä",
            "/",
        ];
        for _ in 0..20_000 {
            let mut page = String::new();
            for _ in 0..noise.below(24) {
                page.push_str(pieces[noise.below(pieces.len())]);
            }
            for (_, reference) in files(&page) {
                let _ = address("https://mail.example.test/login", &reference);
            }
            let _ = attribute(&page, "src");
        }
    }
}
