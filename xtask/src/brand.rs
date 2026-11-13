//! The Garrison logo files: `cargo xtask brand`.
//!
//! Writes docs/brand/ (SVG and PNG) and frontend/public/favicon.svg from the
//! mark below. Needs Inkscape (turns the wordmark into outlines, so the files
//! need no installed font), rsvg-convert and the Noto Sans font. Run it only
//! when the logo changes; the generated files are committed and never edited
//! by hand.

use std::fs;
use std::path::Path;
use std::process::Command;

/// The fortress G on a 32-unit grid. Every edge sits on an even unit, so the
/// mark stays sharp at 16 and 32 pixels. Keep in sync with
/// frontend/src/components/Brand.tsx.
const MARK: &str = "M6 4h4v4h4V4h4v4h4V4h4v8H10v12h12v-4h-6v-4h10v12H6z";
const FONT: &str = r#"font-family="Noto Sans""#;
const FAVICON: &str = "frontend/public/favicon.svg";

/// Colours of the wordmark: (tone, ink, secondary text, its opacity).
const TONES: [(&str, &str, &str, &str); 3] = [
    ("dark", "#FAFAFA", "#A1A1AA", "1"),
    ("light", "#09090B", "#71717A", "1"),
    ("current", "currentColor", "currentColor", "0.6"),
];

fn svg(width: u32, height: u32, body: &str) -> String {
    format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">{body}</svg>
"#
    )
}

/// The scale as the committed files write it: a whole number keeps its `.0`.
fn scale(size: f64) -> String {
    let scale = size / 32.0;
    if scale.fract() == 0.0 {
        format!("{scale:.1}")
    } else {
        format!("{scale}")
    }
}

fn mark(fill: &str, x: f64, y: f64, size: f64) -> String {
    format!(
        r#"<path transform="translate({x} {y}) scale({})" fill="{fill}" d="{MARK}"/>"#,
        scale(size)
    )
}

struct Tone {
    ink: &'static str,
    sub: &'static str,
    opacity: &'static str,
}

fn text(
    x: u32,
    y: u32,
    size: u32,
    weight: u32,
    fill: &str,
    opacity: &str,
    content: &str,
) -> String {
    format!(
        r#"<text x="{x}" y="{y}" {FONT} font-size="{size}" font-weight="{weight}" fill="{fill}" fill-opacity="{opacity}">{content}</text>"#
    )
}

/// The name beside the mark, on one line; with `byline`, the byline below it.
/// The logo carries only Garrison's own name: Stalwart's is named in text,
/// where it says what Garrison works with, never in the logo.
fn header(tone: &Tone, byline: bool) -> String {
    let mut body = mark(tone.ink, 0.0, 0.0, 56.0);
    if byline {
        body += &text(62, 28, 30, 700, tone.ink, "1", "Garrison");
        body += &text(63, 49, 17, 400, tone.sub, tone.opacity, "by relative23");
    } else {
        body += &text(62, 39, 30, 700, tone.ink, "1", "Garrison");
    }
    svg(420, 56, &body)
}

fn large(tone: &Tone) -> String {
    let mut body = mark(tone.ink, 0.0, -1.6, 141.0);
    body += &text(138, 74, 62, 700, tone.ink, "1", "Garrison");
    body += &text(141, 112, 26, 400, tone.sub, tone.opacity, "by relative23");
    svg(640, 132, &body)
}

fn app_icon(background: &str, foreground: &str, border: Option<&str>) -> String {
    let edge = border.map_or(String::new(), |border| {
        format!(r#" stroke="{border}" stroke-width="8""#)
    });
    let body = format!(
        r#"<rect x="4" y="4" width="504" height="504" rx="112" fill="{background}"{edge}/>"#
    );
    svg(512, 512, &(body + &mark(foreground, 96.0, 96.0, 320.0)))
}

/// Dark mark on light browser chrome, light mark on dark chrome.
fn favicon() -> String {
    let style =
        "<style>path{fill:#09090B}@media (prefers-color-scheme:dark){path{fill:#FAFAFA}}</style>";
    svg(32, 32, &format!(r#"{style}<path d="{MARK}"/>"#))
}

/// Raster fallback: carries its own background, so it shows on any tab colour.
fn tile() -> String {
    let background = r##"<rect width="32" height="32" rx="7" fill="#09090B"/>"##;
    svg(
        32,
        32,
        &(background.to_owned() + &mark("#FAFAFA", 0.0, 0.0, 32.0)),
    )
}

fn run(program: &str, arguments: &[&str]) -> Result<(), String> {
    let output = Command::new(program)
        .args(arguments)
        .output()
        .map_err(|error| format!("{program}: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{program} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn outline(path: &Path, current: bool) -> Result<(), String> {
    let file = path.display().to_string();
    run(
        "inkscape",
        &[
            &file,
            "--export-text-to-path",
            "--export-plain-svg",
            "--export-area-drawing",
            "--export-overwrite",
        ],
    )?;
    if current {
        // Inkscape drops currentColor on outlined text; let it inherit from the root.
        let text = fs::read_to_string(path).map_err(|error| format!("{file}: {error}"))?;
        let text = text.replacen("<svg", r#"<svg fill="currentColor""#, 1);
        fs::write(path, text).map_err(|error| format!("{file}: {error}"))?;
    }
    Ok(())
}

fn png(source: &Path, target: &Path, size: u32) -> Result<(), String> {
    let size = size.to_string();
    let (source, target) = (source.display().to_string(), target.display().to_string());
    run(
        "rsvg-convert",
        &["-w", &size, "-h", &size, &source, "-o", &target],
    )
}

pub(crate) fn brand(root: &Path) -> Result<(), String> {
    let brand = root.join("docs/brand");
    fs::create_dir_all(brand.join("png")).map_err(|error| error.to_string())?;
    let mut files = vec![
        (
            "garrison-mark.svg".to_owned(),
            svg(32, 32, &mark("currentColor", 0.0, 0.0, 32.0)),
        ),
        (
            "garrison-mark-on-dark.svg".into(),
            svg(32, 32, &mark("#FAFAFA", 0.0, 0.0, 32.0)),
        ),
        (
            "garrison-mark-on-light.svg".into(),
            svg(32, 32, &mark("#09090B", 0.0, 0.0, 32.0)),
        ),
        ("favicon.svg".into(), favicon()),
        ("favicon-tile.svg".into(), tile()),
        ("app-icon.svg".into(), app_icon("#09090B", "#FAFAFA", None)),
        (
            "app-icon-light.svg".into(),
            app_icon("#FFFFFF", "#09090B", Some("#E4E4E7")),
        ),
    ];
    for (name, ink, sub, opacity) in TONES {
        let tone = Tone { ink, sub, opacity };
        files.push((format!("garrison-logo-{name}.svg"), header(&tone, false)));
        files.push((
            format!("garrison-logo-byline-{name}.svg"),
            header(&tone, true),
        ));
        files.push((format!("garrison-logo-large-{name}.svg"), large(&tone)));
    }
    for (name, content) in &files {
        let target = brand.join(name);
        fs::write(&target, content).map_err(|error| format!("{name}: {error}"))?;
        if name.starts_with("garrison-logo-") {
            outline(&target, name.ends_with("-current.svg"))?;
        }
    }
    fs::write(root.join(FAVICON), favicon()).map_err(|error| format!("{FAVICON}: {error}"))?;
    let (icon, small) = (brand.join("app-icon.svg"), brand.join("favicon-tile.svg"));
    for (source, name, size) in [
        (&icon, "app-icon-512.png", 512),
        (&icon, "app-icon-192.png", 192),
        (&icon, "apple-touch-icon-180.png", 180),
        (&small, "favicon-32.png", 32),
        (&small, "favicon-16.png", 16),
    ] {
        png(source, &brand.join("png").join(name), size)?;
    }
    println!("Wrote {} SVG and 5 PNG files to docs/brand", files.len());
    Ok(())
}
