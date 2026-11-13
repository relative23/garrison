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

/// relative23's logo, the tile and the word, as relative23 draws it for dark
/// and light backgrounds (outlines, no font). It is relative23's mark and not
/// covered by Garrison's licence; the byline shows it after "by".
const RELATIVE23_ON_DARK: &str = include_str!("../assets/relative23-on-dark.svg");
const RELATIVE23_ON_LIGHT: &str = include_str!("../assets/relative23-on-light.svg");
/// The logo's view box: `0 -85 661.2 170`.
const RELATIVE23_TOP: f64 = -85.0;
const RELATIVE23_HEIGHT: f64 = 170.0;
/// The advance of "by " in Noto Sans, in em: where the logo starts.
const BY: f64 = 1.365;

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
    name: &'static str,
    ink: &'static str,
    sub: &'static str,
    opacity: &'static str,
}

/// What lies between an SVG file's root tags.
fn inner(svg: &str) -> &str {
    let start = svg.find('>').map_or(0, |at| at + 1);
    let end = svg.rfind("</svg>").unwrap_or(svg.len());
    &svg[start..end]
}

/// `svg` without its `fill="…"` attributes, so that it takes its parent's fill.
fn without_fills(svg: &str) -> String {
    let mut rest = svg;
    let mut kept = String::with_capacity(svg.len());
    while let Some(at) = rest.find(r#" fill=""#) {
        kept.push_str(&rest[..at]);
        let value = &rest[at + r#" fill=""#.len()..];
        rest = value.find('"').map_or("", |end| &value[end + 1..]);
    }
    kept + rest
}

/// relative23's logo in the colour of the text around it: the tile's letters
/// and bar are cut out of the tile, as relative23's black logo shows them on
/// white, and the word takes the colour too.
fn relative23_in_text_colour() -> String {
    let logo = RELATIVE23_ON_LIGHT;
    let letters: Vec<&str> = logo
        .split(r##"<path fill="#fafaf8" d=""##)
        .skip(1)
        .filter_map(|rest| rest.split('"').next())
        .collect();
    // The tile's bar: 3 by 48 at (19, 4), turned 23 degrees about (20.5, 28).
    let (sin, cos) = 23f64.to_radians().sin_cos();
    let bar: Vec<String> = [(19.0, 4.0), (22.0, 4.0), (22.0, 52.0), (19.0, 52.0)]
        .into_iter()
        .map(|(x, y): (f64, f64)| {
            let (dx, dy) = (x - 20.5, y - 28.0);
            format!(
                "{:.3} {:.3}",
                20.5 + dx * cos - dy * sin,
                28.0 + dx * sin + dy * cos
            )
        })
        .collect();
    let tile = format!(
        r#"<g transform="translate(0 -73.10) scale(2.6107)"><path fill-rule="evenodd" d="M0 0H56V56H0Z {} M{}Z {}"/></g>"#,
        letters.first().copied().unwrap_or_default(),
        bar.join("L"),
        letters.get(1).copied().unwrap_or_default()
    );
    let end = logo.rfind("</svg>").unwrap_or(logo.len());
    let word = logo
        .find(r#"<g transform="translate(181.20 0)">"#)
        .map_or("", |at| &logo[at..end]);
    tile + &without_fills(word)
}

/// "by" and relative23's logo after it, for a byline of font size `size`
/// whose baseline is `y`: the logo 1.3 times the font size, so that its word
/// reads as large as "by", centred on the lowercase letters.
fn byline(tone: &Tone, x: u32, y: u32, size: u32) -> String {
    let (left, baseline, em) = (f64::from(x), f64::from(y), f64::from(size));
    let height = em * 1.3;
    let scale = height / RELATIVE23_HEIGHT;
    let logo_x = left + BY * em + em / 13.0;
    let logo_y = baseline - 0.62 * height - RELATIVE23_TOP * scale;
    let logo = match tone.name {
        "dark" => inner(RELATIVE23_ON_DARK).to_owned(),
        "light" => inner(RELATIVE23_ON_LIGHT).to_owned(),
        // The file's root takes the text colour (see `outline`).
        _ => format!(
            r#"<g fill-opacity="{}">{}</g>"#,
            tone.opacity,
            relative23_in_text_colour()
        ),
    };
    format!(
        r#"{}<g transform="translate({logo_x:.2} {logo_y:.2}) scale({scale:.5})">{logo}</g>"#,
        text(x, y, size, 400, tone.sub, tone.opacity, "by")
    )
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

/// The name beside the mark, on one line; with `with_byline`, the byline below
/// it: "by" and relative23's logo.
/// The logo carries only Garrison's own name: Stalwart's is named in text,
/// where it says what Garrison works with, never in the logo.
fn header(tone: &Tone, with_byline: bool) -> String {
    let mut body = mark(tone.ink, 0.0, 0.0, 56.0);
    if with_byline {
        body += &text(62, 28, 30, 700, tone.ink, "1", "Garrison");
        body += &byline(tone, 63, 49, 17);
    } else {
        body += &text(62, 39, 30, 700, tone.ink, "1", "Garrison");
    }
    svg(420, 56, &body)
}

fn large(tone: &Tone) -> String {
    let mut body = mark(tone.ink, 0.0, -1.6, 141.0);
    body += &text(138, 74, 62, 700, tone.ink, "1", "Garrison");
    body += &byline(tone, 141, 112, 26);
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
        let tone = Tone {
            name,
            ink,
            sub,
            opacity,
        };
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
